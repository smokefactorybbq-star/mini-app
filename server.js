const crypto = require("crypto");
const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || "").trim();

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set");
  process.exit(1);
}

if (!BOT_TOKEN) {
  console.error("ERROR: TELEGRAM_BOT_TOKEN is not set");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("railway.internal")
    ? false
    : { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

app.disable("x-powered-by");

app.use(express.json({ limit: "256kb" }));
app.use(
  express.urlencoded({
    extended: false,
    limit: "256kb"
  })
);

/*
 * Логи запросов.
 * После установки этого файла в Railway Logs будут видны:
 *
 * [HTTP] POST /api/bootstrap
 * [HTTP] PUT /api/profile
 * [HTTP] PUT /api/profile -> 200 (25 ms)
 */
app.use((req, res, next) => {
  const shouldLog =
    req.path === "/" ||
    req.path === "/health" ||
    req.path.startsWith("/api/");

  if (!shouldLog) {
    return next();
  }

  const startedAt = Date.now();

  console.log(`[HTTP] ${req.method} ${req.originalUrl}`);

  res.on("finish", () => {
    const duration = Date.now() - startedAt;

    console.log(
      `[HTTP] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration} ms)`
    );
  });

  next();
});

/*
 * Не кэшируем HTML и API.
 * Это важно для Telegram Mini App, чтобы не открывался старый index.html.
 */
app.use((req, res, next) => {
  if (
    req.path === "/" ||
    req.path.endsWith(".html") ||
    req.path.startsWith("/api/")
  ) {
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, proxy-revalidate"
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }

  next();
});

function discountBySpend(totalSpend) {
  const spend = Number(totalSpend || 0);

  if (spend >= 20000) return 20;
  if (spend >= 15000) return 15;
  if (spend >= 10000) return 10;
  if (spend >= 5000) return 5;

  return 0;
}

function validateTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    throw new Error("Telegram initData is missing");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash) {
    throw new Error("Telegram hash is missing");
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (
    !/^[a-f0-9]{64}$/i.test(receivedHash) ||
    !/^[a-f0-9]{64}$/i.test(calculatedHash)
  ) {
    throw new Error("Invalid Telegram signature");
  }

  const receivedHashBuffer = Buffer.from(receivedHash, "hex");
  const calculatedHashBuffer = Buffer.from(calculatedHash, "hex");

  if (
    receivedHashBuffer.length !== calculatedHashBuffer.length ||
    !crypto.timingSafeEqual(receivedHashBuffer, calculatedHashBuffer)
  ) {
    throw new Error("Invalid Telegram signature");
  }

  const authDate = Number(params.get("auth_date") || 0);
  const currentTime = Math.floor(Date.now() / 1000);

  /*
   * Telegram initData действует 24 часа.
   * Также запрещаем дату более чем на 5 минут из будущего.
   */
  if (
    !authDate ||
    currentTime - authDate > 24 * 60 * 60 ||
    authDate > currentTime + 5 * 60
  ) {
    throw new Error("Telegram authorization expired");
  }

  const rawUser = params.get("user");

  if (!rawUser) {
    throw new Error("Telegram user is missing");
  }

  let user;

  try {
    user = JSON.parse(rawUser);
  } catch {
    throw new Error("Invalid Telegram user data");
  }

  if (!user || !user.id) {
    throw new Error("Telegram user ID is missing");
  }

  return user;
}

function telegramAuth(req, res, next) {
  try {
    const initData =
      req.get("X-Telegram-Init-Data") ||
      req.body?.initData ||
      "";

    req.telegramUser = validateTelegramInitData(initData);

    return next();
  } catch (error) {
    console.error(
      `[AUTH] ${req.method} ${req.originalUrl}: ${error.message}`
    );

    return res.status(401).json({
      ok: false,
      error: error.message
    });
  }
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      telegram_id BIGINT PRIMARY KEY,
      username TEXT,
      telegram_first_name TEXT,
      telegram_last_name TEXT,
      profile_name TEXT,
      phone TEXT,
      address TEXT,
      photo_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_bot_activity_at TIMESTAMPTZ,
      last_site_visit_at TIMESTAMPTZ
    );

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS username TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS telegram_first_name TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS telegram_last_name TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS profile_name TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS phone TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS address TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS photo_url TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS created_at
      TIMESTAMPTZ NOT NULL DEFAULT NOW();

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS updated_at
      TIMESTAMPTZ NOT NULL DEFAULT NOW();

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS last_bot_activity_at TIMESTAMPTZ;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS last_site_visit_at TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS visits (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT REFERENCES users(telegram_id) ON DELETE SET NULL,
      visited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      session_key TEXT,
      user_agent TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_visits_visited_at
      ON visits(visited_at);

    CREATE INDEX IF NOT EXISTS idx_visits_telegram_id
      ON visits(telegram_id);

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL
        REFERENCES users(telegram_id)
        ON DELETE RESTRICT,
      source TEXT NOT NULL DEFAULT 'mini_app',
      customer_name TEXT,
      phone TEXT,
      address TEXT,
      address_plain TEXT,
      payment_method TEXT,
      delivery_fee INTEGER NOT NULL DEFAULT 0,
      items_total INTEGER NOT NULL DEFAULT 0,
      discount_percent INTEGER NOT NULL DEFAULT 0,
      discount_amount INTEGER NOT NULL DEFAULT 0,
      total INTEGER NOT NULL DEFAULT 0,
      order_when TEXT,
      order_date DATE,
      order_time TEXT,
      comment TEXT,
      status TEXT NOT NULL DEFAULT 'created',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_orders_created_at
      ON orders(created_at);

    CREATE INDEX IF NOT EXISTS idx_orders_telegram_id
      ON orders(telegram_id);

    CREATE TABLE IF NOT EXISTS order_items (
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,
      item_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      unit_price INTEGER NOT NULL,
      image_url TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_order_items_order_id
      ON order_items(order_id);
  `);
}

async function upsertTelegramUser(user) {
  const result = await pool.query(
    `
      INSERT INTO users (
        telegram_id,
        username,
        telegram_first_name,
        telegram_last_name,
        photo_url,
        created_at,
        updated_at,
        last_site_visit_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        NOW(),
        NOW(),
        NOW()
      )
      ON CONFLICT (telegram_id)
      DO UPDATE SET
        username = EXCLUDED.username,
        telegram_first_name = EXCLUDED.telegram_first_name,
        telegram_last_name = EXCLUDED.telegram_last_name,
        photo_url = COALESCE(EXCLUDED.photo_url, users.photo_url),
        updated_at = NOW(),
        last_site_visit_at = NOW()
      RETURNING *
    `,
    [
      String(user.id),
      user.username || null,
      user.first_name || null,
      user.last_name || null,
      user.photo_url || null
    ]
  );

  return result.rows[0];
}

async function getAccountData(telegramId) {
  const userResult = await pool.query(
    `
      SELECT
        u.*,

        COALESCE(
          (
            SELECT SUM(o.total)
            FROM orders o
            WHERE o.telegram_id = u.telegram_id
              AND COALESCE(o.status, 'created') <> 'cancelled'
          ),
          0
        )::int AS total_spend,

        COALESCE(
          (
            SELECT COUNT(*)
            FROM orders o
            WHERE o.telegram_id = u.telegram_id
              AND COALESCE(o.status, 'created') <> 'cancelled'
          ),
          0
        )::int AS orders_count

      FROM users u
      WHERE u.telegram_id = $1
    `,
    [String(telegramId)]
  );

  const user = userResult.rows[0];

  if (!user) {
    return null;
  }

  const ordersResult = await pool.query(
    `
      SELECT
        o.id,
        o.created_at,
        o.total,
        o.items_total,
        o.delivery_fee,
        o.discount_percent,
        o.discount_amount,
        o.payment_method,
        o.customer_name,
        o.phone,
        o.address_plain,
        o.address,

        COALESCE(
          json_agg(
            json_build_object(
              'name', oi.item_name,
              'qty', oi.quantity,
              'price', oi.unit_price,
              'img', oi.image_url
            )
            ORDER BY oi.id
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'::json
        ) AS items

      FROM orders o

      LEFT JOIN order_items oi
        ON oi.order_id = o.id

      WHERE o.telegram_id = $1
        AND COALESCE(o.status, 'created') <> 'cancelled'

      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT 30
    `,
    [String(telegramId)]
  );

  const totalSpend = Number(user.total_spend || 0);

  return {
    profile: {
      telegramId: String(user.telegram_id),
      username: user.username || "",
      telegramFirstName: user.telegram_first_name || "",
      telegramLastName: user.telegram_last_name || "",
      name:
        user.profile_name ||
        user.telegram_first_name ||
        "",
      phone: user.phone || "",
      address: user.address || "",
      photoUrl: user.photo_url || ""
    },

    loyalty: {
      totalSpend,
      discountPercent: discountBySpend(totalSpend),
      ordersCount: Number(user.orders_count || 0)
    },

    orders: ordersResult.rows
  };
}

/*
 * Проверка сервера и базы:
 * https://ВАШ-ДОМЕН.up.railway.app/health
 */
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    return res.status(200).json({
      ok: true,
      service: "Smoke Factory BBQ Mini App",
      database: "connected",
      telegramTokenConfigured: Boolean(BOT_TOKEN)
    });
  } catch (error) {
    console.error("GET /health:", error);

    return res.status(503).json({
      ok: false,
      service: "Smoke Factory BBQ Mini App",
      database: "disconnected"
    });
  }
});

/*
 * Вызывается при открытии Mini App.
 * Создаёт или обновляет Telegram-пользователя и загружает его профиль.
 */
app.post("/api/bootstrap", telegramAuth, async (req, res) => {
  try {
    const user = await upsertTelegramUser(req.telegramUser);

    const sessionKey =
      String(req.body?.sessionKey || "")
        .trim()
        .slice(0, 120) || null;

    const userAgent =
      String(req.get("user-agent") || "")
        .trim()
        .slice(0, 500) || null;

    await pool.query(
      `
        INSERT INTO visits (
          telegram_id,
          session_key,
          user_agent
        )
        VALUES ($1, $2, $3)
      `,
      [
        String(user.telegram_id),
        sessionKey,
        userAgent
      ]
    );

    const data = await getAccountData(user.telegram_id);

    console.log(
      `[ACCOUNT] Bootstrap completed for Telegram ID ${user.telegram_id}`
    );

    return res.json({
      ok: true,
      ...data
    });
  } catch (error) {
    console.error("POST /api/bootstrap:", error);

    return res.status(500).json({
      ok: false,
      error: "Database error"
    });
  }
});

async function saveProfileHandler(req, res) {
  try {
    await upsertTelegramUser(req.telegramUser);

    const telegramId = String(req.telegramUser.id);

    const name = String(req.body?.name || "")
      .trim()
      .slice(0, 120);

    const phone = String(req.body?.phone || "")
      .replace(/[\s()-]/g, "")
      .trim()
      .slice(0, 30);

    const address = String(req.body?.address || "")
      .trim()
      .slice(0, 500);

    if (!name) {
      return res.status(400).json({
        ok: false,
        error: "Введите имя"
      });
    }

    if (!/^\+66\d{9,10}$/.test(phone)) {
      return res.status(400).json({
        ok: false,
        error: "Проверьте номер телефона. Формат: +66XXXXXXXXX"
      });
    }

    if (address.length < 4) {
      return res.status(400).json({
        ok: false,
        error: "Введите адрес"
      });
    }

    const updateResult = await pool.query(
      `
        UPDATE users
        SET
          profile_name = $2,
          phone = $3,
          address = $4,
          updated_at = NOW()
        WHERE telegram_id = $1
        RETURNING telegram_id, profile_name, phone, address, updated_at
      `,
      [
        telegramId,
        name,
        phone,
        address
      ]
    );

    if (updateResult.rowCount !== 1) {
      throw new Error("User profile was not updated");
    }

    const data = await getAccountData(telegramId);

    console.log(
      `[PROFILE] Saved successfully for Telegram ID ${telegramId}`
    );

    return res.json({
      ok: true,
      ...data
    });
  } catch (error) {
    console.error(
      `${req.method} /api/profile:`,
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Database error"
    });
  }
}

/*
 * Текущий index.html использует PUT.
 * POST также оставлен для совместимости.
 */
app.put("/api/profile", telegramAuth, saveProfileHandler);
app.post("/api/profile", telegramAuth, saveProfileHandler);

/*
 * Повторная загрузка данных личного кабинета.
 */
app.get("/api/account", telegramAuth, async (req, res) => {
  try {
    await upsertTelegramUser(req.telegramUser);

    const data = await getAccountData(req.telegramUser.id);

    return res.json({
      ok: true,
      ...data
    });
  } catch (error) {
    console.error("GET /api/account:", error);

    return res.status(500).json({
      ok: false,
      error: "Database error"
    });
  }
});

/*
 * Неизвестные API-маршруты должны возвращать JSON,
 * а не содержимое index.html.
 */
app.use("/api", (req, res) => {
  return res.status(404).json({
    ok: false,
    error: `API route not found: ${req.method} ${req.originalUrl}`
  });
});

/*
 * Структура проекта:
 *
 * server.js
 * index.html
 * images/
 * package.json
 */
app.use(
  express.static(__dirname, {
    extensions: ["html"],
    index: "index.html",
    etag: true,
    maxAge: "1h"
  })
);

/*
 * Все остальные страницы открывают index.html.
 */
app.get("*", (req, res) => {
  return res.sendFile(path.join(__dirname, "index.html"), {
    headers: {
      "Cache-Control":
        "no-store, no-cache, must-revalidate, proxy-revalidate"
    }
  });
});

let server;

async function startServer() {
  try {
    await pool.query("SELECT 1");
    await ensureSchema();

    console.log("Database connected, schema ready");

    server = app.listen(PORT, "0.0.0.0", () => {
      console.log(`Smoke Factory Mini App started on port ${PORT}`);
    });

    server.on("error", (error) => {
      console.error("HTTP server error:", error);
    });
  } catch (error) {
    console.error("Database initialization failed:", error);
    process.exit(1);
  }
}

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  try {
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
    }

    await pool.end();

    console.log("Server stopped");
    process.exit(0);
  } catch (error) {
    console.error("Shutdown error:", error);
    process.exit(1);
  }
}

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  shutdown("SIGINT");
});

process.on("unhandledRejection", (error) => {
  console.error("Unhandled promise rejection:", error);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
});

startServer();
