const crypto = require("crypto");
const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

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
  ssl: DATABASE_URL.includes("railway.internal") ? false : { rejectUnauthorized: false }
});

app.use(express.json({ limit: "256kb" }));

function discountBySpend(totalSpend) {
  if (totalSpend >= 20000) return 20;
  if (totalSpend >= 15000) return 15;
  if (totalSpend >= 10000) return 10;
  if (totalSpend >= 5000) return 5;
  return 0;
}

function validateTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    throw new Error("Telegram initData is missing");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) throw new Error("Telegram hash is missing");

  params.delete("hash");
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
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

  const left = Buffer.from(calculatedHash, "hex");
  const right = Buffer.from(receivedHash, "hex");
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
    throw new Error("Invalid Telegram signature");
  }

  const authDate = Number(params.get("auth_date") || 0);
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || Math.abs(now - authDate) > 24 * 60 * 60) {
    throw new Error("Telegram authorization expired");
  }

  const rawUser = params.get("user");
  if (!rawUser) throw new Error("Telegram user is missing");
  return JSON.parse(rawUser);
}

function telegramAuth(req, res, next) {
  try {
    const initData = req.get("X-Telegram-Init-Data") || req.body?.initData || "";
    req.telegramUser = validateTelegramInitData(initData);
    next();
  } catch (error) {
    res.status(401).json({ ok: false, error: error.message });
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

    CREATE TABLE IF NOT EXISTS visits (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT REFERENCES users(telegram_id) ON DELETE SET NULL,
      visited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      session_key TEXT,
      user_agent TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_visits_visited_at ON visits(visited_at);
    CREATE INDEX IF NOT EXISTS idx_visits_telegram_id ON visits(telegram_id);

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL REFERENCES users(telegram_id) ON DELETE RESTRICT,
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
    CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
    CREATE INDEX IF NOT EXISTS idx_orders_telegram_id ON orders(telegram_id);

    CREATE TABLE IF NOT EXISTS order_items (
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      item_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      unit_price INTEGER NOT NULL,
      image_url TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
  `);
}

async function upsertTelegramUser(user) {
  const result = await pool.query(
    `INSERT INTO users (
       telegram_id, username, telegram_first_name, telegram_last_name, photo_url,
       created_at, updated_at, last_site_visit_at
     ) VALUES ($1,$2,$3,$4,$5,NOW(),NOW(),NOW())
     ON CONFLICT (telegram_id) DO UPDATE SET
       username = EXCLUDED.username,
       telegram_first_name = EXCLUDED.telegram_first_name,
       telegram_last_name = EXCLUDED.telegram_last_name,
       photo_url = COALESCE(EXCLUDED.photo_url, users.photo_url),
       updated_at = NOW(),
       last_site_visit_at = NOW()
     RETURNING *`,
    [user.id, user.username || null, user.first_name || null, user.last_name || null, user.photo_url || null]
  );
  return result.rows[0];
}

async function getAccountData(telegramId) {
  const userResult = await pool.query(
    `SELECT u.*,
       COALESCE((SELECT SUM(o.total) FROM orders o WHERE o.telegram_id=u.telegram_id AND o.status <> 'cancelled'),0)::int AS total_spend,
       COALESCE((SELECT COUNT(*) FROM orders o WHERE o.telegram_id=u.telegram_id AND o.status <> 'cancelled'),0)::int AS orders_count
     FROM users u WHERE u.telegram_id=$1`,
    [telegramId]
  );
  const user = userResult.rows[0];
  if (!user) return null;

  const orderResult = await pool.query(
    `SELECT o.id, o.created_at, o.total, o.items_total, o.delivery_fee,
            o.discount_percent, o.discount_amount, o.payment_method,
            o.customer_name, o.phone, o.address_plain, o.address,
            COALESCE(
              json_agg(json_build_object(
                'name', oi.item_name,
                'qty', oi.quantity,
                'price', oi.unit_price,
                'img', oi.image_url
              ) ORDER BY oi.id) FILTER (WHERE oi.id IS NOT NULL),
              '[]'::json
            ) AS items
     FROM orders o
     LEFT JOIN order_items oi ON oi.order_id=o.id
     WHERE o.telegram_id=$1 AND o.status <> 'cancelled'
     GROUP BY o.id
     ORDER BY o.created_at DESC
     LIMIT 30`,
    [telegramId]
  );

  const totalSpend = Number(user.total_spend || 0);
  return {
    profile: {
      telegramId: String(user.telegram_id),
      username: user.username,
      telegramFirstName: user.telegram_first_name,
      telegramLastName: user.telegram_last_name,
      name: user.profile_name || user.telegram_first_name || "",
      phone: user.phone || "",
      address: user.address || "",
      photoUrl: user.photo_url || ""
    },
    loyalty: {
      totalSpend,
      discountPercent: discountBySpend(totalSpend),
      ordersCount: Number(user.orders_count || 0)
    },
    orders: orderResult.rows
  };
}

app.post("/api/bootstrap", telegramAuth, async (req, res) => {
  try {
    const user = await upsertTelegramUser(req.telegramUser);
    await pool.query(
      `INSERT INTO visits (telegram_id, session_key, user_agent) VALUES ($1,$2,$3)`,
      [user.telegram_id, String(req.body?.sessionKey || "").slice(0, 120) || null, String(req.get("user-agent") || "").slice(0, 500)]
    );
    const data = await getAccountData(user.telegram_id);
    res.json({ ok: true, ...data });
  } catch (error) {
    console.error("/api/bootstrap", error);
    res.status(500).json({ ok: false, error: "Database error" });
  }
});

app.put("/api/profile", telegramAuth, async (req, res) => {
  try {
    await upsertTelegramUser(req.telegramUser);
    const name = String(req.body?.name || "").trim().slice(0, 120);
    const phone = String(req.body?.phone || "").trim().slice(0, 30);
    const address = String(req.body?.address || "").trim().slice(0, 500);

    if (!name) return res.status(400).json({ ok: false, error: "Введите имя" });
    if (!/^\+66\d{9,10}$/.test(phone)) return res.status(400).json({ ok: false, error: "Проверьте номер телефона" });
    if (address.length < 4) return res.status(400).json({ ok: false, error: "Введите адрес" });

    await pool.query(
      `UPDATE users SET profile_name=$2, phone=$3, address=$4, updated_at=NOW() WHERE telegram_id=$1`,
      [req.telegramUser.id, name, phone, address]
    );
    const data = await getAccountData(req.telegramUser.id);
    res.json({ ok: true, ...data });
  } catch (error) {
    console.error("/api/profile", error);
    res.status(500).json({ ok: false, error: "Database error" });
  }
});

app.get("/api/account", telegramAuth, async (req, res) => {
  try {
    await upsertTelegramUser(req.telegramUser);
    const data = await getAccountData(req.telegramUser.id);
    res.json({ ok: true, ...data });
  } catch (error) {
    console.error("/api/account", error);
    res.status(500).json({ ok: false, error: "Database error" });
  }
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.status(200).json({ ok: true, service: "Smoke Factory BBQ Mini App", database: "connected" });
  } catch (error) {
    res.status(503).json({ ok: false, service: "Smoke Factory BBQ Mini App", database: "disconnected" });
  }
});

app.use(express.static(__dirname, { extensions: ["html"], index: "index.html" }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

ensureSchema()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Smoke Factory Mini App started on port ${PORT}`);
      console.log("Database connected, schema ready");
    });
  })
  .catch((error) => {
    console.error("Database initialization failed", error);
    process.exit(1);
  });

