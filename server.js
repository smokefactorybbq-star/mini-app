const crypto = require("crypto");
const express = require("express");
const path = require("path");
const { Pool } = require("pg");

console.log("server.js loaded");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = String(
  process.env.DATABASE_URL || ""
).trim();

const BOT_TOKEN = String(
  process.env.TELEGRAM_BOT_TOKEN || ""
).trim();

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set");
  process.exit(1);
}

if (!BOT_TOKEN) {
  console.error(
    "ERROR: TELEGRAM_BOT_TOKEN is not set"
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: DATABASE_URL.includes(
    "railway.internal"
  )
    ? false
    : {
        rejectUnauthorized: false
      },

  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10
});

pool.on("error", (error) => {
  console.error(
    "Unexpected PostgreSQL pool error:",
    error
  );
});

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "256kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "256kb"
  })
);


/*
 * Логи HTTP-запросов.
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

  console.log(
    `[HTTP] ${req.method} ${req.path}`
  );

  res.on("finish", () => {
    const duration =
      Date.now() - startedAt;

    console.log(
      `[HTTP] ${req.method} ${req.path} ` +
      `-> ${res.statusCode} (${duration} ms)`
    );
  });

  next();
});


/*
 * Не кэшируем HTML и API.
 */
app.use((req, res, next) => {
  if (
    req.path === "/" ||
    req.path.endsWith(".html") ||
    req.path.startsWith("/api/")
  ) {
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, " +
      "proxy-revalidate"
    );

    res.setHeader(
      "Pragma",
      "no-cache"
    );

    res.setHeader(
      "Expires",
      "0"
    );
  }

  next();
});


/*
 * Размер скидки в зависимости
 * от общей накопленной суммы.
 */
function discountBySpend(totalSpend) {
  const spend = Number(
    totalSpend || 0
  );

  if (spend >= 20000) {
    return 20;
  }

  if (spend >= 15000) {
    return 15;
  }

  if (spend >= 10000) {
    return 10;
  }

  if (spend >= 5000) {
    return 5;
  }

  return 0;
}


/*
 * Процент кэшбэка.
 * Оставляем ту же шкалу, которая уже использовалась
 * в личном кабинете.
 */
function cashbackBySpend(totalSpend) {
  return discountBySpend(totalSpend);
}


/*
 * Строка для HMAC-подписи запроса списания/начисления бонусов.
 * Порядок полей должен совпадать с bot.py.
 */
function loyaltySignaturePayload(
  body,
  timestamp
) {
  return [
    String(body.telegramId || ""),
    String(body.orderRef || ""),
    String(Number(body.itemsTotal || 0)),
    String(Number(body.delivery || 0)),
    String(Number(body.requestedBonus || 0)),
    String(timestamp || "")
  ].join("|");
}


/*
 * Проверка подписи запроса от бота.
 */
function verifyLoyaltySignature(req) {
  const timestamp = String(
    req.get("X-Loyalty-Timestamp") || ""
  );

  const received = String(
    req.get("X-Loyalty-Signature") || ""
  );

  if (!timestamp || !received) {
    throw new Error(
      "Loyalty signature is missing"
    );
  }

  const now = Math.floor(
    Date.now() / 1000
  );

  const ts = Number(timestamp);

  if (
    !Number.isFinite(ts) ||
    Math.abs(now - ts) > 300
  ) {
    throw new Error(
      "Loyalty request expired"
    );
  }

  const expected = crypto
    .createHmac(
      "sha256",
      BOT_TOKEN
    )
    .update(
      loyaltySignaturePayload(
        req.body || {},
        timestamp
      )
    )
    .digest("hex");

  if (!safeHexEqual(received, expected)) {
    throw new Error(
      "Invalid loyalty signature"
    );
  }
}


/*
 * Безопасное сравнение HEX-подписей.
 */
function safeHexEqual(
  received,
  expected
) {
  try {
    const receivedText = String(
      received || ""
    );

    const expectedText = String(
      expected || ""
    );

    if (
      !/^[a-f0-9]{64}$/i.test(
        receivedText
      ) ||
      !/^[a-f0-9]{64}$/i.test(
        expectedText
      )
    ) {
      return false;
    }

    const receivedBuffer =
      Buffer.from(
        receivedText,
        "hex"
      );

    const expectedBuffer =
      Buffer.from(
        expectedText,
        "hex"
      );

    if (
      receivedBuffer.length !==
      expectedBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      receivedBuffer,
      expectedBuffer
    );

  } catch (_) {
    return false;
  }
}


/*
 * Проверка обычного Telegram WebApp initData.
 */
function validateTelegramInitData(
  initData
) {
  if (
    !initData ||
    typeof initData !== "string"
  ) {
    throw new Error(
      "Telegram initData is missing"
    );
  }

  const params =
    new URLSearchParams(initData);

  const receivedHash =
    params.get("hash");

  if (!receivedHash) {
    throw new Error(
      "Telegram hash is missing"
    );
  }

  params.delete("hash");

  const dataCheckString =
    [...params.entries()]
      .sort(
        ([keyA], [keyB]) =>
          keyA.localeCompare(keyB)
      )
      .map(
        ([key, value]) =>
          `${key}=${value}`
      )
      .join("\n");

  const secretKey = crypto
    .createHmac(
      "sha256",
      "WebAppData"
    )
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac(
      "sha256",
      secretKey
    )
    .update(dataCheckString)
    .digest("hex");

  if (
    !safeHexEqual(
      receivedHash,
      calculatedHash
    )
  ) {
    throw new Error(
      "Invalid Telegram signature"
    );
  }

  const authDate = Number(
    params.get("auth_date") || 0
  );

  const currentTime = Math.floor(
    Date.now() / 1000
  );

  if (
    !authDate ||
    currentTime - authDate >
      24 * 60 * 60 ||
    authDate > currentTime + 5 * 60
  ) {
    throw new Error(
      "Telegram authorization expired"
    );
  }

  const rawUser =
    params.get("user");

  if (!rawUser) {
    throw new Error(
      "Telegram user is missing"
    );
  }

  let user;

  try {
    user = JSON.parse(rawUser);
  } catch (_) {
    throw new Error(
      "Invalid Telegram user data"
    );
  }

  if (
    !user ||
    !user.id
  ) {
    throw new Error(
      "Telegram user ID is missing"
    );
  }

  return user;
}


/*
 * Расшифровка Base64 URL.
 */
function decodeBase64Url(value) {
  const normalized = String(
    value || ""
  )
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const paddingLength =
    (
      4 -
      (
        normalized.length % 4
      )
    ) % 4;

  const padded =
    normalized +
    "=".repeat(paddingLength);

  return Buffer
    .from(
      padded,
      "base64"
    )
    .toString("utf8");
}


/*
 * Проверка подписанной ссылки,
 * которую создаёт bot.py.
 */
function validateSignedLaunchToken(
  token,
  receivedSignature
) {
  if (
    !token ||
    !receivedSignature
  ) {
    throw new Error(
      "Signed Mini App authorization " +
      "is missing"
    );
  }

  const calculatedSignature = crypto
    .createHmac(
      "sha256",
      BOT_TOKEN
    )
    .update(
      String(token)
    )
    .digest("hex");

  if (
    !safeHexEqual(
      receivedSignature,
      calculatedSignature
    )
  ) {
    throw new Error(
      "Invalid Mini App signature"
    );
  }

  let payload;

  try {
    payload = JSON.parse(
      decodeBase64Url(token)
    );
  } catch (_) {
    throw new Error(
      "Invalid Mini App user token"
    );
  }

  const timestamp = Number(
    payload?.t ||
    payload?.ts ||
    0
  );

  const currentTime = Math.floor(
    Date.now() / 1000
  );

  const maxAgeSeconds =
    30 * 24 * 60 * 60;

  if (
    !timestamp ||
    currentTime - timestamp >
      maxAgeSeconds ||
    timestamp >
      currentTime + 5 * 60
  ) {
    throw new Error(
      "Mini App button expired. " +
      "Send /start to the bot"
    );
  }

  if (
    !(
      payload?.i ||
      payload?.id
    )
  ) {
    throw new Error(
      "Mini App user ID is missing"
    );
  }

  return {
    id:
      payload.i ||
      payload.id,

    username:
      payload.n ||
      payload.username ||
      "",

    first_name:
      payload.f ||
      payload.first_name ||
      "",

    last_name:
      payload.l ||
      payload.last_name ||
      "",

    photo_url:
      payload.p ||
      payload.photo_url ||
      ""
  };
}


/*
 * Авторизация личного кабинета.
 */
function miniAppAuth(
  req,
  res,
  next
) {
  try {
    const initData =
      req.get(
        "X-Telegram-Init-Data"
      ) ||
      req.body?.initData ||
      "";

    if (initData) {
      req.telegramUser =
        validateTelegramInitData(
          initData
        );

      req.authSource =
        "telegram-init-data";

      return next();
    }

    const token =
      req.get(
        "X-Miniapp-User-Token"
      ) ||
      req.body?.miniAppUserToken ||
      "";

    const signature =
      req.get(
        "X-Miniapp-Signature"
      ) ||
      req.body?.miniAppSignature ||
      "";

    req.telegramUser =
      validateSignedLaunchToken(
        token,
        signature
      );

    req.authSource =
      "signed-keyboard-url";

    return next();

  } catch (error) {
    console.error(
      `[AUTH] ${req.method} ` +
      `${req.path}: ` +
      error.message
    );

    return res.status(401).json({
      ok: false,
      error: error.message
    });
  }
}


/*
 * Создание и обновление таблиц.
 */
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
      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),
      last_bot_activity_at TIMESTAMPTZ,
      last_site_visit_at TIMESTAMPTZ
    );


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      username TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      telegram_first_name TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      telegram_last_name TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      profile_name TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      phone TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      address TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      photo_url TEXT;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ
      NOT NULL DEFAULT NOW();


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      updated_at TIMESTAMPTZ
      NOT NULL DEFAULT NOW();


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      last_bot_activity_at
      TIMESTAMPTZ;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      last_site_visit_at
      TIMESTAMPTZ;


    /*
     * Ручная историческая сумма,
     * заданная менеджером через /bonus.
     */
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      manual_spend BIGINT
      NOT NULL DEFAULT 0;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      bonus_updated_at
      TIMESTAMPTZ;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      bonus_updated_by BIGINT;


    /*
     * Баланс бонусов и накопленная сумма
     * для новой системы кэшбэка.
     */
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      bonus_balance INTEGER
      NOT NULL DEFAULT 0;


    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      lifetime_spend BIGINT
      NOT NULL DEFAULT 0;


    CREATE TABLE IF NOT EXISTS visits (
      id BIGSERIAL PRIMARY KEY,

      telegram_id BIGINT
        REFERENCES users(telegram_id)
        ON DELETE SET NULL,

      visited_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      session_key TEXT,
      user_agent TEXT
    );


    CREATE INDEX IF NOT EXISTS
      idx_visits_visited_at
    ON visits(visited_at);


    CREATE INDEX IF NOT EXISTS
      idx_visits_telegram_id
    ON visits(telegram_id);


    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,

      telegram_id BIGINT NOT NULL
        REFERENCES users(telegram_id)
        ON DELETE RESTRICT,

      source TEXT
        NOT NULL DEFAULT 'mini_app',

      customer_name TEXT,
      phone TEXT,
      address TEXT,
      address_plain TEXT,
      payment_method TEXT,

      delivery_fee INTEGER
        NOT NULL DEFAULT 0,

      items_total INTEGER
        NOT NULL DEFAULT 0,

      discount_percent INTEGER
        NOT NULL DEFAULT 0,

      discount_amount INTEGER
        NOT NULL DEFAULT 0,

      total INTEGER
        NOT NULL DEFAULT 0,

      order_when TEXT,
      order_date DATE,
      order_time TEXT,
      comment TEXT,

      status TEXT
        NOT NULL DEFAULT 'created',

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );


    CREATE INDEX IF NOT EXISTS
      idx_orders_created_at
    ON orders(created_at);


    CREATE INDEX IF NOT EXISTS
      idx_orders_telegram_id
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


    CREATE INDEX IF NOT EXISTS
      idx_order_items_order_id
    ON order_items(order_id);


    /*
     * История ручных изменений
     * суммы программы лояльности.
     */
    CREATE TABLE IF NOT EXISTS
      loyalty_adjustments (
        id BIGSERIAL PRIMARY KEY,

        request_id TEXT UNIQUE,

        telegram_id BIGINT NOT NULL,

        previous_amount BIGINT
          NOT NULL DEFAULT 0,

        new_amount BIGINT
          NOT NULL DEFAULT 0,

        created_by BIGINT,

        source TEXT
          NOT NULL DEFAULT
          'manager_bonus',

        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
      );


    CREATE INDEX IF NOT EXISTS
      idx_loyalty_adjustments_user
    ON loyalty_adjustments(
      telegram_id
    );


    CREATE INDEX IF NOT EXISTS
      idx_loyalty_adjustments_created
    ON loyalty_adjustments(
      created_at DESC
    );


    /*
     * Идемпотентные операции списания и начисления бонусов.
     */
    CREATE TABLE IF NOT EXISTS
      loyalty_transactions (
        id BIGSERIAL PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        telegram_id BIGINT NOT NULL,
        order_ref TEXT NOT NULL,
        items_total INTEGER NOT NULL,
        delivery_fee INTEGER NOT NULL DEFAULT 0,
        bonus_used INTEGER NOT NULL DEFAULT 0,
        cashback_percent INTEGER NOT NULL DEFAULT 0,
        cashback_earned INTEGER NOT NULL DEFAULT 0,
        balance_before INTEGER NOT NULL DEFAULT 0,
        balance_after INTEGER NOT NULL DEFAULT 0,
        lifetime_spend_before BIGINT NOT NULL DEFAULT 0,
        lifetime_spend_after BIGINT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );


    CREATE INDEX IF NOT EXISTS
      idx_loyalty_transactions_user
    ON loyalty_transactions(
      telegram_id,
      created_at DESC
    );
  `);
}


/*
 * Создание или обновление
 * Telegram-пользователя.
 */
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
        username =
          EXCLUDED.username,

        telegram_first_name =
          EXCLUDED.telegram_first_name,

        telegram_last_name =
          EXCLUDED.telegram_last_name,

        photo_url =
          COALESCE(
            EXCLUDED.photo_url,
            users.photo_url
          ),

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


/*
 * Полные данные личного кабинета.
 */
async function getAccountData(
  telegramId
) {
  const userResult = await pool.query(
    `
      SELECT
        u.*,

        COALESCE(
          (
            SELECT SUM(o.total)
            FROM orders o
            WHERE
              o.telegram_id =
                u.telegram_id

              AND COALESCE(
                o.status,
                'created'
              ) <> 'cancelled'
          ),
          0
        )::bigint AS order_spend,

        COALESCE(
          (
            SELECT COUNT(*)
            FROM orders o
            WHERE
              o.telegram_id =
                u.telegram_id

              AND COALESCE(
                o.status,
                'created'
              ) <> 'cancelled'
          ),
          0
        )::int AS orders_count

      FROM users u

      WHERE u.telegram_id = $1
    `,
    [
      String(telegramId)
    ]
  );

  const user =
    userResult.rows[0];

  if (!user) {
    return null;
  }

  const ordersResult =
    await pool.query(
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
                'name',
                oi.item_name,

                'qty',
                oi.quantity,

                'price',
                oi.unit_price,

                'img',
                oi.image_url
              )
              ORDER BY oi.id
            )
            FILTER (
              WHERE oi.id
              IS NOT NULL
            ),
            '[]'::json
          ) AS items

        FROM orders o

        LEFT JOIN order_items oi
          ON oi.order_id = o.id

        WHERE
          o.telegram_id = $1

          AND COALESCE(
            o.status,
            'created'
          ) <> 'cancelled'

        GROUP BY o.id

        ORDER BY
          o.created_at DESC

        LIMIT 30
      `,
      [
        String(telegramId)
      ]
    );

  const orderSpend = Number(
    user.order_spend || 0
  );

  const manualSpend = Number(
    user.manual_spend || 0
  );

  const totalSpend =
    orderSpend + manualSpend;

  return {
    profile: {
      telegramId: String(
        user.telegram_id
      ),

      username:
        user.username || "",

      telegramFirstName:
        user.telegram_first_name ||
        "",

      telegramLastName:
        user.telegram_last_name ||
        "",

      name:
        user.profile_name ||
        user.telegram_first_name ||
        "",

      phone:
        user.phone || "",

      address:
        user.address || "",

      photoUrl:
        user.photo_url || ""
    },

    loyalty: {
      totalSpend,
      orderSpend,
      manualSpend,

      /*
       * Старые поля сохранены, поэтому личный кабинет
       * продолжает работать как раньше.
       */
      discountPercent:
        discountBySpend(
          totalSpend
        ),

      /*
       * Новые поля для бонусного баланса и кэшбэка.
       */
      lifetimeSpend: Math.max(
        Number(user.lifetime_spend || 0),
        totalSpend
      ),

      cashbackPercent:
        cashbackBySpend(
          Math.max(
            Number(user.lifetime_spend || 0),
            totalSpend
          )
        ),

      balance: Math.max(
        0,
        Number(user.bonus_balance || 0)
      ),

      bonusBalance: Math.max(
        0,
        Number(user.bonus_balance || 0)
      ),

      maxRedeemPercent: 20,

      ordersCount: Number(
        user.orders_count || 0
      ),

      bonusUpdatedAt:
        user.bonus_updated_at ||
        null,

      bonusUpdatedBy:
        user.bonus_updated_by ||
        null
    },

    orders:
      ordersResult.rows
  };
}


/*
 * Проверка сервера и PostgreSQL.
 */
app.get(
  "/health",
  async (req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      return res
        .status(200)
        .json({
          ok: true,

          service:
            "Smoke Factory BBQ " +
            "Mini App",

          database:
            "connected",

          telegramTokenConfigured:
            Boolean(BOT_TOKEN)
        });

    } catch (error) {
      console.error(
        "GET /health:",
        error
      );

      return res
        .status(503)
        .json({
          ok: false,

          service:
            "Smoke Factory BBQ " +
            "Mini App",

          database:
            "disconnected"
        });
    }
  }
);


/*
 * Открытие Mini App.
 */
app.post(
  "/api/bootstrap",
  miniAppAuth,
  async (req, res) => {
    try {
      const user =
        await upsertTelegramUser(
          req.telegramUser
        );

      const sessionKey =
        String(
          req.body?.sessionKey ||
          ""
        )
          .trim()
          .slice(0, 120) ||
        null;

      const userAgent =
        String(
          req.get(
            "user-agent"
          ) ||
          ""
        )
          .trim()
          .slice(0, 500) ||
        null;

      await pool.query(
        `
          INSERT INTO visits (
            telegram_id,
            session_key,
            user_agent
          )
          VALUES (
            $1,
            $2,
            $3
          )
        `,
        [
          String(
            user.telegram_id
          ),
          sessionKey,
          userAgent
        ]
      );

      const data =
        await getAccountData(
          user.telegram_id
        );

      console.log(
        "[ACCOUNT] Bootstrap " +
        "completed for Telegram ID " +
        `${user.telegram_id}; ` +
        `auth=${req.authSource}`
      );

      return res.json({
        ok: true,
        ...data
      });

    } catch (error) {
      console.error(
        "POST /api/bootstrap:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          error: "Database error"
        });
    }
  }
);


/*
 * Сохранение имени, телефона
 * и адреса пользователя.
 */
async function saveProfileHandler(
  req,
  res
) {
  try {
    await upsertTelegramUser(
      req.telegramUser
    );

    const telegramId = String(
      req.telegramUser.id
    );

    const name = String(
      req.body?.name || ""
    )
      .trim()
      .slice(0, 120);

    const phone = String(
      req.body?.phone || ""
    )
      .replace(
        /[\s()-]/g,
        ""
      )
      .trim()
      .slice(0, 30);

    const address = String(
      req.body?.address || ""
    )
      .trim()
      .slice(0, 500);

    if (!name) {
      return res
        .status(400)
        .json({
          ok: false,
          error: "Введите имя"
        });
    }

    if (
      !/^\+66\d{9,10}$/.test(
        phone
      )
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "Проверьте номер телефона. " +
            "Формат: +66XXXXXXXXX"
        });
    }

    if (
      address.length < 4
    ) {
      return res
        .status(400)
        .json({
          ok: false,
          error: "Введите адрес"
        });
    }

    const updateResult =
      await pool.query(
        `
          UPDATE users
          SET
            profile_name = $2,
            phone = $3,
            address = $4,
            updated_at = NOW()

          WHERE telegram_id = $1

          RETURNING
            telegram_id,
            profile_name,
            phone,
            address,
            updated_at
        `,
        [
          telegramId,
          name,
          phone,
          address
        ]
      );

    if (
      updateResult.rowCount !== 1
    ) {
      throw new Error(
        "User profile was not updated"
      );
    }

    const data =
      await getAccountData(
        telegramId
      );

    console.log(
      "[PROFILE] Saved successfully " +
      `for Telegram ID ${telegramId}`
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

    return res
      .status(500)
      .json({
        ok: false,
        error: "Database error"
      });
  }
}


app.put(
  "/api/profile",
  miniAppAuth,
  saveProfileHandler
);


app.post(
  "/api/profile",
  miniAppAuth,
  saveProfileHandler
);


/*
 * Повторная загрузка
 * личного кабинета.
 */
app.get(
  "/api/account",
  miniAppAuth,
  async (req, res) => {
    try {
      await upsertTelegramUser(
        req.telegramUser
      );

      const data =
        await getAccountData(
          req.telegramUser.id
        );

      return res.json({
        ok: true,
        ...data
      });

    } catch (error) {
      console.error(
        "GET /api/account:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          error: "Database error"
        });
    }
  }
);


/*
 * Создание строки, которую подписывает
 * bot.py для команды /bonus.
 *
 * Порядок ключей должен быть:
 * amount
 * managerId
 * requestId
 * telegramId
 * timestamp
 */
function makeBonusPayload({
  telegramId,
  amount,
  managerId,
  timestamp,
  requestId
}) {
  return JSON.stringify({
    amount,
    managerId,
    requestId,
    telegramId: String(
      telegramId
    ),
    timestamp
  });
}


/*
 * Команда /bonus из бота.
 *
 * Этот маршрут не доступен обычному
 * пользователю Mini App. Запрос должен
 * иметь HMAC-подпись токеном бота.
 */
app.post(
  "/api/admin/bonus",
  async (req, res) => {
    const telegramId = String(
      req.body?.telegramId || ""
    ).trim();

    const amount = Number(
      req.body?.amount
    );

    const managerId = Number(
      req.body?.managerId
    );

    const timestamp = Number(
      req.body?.timestamp
    );

    const requestId = String(
      req.body?.requestId || ""
    )
      .trim()
      .slice(0, 250);

    const receivedSignature =
      String(
        req.get(
          "X-Bonus-Signature"
        ) || ""
      ).trim();

    if (
      !/^\d+$/.test(
        telegramId
      )
    ) {
      return res
        .status(400)
        .json({
          ok: false,
          error:
            "Неверный Telegram ID"
        });
    }

    if (
      !Number.isSafeInteger(
        amount
      ) ||
      amount < 0 ||
      amount > 10000000
    ) {
      return res
        .status(400)
        .json({
          ok: false,
          error: "Неверная сумма"
        });
    }

    if (
      !Number.isSafeInteger(
        managerId
      ) ||
      managerId <= 0
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "Неверный ID менеджера"
        });
    }

    const currentTimestamp =
      Math.floor(
        Date.now() / 1000
      );

    if (
      !Number.isSafeInteger(
        timestamp
      ) ||
      Math.abs(
        currentTimestamp -
        timestamp
      ) > 300
    ) {
      return res
        .status(401)
        .json({
          ok: false,
          error: "Запрос устарел"
        });
    }

    if (!requestId) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "Отсутствует requestId"
        });
    }

    const payload =
      makeBonusPayload({
        telegramId,
        amount,
        managerId,
        timestamp,
        requestId
      });

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          BOT_TOKEN
        )
        .update(payload)
        .digest("hex");

    if (
      !safeHexEqual(
        receivedSignature,
        expectedSignature
      )
    ) {
      console.error(
        "[BONUS] Invalid signature"
      );

      return res
        .status(401)
        .json({
          ok: false,

          error:
            "Неверная подпись запроса"
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      /*
       * Если этот requestId уже был
       * обработан, повторно историю
       * не записываем.
       */
      const duplicateResult =
        await client.query(
          `
            SELECT
              telegram_id,
              new_amount
            FROM loyalty_adjustments
            WHERE request_id = $1
            LIMIT 1
          `,
          [
            requestId
          ]
        );

      if (
        duplicateResult.rowCount > 0
      ) {
        await client.query(
          "COMMIT"
        );

        const account =
          await getAccountData(
            telegramId
          );

        return res.json({
          ok: true,
          duplicate: true,
          telegramId,

          previousAmount:
            Number(
              duplicateResult
                .rows[0]
                .new_amount || 0
            ),

          manualSpend:
            Number(
              account?.loyalty
                ?.manualSpend || 0
            ),

          orderSpend:
            Number(
              account?.loyalty
                ?.orderSpend || 0
            ),

          totalSpend:
            Number(
              account?.loyalty
                ?.totalSpend || 0
            ),

          discountPercent:
            Number(
              account?.loyalty
                ?.discountPercent || 0
            )
        });
      }

      const previousResult =
        await client.query(
          `
            SELECT manual_spend
            FROM users
            WHERE telegram_id = $1
            FOR UPDATE
          `,
          [
            telegramId
          ]
        );

      const previousAmount =
        Number(
          previousResult
            .rows[0]
            ?.manual_spend ||
          0
        );

      /*
       * Создаём пользователя, если
       * он ещё не открывал Mini App.
       *
       * Если пользователь существует,
       * меняем только ручную сумму.
       */
      await client.query(
        `
          INSERT INTO users (
            telegram_id,
            manual_spend,
            bonus_updated_at,
            bonus_updated_by,
            created_at,
            updated_at
          )
          VALUES (
            $1,
            $2,
            NOW(),
            $3,
            NOW(),
            NOW()
          )

          ON CONFLICT (telegram_id)
          DO UPDATE SET
            manual_spend =
              EXCLUDED.manual_spend,

            bonus_updated_at = NOW(),

            bonus_updated_by =
              EXCLUDED.bonus_updated_by,

            updated_at = NOW()
        `,
        [
          telegramId,
          amount,
          managerId
        ]
      );

      await client.query(
        `
          INSERT INTO
            loyalty_adjustments (
              request_id,
              telegram_id,
              previous_amount,
              new_amount,
              created_by,
              source
            )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            'manager_bonus'
          )
        `,
        [
          requestId,
          telegramId,
          previousAmount,
          amount,
          managerId
        ]
      );

      await client.query(
        "COMMIT"
      );

      const account =
        await getAccountData(
          telegramId
        );

      console.log(
        "[BONUS] Updated:",
        {
          telegramId,
          previousAmount,
          newAmount: amount,
          managerId,

          totalSpend:
            account?.loyalty
              ?.totalSpend,

          discountPercent:
            account?.loyalty
              ?.discountPercent
        }
      );

      return res.json({
        ok: true,
        duplicate: false,
        telegramId,
        previousAmount,

        manualSpend:
          Number(
            account?.loyalty
              ?.manualSpend ||
            amount
          ),

        orderSpend:
          Number(
            account?.loyalty
              ?.orderSpend || 0
          ),

        totalSpend:
          Number(
            account?.loyalty
              ?.totalSpend ||
            amount
          ),

        discountPercent:
          Number(
            account?.loyalty
              ?.discountPercent || 0
          )
      });

    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (
        rollbackError
      ) {
        console.error(
          "[BONUS] Rollback error:",
          rollbackError
        );
      }

      console.error(
        "POST /api/admin/bonus:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Не удалось сохранить сумму"
        });

    } finally {
      client.release();
    }
  }
);



/*
 * Безопасное списание бонусов и начисление кэшбэка.
 * Ошибка чековой программы на этот маршрут не влияет.
 */
async function loyaltySettleHandler(
  req,
  res
) {
  const client =
    await pool.connect();

  try {
    verifyLoyaltySignature(req);

    const telegramId = String(
      req.body?.telegramId || ""
    ).trim();

    const orderRef = String(
      req.body?.orderRef || ""
    )
      .trim()
      .slice(0, 160);

    const requestId =
      `order:${telegramId}:${orderRef}`;

    const itemsTotal = Math.max(
      0,
      Math.min(
        1000000,
        Math.floor(
          Number(
            req.body?.itemsTotal || 0
          )
        )
      )
    );

    const delivery = Math.max(
      0,
      Math.min(
        100000,
        Math.floor(
          Number(
            req.body?.delivery || 0
          )
        )
      )
    );

    const requestedBonus = Math.max(
      0,
      Math.min(
        1000000,
        Math.floor(
          Number(
            req.body?.requestedBonus || 0
          )
        )
      )
    );

    if (
      !telegramId ||
      !orderRef ||
      itemsTotal <= 0
    ) {
      return res
        .status(400)
        .json({
          ok: false,
          error:
            "Invalid loyalty order data"
        });
    }

    await client.query("BEGIN");

    const existing =
      await client.query(
        `
          SELECT *
          FROM loyalty_transactions
          WHERE request_id = $1
          FOR UPDATE
        `,
        [requestId]
      );

    if (existing.rowCount > 0) {
      const row = existing.rows[0];

      await client.query("COMMIT");

      return res.json({
        ok: true,
        idempotent: true,
        bonusUsed: Number(
          row.bonus_used || 0
        ),
        cashbackPercent: Number(
          row.cashback_percent || 0
        ),
        cashbackEarned: Number(
          row.cashback_earned || 0
        ),
        balanceBefore: Number(
          row.balance_before || 0
        ),
        balanceAfter: Number(
          row.balance_after || 0
        ),
        lifetimeSpendBefore: Number(
          row.lifetime_spend_before || 0
        ),
        lifetimeSpendAfter: Number(
          row.lifetime_spend_after || 0
        ),
        maxRedeemPercent: 20,
        total: Math.max(
          0,
          Number(row.items_total || 0) -
          Number(row.bonus_used || 0) +
          Number(row.delivery_fee || 0)
        )
      });
    }

    await client.query(
      `
        INSERT INTO users (
          telegram_id,
          created_at,
          updated_at,
          bonus_balance,
          lifetime_spend
        )
        VALUES (
          $1,
          NOW(),
          NOW(),
          0,
          0
        )
        ON CONFLICT (telegram_id)
        DO NOTHING
      `,
      [telegramId]
    );

    const userResult =
      await client.query(
        `
          SELECT
            telegram_id,
            bonus_balance,
            lifetime_spend,
            manual_spend
          FROM users
          WHERE telegram_id = $1
          FOR UPDATE
        `,
        [telegramId]
      );

    if (userResult.rowCount === 0) {
      throw new Error(
        "Loyalty user not found"
      );
    }

    const user =
      userResult.rows[0];

    const balanceBefore = Math.max(
      0,
      Number(
        user.bonus_balance || 0
      )
    );

    /*
     * Для старых клиентов учитываем ручную сумму /bonus,
     * чтобы их уровень не сбросился после обновления.
     */
    const lifetimeSpendBefore = Math.max(
      Number(
        user.lifetime_spend || 0
      ),
      Number(
        user.manual_spend || 0
      )
    );

    const cashbackPercent =
      cashbackBySpend(
        lifetimeSpendBefore
      );

    const maxByOrder =
      Math.floor(
        itemsTotal * 20 / 100
      );

    const bonusUsed = Math.min(
      requestedBonus,
      balanceBefore,
      maxByOrder
    );

    const cashbackBase = Math.max(
      0,
      itemsTotal - bonusUsed
    );

    const cashbackEarned =
      Math.floor(
        cashbackBase *
        cashbackPercent /
        100
      );

    const balanceAfter = Math.max(
      0,
      balanceBefore -
      bonusUsed +
      cashbackEarned
    );

    const lifetimeSpendAfter =
      lifetimeSpendBefore +
      cashbackBase;

    await client.query(
      `
        UPDATE users
        SET
          bonus_balance = $2,
          lifetime_spend = $3,
          updated_at = NOW()
        WHERE telegram_id = $1
      `,
      [
        telegramId,
        balanceAfter,
        lifetimeSpendAfter
      ]
    );

    await client.query(
      `
        INSERT INTO loyalty_transactions (
          request_id,
          telegram_id,
          order_ref,
          items_total,
          delivery_fee,
          bonus_used,
          cashback_percent,
          cashback_earned,
          balance_before,
          balance_after,
          lifetime_spend_before,
          lifetime_spend_after
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,
          $7,$8,$9,$10,$11,$12
        )
      `,
      [
        requestId,
        telegramId,
        orderRef,
        itemsTotal,
        delivery,
        bonusUsed,
        cashbackPercent,
        cashbackEarned,
        balanceBefore,
        balanceAfter,
        lifetimeSpendBefore,
        lifetimeSpendAfter
      ]
    );

    await client.query("COMMIT");

    return res.json({
      ok: true,
      idempotent: false,
      bonusUsed,
      cashbackPercent,
      cashbackEarned,
      balanceBefore,
      balanceAfter,
      lifetimeSpendBefore,
      lifetimeSpendAfter,
      maxRedeemPercent: 20,
      maxRedeemAmount: maxByOrder,
      total: Math.max(
        0,
        itemsTotal -
        bonusUsed +
        delivery
      )
    });

  } catch (error) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch (_) {}

    console.error(
      "POST /api/loyalty/settle:",
      error
    );

    const authError =
      /signature|expired/i.test(
        String(
          error?.message || ""
        )
      );

    return res
      .status(
        authError ? 401 : 500
      )
      .json({
        ok: false,
        error: authError
          ? "Unauthorized loyalty request"
          : "Loyalty transaction failed"
      });

  } finally {
    client.release();
  }
}


/*
 * Основной маршрут для bot.py.
 * Второй адрес оставлен как совместимый резерв.
 */
app.post(
  "/api/loyalty/settle",
  loyaltySettleHandler
);

app.post(
  "/loyalty/settle",
  loyaltySettleHandler
);


/*
 * Неизвестные API-маршруты
 * возвращают JSON.
 */
app.use(
  "/api",
  (req, res) => {
    return res
      .status(404)
      .json({
        ok: false,

        error:
          "API route not found: " +
          `${req.method} ` +
          `${req.originalUrl}`
      });
  }
);


/*
 * Статические файлы:
 *
 * server.js
 * index.html
 * images/
 * package.json
 */
app.use(
  express.static(
    __dirname,
    {
      extensions: [
        "html"
      ],

      index:
        "index.html",

      etag: true,
      maxAge: "1h"
    }
  )
);


/*
 * Остальные GET-запросы
 * открывают index.html.
 */
app.use(
  (req, res, next) => {
    if (
      req.method !== "GET"
    ) {
      return next();
    }

    return res.sendFile(
      path.join(
        __dirname,
        "index.html"
      ),
      {
        headers: {
          "Cache-Control":
            "no-store, no-cache, " +
            "must-revalidate, " +
            "proxy-revalidate"
        }
      }
    );
  }
);


let server;


/*
 * Запуск сервера.
 */
async function startServer() {
  try {
    await pool.query(
      "SELECT 1"
    );

    await ensureSchema();

    console.log(
      "Database connected, schema ready"
    );

    server = app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "Smoke Factory Mini App " +
          `started on port ${PORT}`
        );
      }
    );

    server.on(
      "error",
      (error) => {
        console.error(
          "HTTP server error:",
          error
        );
      }
    );

  } catch (error) {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  }
}


/*
 * Корректная остановка Railway.
 */
async function shutdown(signal) {
  console.log(
    `${signal} received. ` +
    "Shutting down..."
  );

  try {
    if (server) {
      await new Promise(
        (resolve) => {
          server.close(resolve);
        }
      );
    }

    await pool.end();

    console.log(
      "Server stopped"
    );

    process.exit(0);

  } catch (error) {
    console.error(
      "Shutdown error:",
      error
    );

    process.exit(1);
  }
}


process.on(
  "SIGTERM",
  () => {
    shutdown("SIGTERM");
  }
);


process.on(
  "SIGINT",
  () => {
    shutdown("SIGINT");
  }
);


process.on(
  "unhandledRejection",
  (error) => {
    console.error(
      "Unhandled promise rejection:",
      error
    );
  }
);


process.on(
  "uncaughtException",
  (error) => {
    console.error(
      "Uncaught exception:",
      error
    );
  }
);


startServer();
