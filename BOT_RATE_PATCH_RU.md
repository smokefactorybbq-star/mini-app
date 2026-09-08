# Патч для кнопки «Курс» в текущем `bot.py` (aiogram 3)

Mini App уже готов принимать курс через:

- `GET /api/exchange-rate` — получить текущий курс.
- `POST /api/admin/exchange-rate` — сохранить новый курс с HMAC-подписью `TELEGRAM_BOT_TOKEN`.

Курс означает **рублей за 1 бат**. Например `2.71`: заказ `200 ฿` = `542 ₽`.

> В этом архиве исходника действующего `bot.py` нет, поэтому этот файл — точный код интеграции, который нужно добавить в существующий bot-проект, не заменяя его целиком.

## 1. Импорты

Добавьте, если их ещё нет:

```python
import hashlib
import hmac
import time
import uuid
from urllib.parse import urlsplit

import aiohttp
from aiogram import F, types
```

## 2. Адрес Mini App и состояние ввода курса

Рядом с существующими переменными окружения:

```python
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "7309681026"))
WEBAPP_URL = os.getenv("WEBAPP_URL", "").strip()

_parts = urlsplit(WEBAPP_URL)
MINI_APP_API_URL = f"{_parts.scheme}://{_parts.netloc}".rstrip("/")

waiting_for_rate = set()
```

`TELEGRAM_BOT_TOKEN` в текущем bot.py уже должен быть загружен в переменную токена. Ниже в примере используется имя `BOT_TOKEN`. Если у вас переменная называется иначе, подставьте её имя.

## 3. Кнопка только менеджеру

В функции, которая строит ReplyKeyboardMarkup для `/start`, добавьте строку только для `ADMIN_CHAT_ID`:

```python
if int(user_id) == int(ADMIN_CHAT_ID):
    rows.append([
        types.KeyboardButton(text="Курс")
    ])
```

И передавайте ID пользователя в эту функцию из `/start`:

```python
reply_markup=start_keyboard(message.from_user.id)
```

У обычных покупателей кнопки `Курс` быть не должно.

## 4. Сохранение курса на сервере

```python
async def save_rub_rate(rate: float, manager_id: int):
    timestamp = int(time.time())
    request_id = f"rate:{manager_id}:{timestamp}:{uuid.uuid4().hex}"

    canonical = "|".join([
        f"{rate:.4f}",
        str(manager_id),
        str(timestamp),
        request_id,
    ])

    signature = hmac.new(
        BOT_TOKEN.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    payload = {
        "rate": rate,
        "managerId": manager_id,
        "timestamp": timestamp,
        "requestId": request_id,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{MINI_APP_API_URL}/api/admin/exchange-rate",
            json=payload,
            headers={"X-Rate-Signature": signature},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:
            data = await response.json(content_type=None)
            if response.status != 200 or not data.get("ok"):
                raise RuntimeError(data.get("error") or f"HTTP {response.status}")
            return data
```

## 5. Обработчики кнопки «Курс»

Разместите эти обработчики **до общего обработчика произвольного текста**, если он есть:

```python
@dp.message(F.text == "Курс")
async def rate_button(message: types.Message):
    if message.from_user.id != ADMIN_CHAT_ID:
        return

    waiting_for_rate.add(message.from_user.id)
    await message.answer("Какой?")


@dp.message(lambda message: message.from_user and message.from_user.id in waiting_for_rate)
async def rate_value(message: types.Message):
    if message.from_user.id != ADMIN_CHAT_ID:
        return

    text = (message.text or "").strip().replace(",", ".")

    try:
        rate = float(text)
    except ValueError:
        await message.answer("Введите курс числом. Например: 2.71")
        return

    if not (0.1 <= rate <= 100):
        await message.answer("Введите корректный курс. Например: 2.71")
        return

    try:
        await save_rub_rate(rate, message.from_user.id)
    except Exception as exc:
        await message.answer(f"Не удалось сохранить курс: {exc}")
        return

    waiting_for_rate.discard(message.from_user.id)
    await message.answer(f"Курс сохранён: 1 ฿ = {rate:.2f} ₽")
```

После этого Mini App при выборе `Банк РФ` сам запрашивает свежий сохранённый курс, умножает итог заказа в батах на курс и показывает QR + сумму в рублях.
