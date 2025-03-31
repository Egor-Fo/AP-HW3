# 🔗 URL Shortener API

Простой сервис сокращения ссылок на FastAPI с поддержкой регистрации пользователей, аналитики и кэширования.

---

## 🚀 Возможности

- ✅ Генерация короткой ссылки
- 🧾 Получение статистики по ссылке
- 🧼 Удаление и обновление (только для владельца)
- 🔐 Регистрация и аутентификация пользователей (JWT)
- 🧠 Кэширование ссылок в Redis
- 🧭 Поддержка истечения срока жизни ссылок

---

## 🧠 Стек технологий

- `FastAPI` + `SQLAlchemy`
- `PostgreSQL`
- `Redis`
- `Docker`, `docker-compose`
- `passlib`, `python-jose`, `shortuuid`, `qrcode`

---

## 📦 Установка

### 1. Клонируй проект

```bash
git clone https://github.com/yourusername/AP-HW3.git
cd AP-HW3
```

### 2. Запуск через Docker Compose

```bash
docker-compose up --build
```

---

## 🔐 Аутентификация

- Используется OAuth2 с JWT токенами
- Для защищённых эндпоинтов требуется токен `Authorization: Bearer <token>`


## 📨 Примеры запросов

### 🔸 POST /register

```json
{
  "username": "testuser",
  "password": "strongpassword"
}
```

### 🔸 POST /login

```json
{
  "username": "testuser",
  "password": "strongpassword"
}
```

Возвращает JWT токен.

---

### 🔸 POST /links/shorten

```json
{
  "original_url": "https://example.com",
  "custom_alias": "promo2025",
  "expires_at": "2025-04-01T12:00:00"
}
```

✅ Можно вызывать **без авторизации**

---

### 🔸 GET /{short_code}

Переход по короткой ссылке.

---

### 🔸 GET /links/{short_code}/stats

🔐 Требует авторизации и прав владельца.

---

### 🔸 PUT /links/{short_code}

```json
{
  "new_original_url": "https://newsite.com"
}
```

🔐 Требует авторизации и прав владельца.

---

### 🔸 DELETE /links/{short_code}

Удаление ссылки владельцем.

---

### 🔸 GET /links/{short_code}/qrcode

Генерация QR-кода для короткой ссылки.

---

## 🗄️ Структура БД

- `users`: id, username, hashed_password
- `links`: short_code, original_url, created_at, expires_at, clicks, last_accessed_at, owner_id (FK)