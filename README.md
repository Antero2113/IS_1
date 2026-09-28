# Разработка защищенного REST API с интеграцией в CI/CD

Работа №1, «Информационная безопасность»

Цель работы — получить практический опыт разработки безопасного backend-приложения
с автоматизированной проверкой кода на уязвимости и интеграцией инструментов
безопасности в CI/CD.

<br>

## Стек

- **Язык / рантайм:** Node.js ≥ 22.5 
- **Фреймворк:** Express 5
- **БД:** SQLite 
- **Аутентификация:** JWT (`jsonwebtoken`) + bcrypt (`bcryptjs`, cost factor 12)
- **Защита:** `helmet` (HTTP-заголовки), `express-rate-limit` (брутфорс-защита логина)

<br>

## Запуск

```bash
npm install
npm start        # http://localhost:3000
npm run dev      # с автоперезапуском (node --watch)
```

Тестовые учётные записи (пароли хранятся как bcrypt-хэши):

| Логин | Пароль     | Роль  |
|-------|------------|-------|
| admin | `Admin123!` | admin |
| alice | `Alice123!` | user  |

Переменные окружения (`.env`):

| Переменная                  | По умолчанию                    | Назначение                          |
|-----------------------------|---------------------------------|-------------------------------------|
| `PORT`                      | `3000`                          | Порт сервера                        |
| `DB_PATH`                   | `./data/app.db`                 | Путь к файлу SQLite (`:memory:` — в памяти) |
| `JWT_SECRET`                | *dev-значение*                  | Секрет подписи JWT (обязательно задать свой, ≥16 символов) |
| `JWT_EXPIRES_IN`            | `1h`                            | Время жизни токена                  |
| `LOGIN_RATE_LIMIT_WINDOW_MS`| `900000` (15 мин)               | Окно rate-limit для `/auth/login`   |
| `LOGIN_RATE_LIMIT_MAX`      | `5`                             | Максимум попыток входа за окно      |

<br>

## API

| Метод  | Путь            | Доступ    | Описание                                        |
|--------|-----------------|-----------|-------------------------------------------------|
| `POST` | `/auth/login`   | публичный | Аутентификация, выдача JWT                      |
| `GET`  | `/api/data`     | JWT       | Список постов, опционально `?search=` (LIKE-фильтр) |
| `POST` | `/api/posts`    | JWT       | Создание поста (`title`, `content`)             |
| `GET`  | `/health`       | публичный | Проверка доступности                            |

Примеры:

```bash
# 1. Передаём логин, получаем токен
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}'

# 2. Получение данных (защищённый эндпоинт)
curl http://localhost:3000/api/data \
  -H "Authorization: Bearer <TOKEN>"

# 3. Создание поста (защищённый эндпоинт)
curl -X POST http://localhost:3000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"title":"Мой пост","content":"Текст поста"}'
```

<br>

## Реализованные меры защиты (с опорой на OWASP Top 10 2025)

| Категория                          | Реализация                                                                                     |
|------------------------------------|------------------------------------------------------------------------------------------------|
| **A03 — SQL-инъекции**             | Запросы через параметризованные statements (`db.prepare(...).get/all/run`), нет конкатенации пользовательского ввода в SQL. Проверяется тестом `?search=' OR 1=1 --`. |
| **A03 — XSS**                      | Все пользовательские данные перед возвратом в ответе пропускаются через OWASP-экранирование ([`escapeHtml()`](src/security.js:17)); плюс `helmet()` заголовки и `Content-Type: application/json`. |
| **A07 — Broken Authentication**    | Пароли хранятся как **bcrypt-хэши**; JWT выдаётся при успешном входе; middleware [`authenticateToken()`](src/auth.js:26) защищает все `/api/*`; единая ошибка «Invalid credentials» (нет перечисления пользователей); rate-limit на логине против брутфорса. |
| **A01 — Access Control**           | Все защищённые маршруты требуют валидный Bearer-JWT; 401 при отсутствии/порче/истечении токена. |
| **A05 — Misconfiguration**         | `x-powered-by` отключён; лимит JSON-тела 10kb; глобальный обработчик ошибок не отдаёт стектрейсы; секреты — только через env. |
| **A09 — Logging/Monitoring**       | Централизованное логирование ошибок на сервере.                                               |

<br>

## CI/CD — GitHub Actions

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) запускается автоматически при
**каждом push** и **создании pull request** и выполняет:

1. `npm ci` — установка зависимостей по lock-файлу;
2. **SAST** — `npm audit --audit-level=moderate` (для JavaScript — как указано в задании: «npm audit или snyk test»);
3. **SAST (доп.)** — `npx eslint .` со статическим security-плагином `eslint-plugin-security` (анализ исходного кода);
4. **SCA** — **OWASP Dependency-Check** (`dependency-check/Dependency-Check_Action@main`) — сканирует зависимости проекта (package-lock.json / node_modules), сопоставляет их с CVE и генерирует HTML-отчёт;
5. **Отчёт SCA** — загружается как артефакт сборки `dependency-check-report` (вкладка Actions → Artifacts);
6. `npm test` — автоматические security-тесты API (JWT-поток, попытки SQL-инъекций, XSS-экранирование, rate-limit).

Локально можно запустить `npm run lint`, `npm run security:audit`, `npm test`;
полный SCA-скан через OWASP Dependency-Check выполняется в CI.

<br>

### Скриншот отчета SAST

<img width="487" height="267" alt="изображение" src="https://github.com/user-attachments/assets/85031bb9-cdac-4871-af7c-526756f7f666" />

<br>

### Скриншот отчета SCA

<img width="1025" height="727" alt="изображение" src="https://github.com/user-attachments/assets/b55bb178-5f16-455d-8b96-57d9096dd06b" />

<br>

## Структура проекта

```
.
├── .github/workflows/ci.yml   # CI/CD пайплайн с security-сканерами
├── server.js                  # Точка входа (config -> db -> app -> listen)
├── src/
│   ├── config.js              # Конфигурация из переменных окружения
│   ├── db.js                  # SQLite: схема, сиды, параметризованные запросы
│   ├── security.js            # Экранирование (XSS), валидация и санитизация ввода
│   ├── auth.js                # Подпись/проверка JWT, middleware аутентификации
│   ├── app.js                 # Сборка Express-приложения (helmet, роуты, ошибки)
│   └── routes/
│       ├── authRoutes.js      # POST /auth/login (+ rate-limit)
│       └── dataRoutes.js      # GET /api/data, POST /api/posts
└── test/api.test.js           # Интеграционные security-тесты
```
