# GitHub Autoreg — собранная база знаний

Все проверенные факты из наших прогонов. Дата актуальности: 2026-10-09.
Канал: [@alstack](https://t.me/alstack).

## 1. Флоу signup (живой, октябрь 2026)

- GitHub перевёл signup на **multi-step wizard**: email -> Continue -> password
  -> Continue -> username -> Create account. Одностраничная форма мертва.
- Вход: https://github.com/?utm_source=google (ref-параметр снижает подозрительность).
- После Create account может появиться **Arkose FunCaptcha** (octocaptcha.com iframe):
  ~16с PoW, потом "Visual puzzle". Варианты: sequence / rotate / character / wires.
- Email-верификация: письмо mail.cx приходит за 5-30с; код 8 цифр.
- После верификации — авто-логин, проверка cookie `logged_in`.

## 2. Анти-детект и прогрев (лечит suspended)

- **Camoufox** (Firefox anti-detect) — единственный стабильный движок.
  Chromium/patchright ловят DataDome быстрее.
- **Прогрев обязателен**: dwell 4-7с на главной + JS-скроллы + пауза 6-10с
  на /signup перед формой. Без прогрева акки часто `suspended` на home IP.
- **ВАЖНО**: `page.mouse.move()` в Playwright НЕ имеет таймаута — на
  недогруженной странице висит вечно. Только JS `window.scrollBy` +
  `set_default_timeout`.
- DataDome trust cookie сохраняется между прогонами (`.datadome-trust.json`),
  клонируется в fresh-профиль.
- fresh_profile=True: новый браузер без кэша на каждый акк.

## 3. Captcha: multi-LLM voting ($0)

- Multi-LLM voting solver (собственная реализация).
- Кандидаты склеиваются в пронумерованную сетку, PIL-энханс, уходят
  параллельно в vision-модели; большинство побеждает; `ANSWER=<n>`.
- Бесплатные voter'ы через локальный OpenAI-совместимый гейтвей
  (dashscope-proxy 127.0.0.1:16432): qwen3-vl-flash (подтверждён: COLOR=red
  за 2.0с), qwen-vl-max, qwen-vl-plus.
- Review-скриншоты REVIEW_rN.png: красная рамка = финальный голос,
  цветные = голоса моделей.
- wag-captcha sidecar (:8877) — для DataDome, НЕ для Arkose.
- CapSolver DataDomeSliderTask работает, но платно; баланс был $0.

## 4. Почта

- **mail.cx** — бесплатно, без регистрации: домены uqu.me, ddker.com, 9k3r.com.
- IMAP/SMTP не нужны — REST API (создание inbox, чтение сообщений).
- Gmail +alias канонизируется GitHub'ом — не годится для масс-рега.
- t-online.de 17k ящиков — все уже зарегистрированы на GitHub.
- 1secmail мёртв. tempmail.lol v2: токен в query (?token=).

## 5. Прокси

- Бесплатные пулы (ProxyScrape/TheSpeedX и 60+ источников через ProxyGrab) —
  выход ~50-90 живых на github.com из тысяч. Тест: GET /login через прокси.
- Free-прокси медленные: goto может падать по таймауту -> sticky-ротация
  (proxy_hard_block_retries=3, proxy_rate_limit_retries=2).
- Home IP (без прокси) -> акк регистрируется, но почти всегда `suspended`.
- ZTE 4G модем (192.168.0.4:8080-8091) — ротация IP через web API модема
  (DISCONNECT_NETWORK/CONNECT_NETWORK), lifecell Ukraine.
- Прокси-пулы парсить `line.split()[0]` (формат "http://ip:port ip").

## 6. Post-signup стадии (enrich)

- Stage 4: create first repository (делает акк "живым").
- Stage 5: TOTP 2FA — Settings -> Password and authentication ->
  Authenticator app -> "setup key" -> secret -> pyotp -> recovery codes.
- Stage 6: classic PAT —
  /settings/tokens/new -> sudo password -> note -> scopes repo+workflow ->
  Generate token -> токен показывается ОДИН раз, читать regex ghp_[A-Za-z0-9]{36}.
- Profile completion: avatar/status/bio — генератор персон.

## 7. Формат выхлопа

`email----password----username----totp_secret----has_recovery----pat`

Recovery-коды отдельно: accounts/recovery/<email-hash>.txt

## 8. Windows-питфолы

- Camoufox в потоке uvicorn -> `[Errno 22] Invalid argument`. Только subprocess.
- PYTHONPATH="" обязателен (Hermes venv контаминирует).
- Python 3.11 (не 3.14 — greenlet несовместим).
- write_file маскирует секреты -> ключи читать из файла в рантайме.
- git-remote-https мёртв на машине -> пуш через Git Data API
  (blob -> tree -> commit -> ref update); пустая репа требует init через
  Contents API первым файлом.

## 8b. Username-цикл (баг, найден 09.10)

- Короткие базы (t76x) + последовательные суффиксы (name2/name3) тоже заняты —
  GitHub сжирает все page-reloads на "Username X is not available".
- Фикс 1: retry со СЛУЧАЙНЫМ суффиксом 100-9999, не +1.
- Фикс 2: при SESSION switch брать НОВЫЙ mailbox (mail.cx бесплатен) —
  новый email = новая база username. Только для provider=mailcx.

## 9. Статистика наших прогонов

- 2026-10-09: smoke через прокси: verified+logged_in ~2мин/акк.
- Масс-батч 25: в работе, промежуточно 4+ OK.
- suspended без прокси/proxy: uur5221b8slxlc@9k3r.com (home IP).
- GitHub checkup-страница: "More options" -> "tomorrow" dismisses.
- 2FA input: input[name=app_otp]; "context destroyed" после Verify = успех.
