# Расширение веб-браузера для обнаружения фишинговых сайтов

Chrome/Chromium Extension + Flask backend + внутренняя база вердиктов на 100 000 записей + URL feature extraction + ML + текстурный анализ URL + эвристическая оценка + DNS-проверка.

## Состав версии 4.0

- База URL в `backend/data/dataset.csv` содержит 100 000 записей.
- Внутренняя репутационная база `backend/data/verdicts.json` содержит 100 000 доменных записей.
- Добавлена DNS-проверка существования домена с коротким timeout и кэшем.
- Используется гибридная логика: ML probability + прозрачный heuristic score + DNS-сигнал.
- Количество признаков URL увеличено до 67, включая 21 признак URL-текстур: token rhythm, character-class transitions, digit-letter transitions, typo-squatting брендов, base64-like/random tokens и плотность login/auth/verify/payment-маркеров.
- Модель использует `TexturedUrlClassifier`: RandomForest по инженерным признакам + character n-gram TF-IDF + LogisticRegression по текстуре строки URL.
- В popup расширения есть ручной ввод URL: можно открыть popup, вставить ссылку и сразу выполнить проверку.
- Интерфейс показывает визуальный паттерн результата, источник решения, риск, DNS-статус, вероятность фишинга и причины.
- Добавлен CI workflow `.github/workflows/ci.yml` и единый скрипт `scripts/check_project.py`.
- Автотесты покрывают API, feature extraction, URL-texture, DNS, repository, risk engine, model service и training frame.

## Структура

```text
backend/                   Flask API и ML-логика
  app.py                   REST API: /health, /api/check, /predict, /api/verdicts
  config.py                настройки путей, CORS, DNS, debug и demo-режима
  data_generator.py        воспроизводимая генерация dataset/verdict base
  dns_checker.py           DNS-проверка домена с timeout и cache
  feature_extractor.py     нормализация URL и расширенный набор признаков
  url_texture.py           текстурные признаки URL: токены, n-граммные маркеры, typo-squatting
  textured_model.py        гибридная ML-модель: RandomForest + TF-IDF n-grams
  risk_engine.py           гибридная оценка риска
  model_service.py         загрузка модели и fallback-эвристика
  model_train.py           обучение TexturedUrlClassifier и сохранение метрик
  data/dataset.csv         датасет URL
  data/verdicts.json       внутренняя база вердиктов
  tests/                   pytest-тесты
extension/                 расширение Manifest V3
scripts/check_project.py   единая локальная проверка проекта
  release_audit.py          проверка технической готовности
.github/workflows/ci.yml   CI: compileall + pytest + node --check
```

## Проверка готовности проекта

В проект добавлен `scripts/release_audit.py`. Он автоматически проверяет размер dataset, размер verdict base, DNS по умолчанию, CI, URL-текстуры, ручной ввод URL в расширении, отображение DNS/texture в интерфейсе и расширенный набор тестов.

```bash
python scripts/release_audit.py
```

## Быстрый запуск backend на Windows

В корне проекта запустить:

```bat
start_backend_windows.bat
```

Скрипт создаст `.venv`, установит зависимости и запустит Flask на `http://127.0.0.1:5001`.

## Ручной запуск backend

```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Модель и признаки уже лежат в архиве. При необходимости переобучить модель:

```bash
cd backend
python model_train.py
# по умолчанию используется стратифицированная выборка
# для полного обучения задайте размер всей базы через --max-rows
```

Перегенерировать базу:

```bash
cd backend
python data_generator.py --size 100000
python model_train.py
# для полного обучения задайте размер всей базы через --max-rows
```

## Подключение расширения

1. Запустить backend.
2. Открыть в Chrome/Chromium `chrome://extensions`.
3. Включить Developer mode / «Режим разработчика».
4. Нажать Load unpacked / «Загрузить распакованное расширение».
5. Выбрать папку `extension`.
6. Открыть сайт или вставить URL вручную в popup расширения.
7. Нажать «Проверить вкладку» или «Проверить введённый URL».

## Проверка API

```bash
curl -X POST http://127.0.0.1:5001/api/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Статистика базы:

```bash
curl http://127.0.0.1:5001/health
curl "http://127.0.0.1:5001/api/verdicts?limit=5"
```

## Автоматическая проверка проекта

Windows:

```bat
check_project_windows.bat
```

Linux/macOS:

```bash
./check_project_linux_mac.sh
```

Вручную:

```bash
cd backend
pytest -q
python -m compileall .
node --check ../extension/popup.js
node --check ../extension/background.js
```

## URL-текстуры

В проект добавлен отдельный слой текстурного анализа URL. Здесь под «текстурами» понимаются текстовые/символьные паттерны адреса, а не скриншоты сайта: character n-граммы, плотность разделителей, чередование букв и цифр, typo-squatting, длинные случайные токены и login/auth/verify/payment-маркеры. Подробно это описано в `docs/URL_TEXTURES.md` и чек-листе запуска `docs/DEMO_CHECKLIST.md`.

## Демонстрационные URL

- `https://example.com` — безопасный домен из внутренней базы.
- `https://secure-login-example.bad/account` — фишинговый домен из внутренней базы.
- `https://paypa1-login-secure.example.bad/account?token=ABCDEF1234567890XYZ` — гибридная проверка выявляет имитацию бренда, typo-texture и чувствительный токен.
- `http://192.168.0.1/secure/login/verify/account` — IP вместо домена + подозрительные слова.
- `javascript:alert(1)` и `https://.` — некорректные адреса, backend возвращает validation error.

## Ограничение датасета

Датасет и репутационная база являются воспроизводимо сгенерированными. Метрики относятся к текущему набору данных; при практическом применении качество разметки, источники обновления и политика обработки URL должны проверяться отдельно.
