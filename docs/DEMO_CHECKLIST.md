# Чек-лист запуска и демонстрации

Цель файла — чтобы проект можно было открыть, запустить и проверить без ручного поиска команд.

## 1. Быстрый запуск

Windows:

```bat
start_backend_windows.bat
```

Linux/macOS:

```bash
./start_backend_linux_mac.sh
```

Backend должен запуститься на `http://127.0.0.1:5001`.

## 2. Проверка готовности проекта

Windows:

```bat
check_project_windows.bat
```

Linux/macOS:

```bash
./check_project_linux_mac.sh
```

Проверяются Python-компиляция, pytest, release-audit, JavaScript syntax-check.

## 3. Загрузка расширения

1. Открыть `chrome://extensions`.
2. Включить режим разработчика.
3. Нажать «Загрузить распакованное расширение».
4. Выбрать папку `extension`.
5. Открыть popup расширения.

## 4. Что проверить вручную

- Проверка текущей вкладки.
- Ручной ввод URL прямо в popup.
- Безопасный пример: `https://example.com`.
- Фишинговый пример из базы: `https://secure-login-example.bad/account`.
- Неизвестный подозрительный пример: `https://paypa1-security-login-check-zzzzzz999.invalidx/account?token=ABCDEF1234567890XYZ`.
- Ошибка валидации: `javascript:alert(1)`.

## 5. Технические элементы проекта

- DNS-проверка есть в `backend/dns_checker.py`; включена по умолчанию, но в CI отключается переменной окружения, чтобы тесты не зависели от сети.
- Датасет: 100 000 URL, баланс 50 000 safe / 50 000 phishing.
- Внутренняя база вердиктов: 100 000 записей.
- CI есть в `.github/workflows/ci.yml`.
- Тесты запускаются одной командой.
- URL-текстуры реализованы в `backend/url_texture.py` и используются в `TexturedUrlClassifier`.
- Логика гибридная: database + ML + heuristic + DNS + texture analysis.
