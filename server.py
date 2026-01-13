"""
API Test Generator - Flask Backend Server
Локальный сервер для генерации автотестов API
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import re
from urllib.parse import urlparse
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)  # Разрешаем CORS для всех источников
load_dotenv()  # Загружаем переменные окружения из .env

# Константы безопасности
MAX_DOC_SIZE = 500 * 1024  # Максимальный размер документации: 500KB
MAX_DOC_LENGTH = 300000  # Максимальная длина текста: ~300K символов


def validate_url(url):
    """Валидация URL - проверка формата и безопасности"""
    if not url or not isinstance(url, str):
        return False, "URL должен быть строкой"

    # Проверка формата URL
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False, "URL должен использовать протокол http или https"
        if not parsed.netloc:
            return False, "URL должен содержать домен"
    except Exception as e:
        return False, f"Некорректный формат URL: {str(e)}"

    # Блокировка локальных адресов и внутренних сетей (защита от SSRF)
    blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",  # AWS metadata
        "metadata.google.internal",  # GCP metadata
    ]

    host = parsed.netloc.split(":")[0].lower()
    if (
        host in blocked_hosts
        or host.startswith("192.168.")
        or host.startswith("10.")
        or host.startswith("172.16.")
    ):
        return False, "Доступ к локальным адресам запрещён"

    return True, None


def sanitize_content(content):
    """Санитизация контента - защита от промпт-инъекций"""
    if not content or not isinstance(content, str):
        return content

    # Удаление подозрительных паттернов промпт-инъекций
    # Паттерны, которые могут использоваться для манипуляции промптом
    suspicious_patterns = [
        r"ignore\s+(previous|above|all)\s+instructions?",
        r"forget\s+(previous|above|all)\s+instructions?",
        r"disregard\s+(previous|above|all)\s+instructions?",
        r"system\s*:\s*",
        r"user\s*:\s*",
        r"assistant\s*:\s*",
        r"you\s+are\s+now",
        r"new\s+instructions?",
        r"override",
        r"bypass",
        r"execute\s+(command|code)",
        r"<\|.*?\|>",  # Специальные токены
    ]

    sanitized = content
    for pattern in suspicious_patterns:
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

    return sanitized


def is_likely_api_documentation(content, content_type=""):
    """Проверка, что контент похож на документацию API - проверка структуры файла"""
    if not content or len(content) < 50:
        return False

    content_stripped = content.strip()

    # Проверка на JSON структуру OpenAPI/Swagger
    if content_stripped.startswith("{") and "}" in content:
        try:
            import json

            parsed_json = json.loads(content)

            # Проверка обязательных полей OpenAPI 3.x
            if isinstance(parsed_json, dict):
                # OpenAPI 3.x должен иметь поле "openapi" и "paths"
                if "openapi" in parsed_json and "paths" in parsed_json:
                    # Проверяем что openapi - это версия (строка начинающаяся с цифры)
                    openapi_val = str(parsed_json.get("openapi", ""))
                    if openapi_val and (
                        openapi_val.startswith("3.") or openapi_val.startswith("3.0")
                    ):
                        return True

                # Swagger 2.x должен иметь поле "swagger" и "paths"
                if "swagger" in parsed_json and "paths" in parsed_json:
                    swagger_val = str(parsed_json.get("swagger", ""))
                    if swagger_val and swagger_val.startswith("2."):
                        return True

                # Дополнительная проверка: наличие обязательных полей для API спецификации
                required_fields = ["paths"]
                optional_but_indicative = [
                    "info",
                    "servers",
                    "components",
                    "definitions",
                    "host",
                    "basePath",
                ]

                has_required = all(field in parsed_json for field in required_fields)
                has_optional = any(
                    field in parsed_json for field in optional_but_indicative
                )

                # Если есть paths и хотя бы одно из опциональных полей - это похоже на API спецификацию
                if has_required and has_optional:
                    # Проверяем что paths - это объект с эндпоинтами
                    paths = parsed_json.get("paths", {})
                    if isinstance(paths, dict) and len(paths) > 0:
                        # Проверяем что хотя бы один путь содержит методы (get, post, etc)
                        for path_value in paths.values():
                            if isinstance(path_value, dict):
                                http_methods = [
                                    "get",
                                    "post",
                                    "put",
                                    "delete",
                                    "patch",
                                    "head",
                                    "options",
                                ]
                                if any(method in path_value for method in http_methods):
                                    return True
        except (json.JSONDecodeError, ValueError):
            pass

    # Проверка на YAML структуру OpenAPI/Swagger
    if ":" in content:
        # YAML должен содержать обязательные поля на верхнем уровне
        # Проверяем наличие ключевых полей в начале файла (первые 2000 символов)
        yaml_start = content[:2000].lower()

        # OpenAPI 3.x в YAML
        if "openapi:" in yaml_start and "paths:" in yaml_start:
            # Проверяем что после openapi: идет версия 3.x
            openapi_match = re.search(
                r'openapi:\s*["\']?3\.', content[:500], re.IGNORECASE
            )
            if openapi_match:
                return True

        # Swagger 2.x в YAML
        if "swagger:" in yaml_start and "paths:" in yaml_start:
            swagger_match = re.search(
                r'swagger:\s*["\']?2\.', content[:500], re.IGNORECASE
            )
            if swagger_match:
                return True

    # Проверка HTML - только если это явно Swagger UI
    if content_type and "text/html" in content_type.lower():
        # HTML должен содержать специфичные элементы Swagger UI
        # Проверяем наличие swagger-ui специфичных классов/ID
        swagger_ui_indicators = [
            r'<div[^>]*id=["\']swagger-ui["\']',
            r'<div[^>]*class=["\'][^"\']*swagger-ui[^"\']*["\']',
            r"swagger-ui-bundle",
            r"swagger-ui-standalone-preset",
            r'url:\s*["\']https?://[^"\']+\.(json|yaml|yml)["\']',  # URL к JSON/YAML спецификации
        ]

        html_match_count = sum(
            1
            for pattern in swagger_ui_indicators
            if re.search(pattern, content, re.IGNORECASE)
        )

        # Если найдено минимум 2 индикатора Swagger UI - это похоже на документацию
        if html_match_count >= 2:
            return True

        # Если HTML содержит прямой встроенный JSON/YAML спецификации
        if re.search(
            r'<script[^>]*>.*?["\']openapi["\']|["\']swagger["\'].*?</script>',
            content,
            re.IGNORECASE | re.DOTALL,
        ):
            return True

    # Если ничего не подошло - это не документация API
    return False


def validate_doc_content(content):
    """Валидация содержимого документации"""
    if not content:
        return False, "Содержимое документации пусто"

    if not isinstance(content, str):
        return False, "Содержимое должно быть строкой"

    # Проверка размера
    content_size = len(content.encode("utf-8"))
    if content_size > MAX_DOC_SIZE:
        return (
            False,
            f"Размер документации слишком большой ({content_size / 1024:.1f}KB). Максимум: {MAX_DOC_SIZE / 1024:.1f}KB",
        )

    if len(content) > MAX_DOC_LENGTH:
        return (
            False,
            f"Документация слишком длинная ({len(content)} символов). Максимум: {MAX_DOC_LENGTH} символов",
        )

    return True, None


@app.route("/api/generate", methods=["POST"])
def generate_tests():
    """Эндпоинт для генерации тестов через Groq API (Llama 3.x)"""
    try:
        data = request.json or {}
        doc_content = data.get("doc_content")
        doc_url = data.get("doc_url")
        language = data.get("language")
        framework = data.get("framework")
        comment_language = data.get(
            "comment_language", "ru"
        )  # Язык комментариев: 'ru' или 'en'

        # Ключ берём из .env / переменных окружения
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return (
                jsonify(
                    {
                        "error": "GROQ_API_KEY не задан. Добавьте его в .env или переменные окружения."
                    }
                ),
                500,
            )

        # Должен быть либо текст контракта, либо URL
        if not doc_content and not doc_url:
            return (
                jsonify(
                    {
                        "error": "Нужно либо загрузить файл с контрактом, либо указать URL документации (doc_url)."
                    }
                ),
                400,
            )

        # Валидация URL, если он передан
        if doc_url:
            is_valid, error_msg = validate_url(doc_url)
            if not is_valid:
                return jsonify({"error": f"Некорректный URL: {error_msg}"}), 400

        # Валидация размера и содержимого, если doc_content передан напрямую
        if doc_content:
            is_valid, error_msg = validate_doc_content(doc_content)
            if not is_valid:
                return jsonify({"error": error_msg}), 400

            # Проверка, что это похоже на документацию API
            if not is_likely_api_documentation(doc_content):
                return (
                    jsonify(
                        {
                            "error": "Загруженный контент не похож на документацию API. Пожалуйста, загрузите файл OpenAPI/Swagger, JSON, YAML или Markdown с описанием API."
                        }
                    ),
                    400,
                )

            # Санитизация контента от промпт-инъекций
            doc_content = sanitize_content(doc_content)

        # Если doc_content не передан, но есть URL — скачиваем контракт с указанного адреса
        if not doc_content and doc_url:
            try:
                print(f"🌐 Загрузка контракта по URL: {doc_url}")
                doc_response = requests.get(doc_url, timeout=30)
                if doc_response.status_code != 200:
                    return (
                        jsonify(
                            {
                                "error": f"Не удалось загрузить контракт по URL, HTTP {doc_response.status_code}"
                            }
                        ),
                        400,
                    )

                content_type = doc_response.headers.get("Content-Type", "").lower()

                # Проверка размера ответа
                content_size = len(doc_response.content)
                if content_size > MAX_DOC_SIZE:
                    return (
                        jsonify(
                            {
                                "error": f"Размер документации по URL слишком большой ({content_size / 1024:.1f}KB). Максимум: {MAX_DOC_SIZE / 1024:.1f}KB"
                            }
                        ),
                        400,
                    )

                # Если это HTML (часто Swagger UI), пробуем найти настоящий JSON/YAML контракт по типичным путям
                if "html" in content_type:
                    from urllib.parse import urlparse, urlunparse

                    parsed = urlparse(doc_url)
                    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

                    candidate_paths = [
                        "/v3/api-docs",
                        "/swagger.json",
                        "/openapi.json",
                        "/v2/swagger.json",  # например, как у petstore.swagger.io
                    ]

                    for path in candidate_paths:
                        candidate_url = origin + path
                        try:
                            print(
                                f"🌐 Попытка загрузить спецификацию по URL: {candidate_url}"
                            )
                            spec_resp = requests.get(candidate_url, timeout=15)
                            if spec_resp.status_code == 200:
                                candidate_size = len(spec_resp.content)
                                if candidate_size > MAX_DOC_SIZE:
                                    print(
                                        f"⚠️ Спецификация по {candidate_url} слишком большая, пропускаем"
                                    )
                                    continue

                                doc_content = spec_resp.text
                                print(
                                    "✅ Контракт успешно загружен из Swagger JSON/YAML"
                                )
                                break
                        except requests.exceptions.RequestException as inner_e:
                            print(
                                f"⚠️ Не удалось загрузить спецификацию по {candidate_url}: {inner_e}"
                            )

                    # Если ни один из кандидатов не сработал — проверяем HTML
                    if not doc_content:
                        # Проверяем, что HTML похож на документацию API
                        if not is_likely_api_documentation(
                            doc_response.text, content_type
                        ):
                            return (
                                jsonify(
                                    {
                                        "error": "URL не ведёт на документацию API. Пожалуйста, укажите ссылку на OpenAPI/Swagger спецификацию или страницу с документацией API."
                                    }
                                ),
                                400,
                            )
                        print(
                            "ℹ️ Не удалось найти JSON/YAML спецификацию, передаём HTML как есть"
                        )
                        doc_content = doc_response.text
                else:
                    # Пытаемся декодировать как текст (JSON/YAML/Markdown и т.п.)
                    doc_content = doc_response.text

                    # Проверка, что это похоже на документацию API
                    if not is_likely_api_documentation(doc_content, content_type):
                        return (
                            jsonify(
                                {
                                    "error": "URL не ведёт на документацию API. Пожалуйста, укажите ссылку на OpenAPI/Swagger спецификацию (JSON/YAML) или страницу с документацией API."
                                }
                            ),
                            400,
                        )

                # Санитизация скачанного контента от промпт-инъекций
                doc_content = sanitize_content(doc_content)

            except requests.exceptions.RequestException as e:
                print(f"🌐 Ошибка загрузки контракта по URL: {str(e)}")
                return (
                    jsonify(
                        {"error": f"Ошибка при загрузке контракта по URL: {str(e)}"}
                    ),
                    400,
                )

        if not all([doc_content, language, framework]):
            return jsonify({"error": "Отсутствуют обязательные параметры"}), 400

        # Финальная валидация размера после всех обработок
        is_valid, error_msg = validate_doc_content(doc_content)
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        # Определение формата документации (грубая эвристика)
        doc_lower = (doc_content or "").lower()
        if "openapi" in doc_lower or "swagger" in doc_lower:
            doc_format = "OpenAPI / Swagger"
        elif doc_content and doc_content.lstrip().startswith("{"):
            doc_format = "JSON"
        elif "paths:" in doc_lower and "components:" in doc_lower:
            doc_format = "OpenAPI (YAML)"
        elif doc_content and doc_content.lstrip().startswith("#"):
            doc_format = "Markdown"
        else:
            doc_format = "Текстовая документация"

        # Генерация промпта (на английском, но с учётом русскоязычной документации)
        prompt = f"""
You are an expert in API test automation.

Carefully read the API contract documentation and generate automated tests, STRICTLY based ONLY on the information from the contract.
DO NOT invent fields, endpoints, parameters or responses if they are not explicitly described.

DOCUMENTATION FORMAT:
{doc_format}  # e.g. OpenAPI 3.0 / Swagger / Markdown / JSON

ORIGINAL DOCUMENTATION URL (if provided by the user):
{doc_url or "N/A"}

API DOCUMENTATION:
{doc_content}

REQUIREMENTS:
- Programming language: {language}
- Test framework: {framework}
- Find the base URL and all endpoints from the documentation using the following rules:
  - For OpenAPI/Swagger (JSON or YAML):
    - If 'servers[0].url' is present:
      - If it is an absolute URL (starts with http:// or https://), use it as base_url
      - If it is a relative URL (starts with /), then:
        - If ORIGINAL DOCUMENTATION URL is available, take its scheme + host and prepend to servers[0].url
        - Otherwise, define a configurable BASE_URL constant and concatenate with this relative path
    - Otherwise, if there is a top-level 'host' + 'basePath', combine them into base_url
    - If neither is present, but example URLs are shown in descriptions, extract the common prefix as base_url
  - For plain JSON/Markdown/text specifications:
    - Look for sections or headings mentioning 'Base URL', 'Server URL', 'API URL', 'Host' or similar (in English or Russian)
    - If example requests (like curl or HTTP snippets) are shown, extract the scheme + host + common path prefix as base_url
  - If a clear base URL cannot be reliably determined, define a configurable BASE_URL constant and leave a TODO with a short comment that it must be filled manually
- Generate tests for ALL endpoints described in the documentation
- For each endpoint, include:
  - positive scenarios
  - negative scenarios (invalid parameters, wrong data, missing required fields)
- Validate:
  - HTTP status codes
  - response body structure
  - data types and required fields
- Use fixtures / setup for configuration (base_url, headers, auth)
- The code must be ready to run without manual changes
- Add comments in the code IN {comment_language.upper()} language ({"Russian" if comment_language == "ru" else "English"})

CONSTRAINTS:
- Use ONLY the data from the documentation
- If some information (including base_url) is missing or ambiguous, skip the test or add a TODO comment
- DO NOT add any explanations outside of the code

OUTPUT:
Return ONLY the raw source code of the automated tests.
"""

        # Запрос к Groq API (OpenAI-совместимый чат /v1/chat/completions)
        print("📤 Отправка запроса к Groq API...")
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            json={
                # Подходящая универсальная модель Groq (можно заменить при желании)
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 4000,
            },
            timeout=60,
        )

        if response.status_code != 200:
            try:
                err_json = response.json()
                # Groq использует openai-совместимый формат ошибок
                error_obj = err_json.get("error") or {}
                error_msg = (
                    error_obj.get("message")
                    or error_obj.get("code")
                    or f"HTTP {response.status_code}"
                )
            except Exception:
                error_msg = f"HTTP {response.status_code}"

            print(f"❌ Ошибка API: {error_msg}")
            return jsonify({"error": error_msg}), response.status_code

        result = response.json()
        # Формат ответа Groq совместим с OpenAI: choices[0].message.content
        tests = result["choices"][0]["message"]["content"]

        # Очистка от markdown форматирования
        clean_tests = (
            tests.replace("```python", "")
            .replace("```javascript", "")
            .replace("```java", "")
            .replace("```csharp", "")
            .replace("```go", "")
            .replace("```", "")
            .strip()
        )

        print(f"✅ Тесты успешно сгенерированы ({len(clean_tests)} символов)")
        return jsonify({"tests": clean_tests})

    except requests.exceptions.Timeout:
        print("⏱️ Таймаут запроса")
        return jsonify({"error": "Таймаут запроса к Groq API"}), 504
    except requests.exceptions.RequestException as e:
        print(f"🌐 Ошибка сети: {str(e)}")
        return jsonify({"error": f"Ошибка сети: {str(e)}"}), 500
    except Exception as e:
        print(f"💥 Неожиданная ошибка: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health_check():
    """Проверка работоспособности сервера"""
    return jsonify({"status": "ok", "message": "Server is running"}), 200


@app.route("/", methods=["GET"])
def index():
    """Главная страница"""
    return jsonify(
        {
            "message": "API Test Generator Server",
            "endpoints": {"generate": "POST /api/generate", "health": "GET /health"},
            "usage": "Используйте React интерфейс в Claude.ai для работы с сервером",
        }
    ), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))

    print("=" * 60)
    print("🚀 API Test Generator Server (LOCAL MODE)")
    print("=" * 60)
    print(f"📍 Backend API: http://localhost:{port}/api/generate")
    print(f"🌐 Health Check: http://localhost:{port}/health")
    print("=" * 60)

    app.run(host="0.0.0.0", port=port)
