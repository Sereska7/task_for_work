# FastAPI Проект с использованием PostgreSQL, Redis и WebSockets

## Описание

Этот проект представляет собой веб-приложение на FastAPI, которое использует PostgreSQL для хранения данных, Redis для кэширования и WebSockets для получения данных о криптовалютных ценах в режиме реального времени. В проекте реализована аутентификация пользователей через JWT, возможность установки уведомлений на изменение цен и обработка данных через WebSockets.

## Требования

Для работы проекта вам понадобятся:

- **Docker** и **Docker Compose** (для запуска PostgreSQL и Redis в контейнерах)
- **Python 3.11+**
- **FastAPI** и другие зависимости проекта

## Установка

1. Клонируйте репозиторий:

    ```bash
    git clone https://github.com/ваш-репозиторий.git
    cd ваш-репозиторий
    ```

2. Создайте виртуальное окружение и активируйте его:

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Для Windows: .venv\Scripts\activate
    ```

3. Установите зависимости:

    ```bash
    pip install -r requirements.txt
    ```

## Настройка переменных окружения

1. Создайте файл `.env` на основе примера `.env.example` и укажите необходимые значения переменных:

    ```bash
    cp .env.example .env
    ```

2. Пример содержимого файла `.env`:

    ```env
    SECRET_KEY=your_secret_key
    ALGORITHM=HS256
    DB_URL=postgresql://postgres:password@localhost:5432/task_db
    REDIS_URL=redis://localhost:6379
    ```

## Запуск базы данных PostgreSQL и Redis в Docker

Для работы приложения необходимо запустить базы данных PostgreSQL и Redis в Docker.

1. **Запуск PostgreSQL**:

    ```bash
    docker run --name postgres-db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=task_db -d -p 5432:5432 -v postgres-data:/var/lib/postgresql/data postgres
    ```

2. **Запуск Redis**:

    ```bash
    docker run --name redis-server -d -p 6379:6379 redis
    ```

3. Убедитесь, что контейнеры запущены:

    ```bash
    docker ps
    ```

## Инициализация базы данных

После того как контейнер PostgreSQL запущен, инициализируйте базу данных:

1. Выполните скрипт для создания таблиц:

    ```bash
    python init_db.py
    ```

## Запуск приложения

```bash
uvicorn main:main_app --reload
```