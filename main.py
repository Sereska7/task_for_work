import asyncio
import json
import logging
import os
from decimal import Decimal
from typing import Optional
import jwt
import uvicorn
import websockets
import redis.asyncio as aioredis
from black import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from pydantic.v1.datetime_parse import date_re
from sqlalchemy.util import await_only
from starlette import status

from base_data import get_user, get_pair, add_alarm_for_price, init_db, User, get_alarm_prices, add_user, remove_alarm

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger()


class CreateUser(BaseModel):
    email: EmailStr
    password: str


# Pydantic модель для логина пользователя
class SUserLog(BaseModel):
    email: EmailStr
    password: str


# Pydantic модель для установки уведомления
class SetAlertRequest(BaseModel):
    pair: str
    price: float


# Функция для инициализации приложения и запуска фоновой задачи
async def lifespan(app: FastAPI):
    # start
    load_dotenv(dotenv_path=".env.example")
    await init_db()  # Инициализируем базу данных при запуске приложения
    logging.basicConfig(level=logging.WARNING)  # Настройка логирования
    asyncio.create_task(binance_ws(socket_btc))
    asyncio.create_task(binance_ws(socket_eth))
    yield
    # stop

# Инициализация FastAPI приложения с использованием lifespan
main_app = FastAPI(lifespan=lifespan)


async def get_redis():
    # Подключаемся к Redis
    redis = await aioredis.from_url("redis://localhost:6379", encoding="utf-8", decode_responses=True)
    return redis


# Функция для получения хеша пароля
def get_password_hash(password: str):
    return pwd_context.hash(password)


# Функция для проверки пароля пользователя
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


# Аутентификация пользователя по email и паролю
async def authenticate_user(data_user: SUserLog):
    user = await get_user(email=data_user.email)

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if not verify_password(data_user.password, user.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return user  # Возвращаем аутентифицированного пользователя


# Создание JWT токена для пользователя
async def create_access_token(data: dict):
    to_encode = data.copy()
    encode_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), os.getenv("ALGORITHM"))
    return encode_jwt


# Получение токена из запроса
async def get_token_from_request(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No authentication token provided")
    return token


# Получение текущего пользователя на основе токена
async def get_current_user(token: Optional[str] = Depends(get_token_from_request)):
    payload = jwt.decode(token, os.getenv("SECRET_KEY"), os.getenv("ALGORITHM"))
    user_id = payload.get("sub")
    user = await get_user(id=int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


# Эндпоинт для регистрации пользователя
@main_app.post("/register_user")
async def register_user(data_user: CreateUser):
    hash_password = get_password_hash(data_user.password)
    new_user = await add_user(
        data_user.email,
        password=hash_password,
        date_reg=datetime.now()
    )
    return new_user


# Эндпоинт для логина пользователя (авторизация и выдача токена)
@main_app.post("/login")
async def login_user(user_data: SUserLog, response: Response):
    user = await authenticate_user(user_data)

    access_token = await create_access_token({"sub": str(user.id)})  # Создание токена
    response.set_cookie("access_token", access_token, httponly=True)  # Сохранение токена в куки
    return access_token


# Эндпоинт для установки уведомлений пользователем
@main_app.put("/set_alert")
async def create_alert(
        data: SetAlertRequest, current_user: User = Depends(get_current_user)
):
    pair = await get_pair(data.pair)
    new_alarm = await add_alarm_for_price(
        pair.id, current_user.id, data.price
    )
    alert_prices = await get_alarm_prices()
    redis_key = "alarm_price_list"
    redis = await get_redis()
    await redis.delete(redis_key)
    alert_prices = [
        {key: float(value) if isinstance(value, Decimal) else value for key, value in row.items()}
        for row in alert_prices
    ]
    result = await redis.set(redis_key, json.dumps(alert_prices))
    log.info(f"Успешно {result}")
    await redis.close()
    return new_alarm


# Эндпоинт для получения всех 'колокольчиков'
@main_app.get("/get_alarm")
async def get_alarms(current_user: User = Depends(get_current_user)):
    return await get_alarm_prices()


# Эндпоинт для удаления 'колокольчика'
@main_app.delete("/delete_alarm")
async def delete_alarm(alarm_id: int, current_user: User = Depends(get_current_user)):
    await remove_alarm(alarm_id)
    return HTTPException(status_code=status.HTTP_200_OK)


# WebSocket URL для отслеживания цен на несколько пар
socket_btc = "wss://stream.binance.com:9443/stream?streams=btcusdt@trade"
socket_eth = "wss://stream.binance.com:9443/stream?streams=ethusdt@trade"


# Асинхронная функция для подключения к WebSocket и обработки данных
async def binance_ws(socket):
    async with websockets.connect(socket) as websocket:
        while True:
            data = await websocket.recv()
            log.warning(json.loads(data))
            await asyncio.sleep(5)
            await check_prices(json.loads(data))


# Асинхронная функция для кэширования всех уведомлений в Redis
async def cache_alarm_prices():
    # Получаем все уведомления из базы данных
    alarm_prices = await get_alarm_prices()

    # Ключ для хранения данных в Redis
    redis_key = "alarm_price_list"

    # Получаем соединение с Redis
    redis = await get_redis()

    # Сохраняем уведомления в Redis в формате JSON
    await redis.set(redis_key, json.dumps(alarm_prices))

    # Закрываем соединение с Redis
    await redis.close()


# Асинхронная функция для получения уведомлений из кеша Redis
async def get_cache_alarm_prices():
    # Получаем соединение с Redis
    redis = await get_redis()

    # Получаем данные по ключу "alarm_price_list"
    cached_data = await redis.get("alarm_price_list")

    if cached_data:
        # Если данные найдены, десериализуем их
        alarm_prices = json.loads(cached_data)

        # Закрываем соединение с Redis
        await redis.close()

        # Возвращаем данные
        return alarm_prices


# Асинхронная функция для проверки цен и отправки уведомлений
async def check_prices(data: dict):
    pair_info = data["data"]  # Достаём данные валютной пары
    pair_name = pair_info["s"]  # Название валютной пары
    pair_data = await get_pair(pair_name)  # Получаем данные валютной пары из базы данных
    pair_price = pair_info["p"]  # Текущая цена валютной пары

    # Получаем все уведомления из кеша Redis
    alarm_prices = await get_cache_alarm_prices()

    for alarm_price in alarm_prices:
        # Проверяем, совпадает ли уведомление с текущей валютной парой
        if alarm_price["pair_id"] == pair_data.id:
            # Логируем текущую цену и цену уведомления
            log.info(f"alarm_price: {float(alarm_price['price'])} new_price: {pair_price}")
            log.info(f"Проверка совпадение user_id прошла")

            # Если цена уведомления меньше или равна текущей цене
            if float(alarm_price["price"]) <= float(pair_price):
                # Получаем пользователя, которому нужно отправить уведомление
                user = await get_user(id=alarm_price["user_id"])

                # Логируем отправку уведомления
                log.warning(f"Отправка сообщения {user.email} "
                            f"Цена валюты: {pair_name} меньше или равна {alarm_price['price']}")
        else:
            # Продолжаем проверку следующих уведомлений
            continue


# Запуск приложения
if __name__ == "__main__":
    uvicorn.run("main:main_app")
