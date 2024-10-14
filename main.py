import asyncio
import json
import logging
import os
import aioredis
from typing import Optional

import jwt
import uvicorn
import websockets
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from starlette import status

from base_data import get_user, get_pair, add_alarm_for_price, init_db, User, get_alarm_prices

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger()


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
    return new_alarm


# WebSocket URL для отслеживания цен на несколько пар
socket_btc = "wss://stream.binance.com:9443/stream?streams=btcusdt@trade"
socket_eth = "wss://stream.binance.com:9443/stream?streams=ethusdt@trade"


async def binance_ws(socket):
    async with websockets.connect(socket) as websocket:
        while True:
            data = await websocket.recv()
            log.warning(json.loads(data))
            await asyncio.sleep(2)


async def cache_alarm_prices():
    alarm_prices = await get_alarm_prices()


async def check_prices(data: dict):
    pair_info = data["data"]
    pair_name = pair_info["s"]
    pair_price = pair_info["p"]


# Запуск приложения
if __name__ == "__main__":
    uvicorn.run("main:main_app")
