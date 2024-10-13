import asyncio

import requests
import websockets
import json
from datetime import datetime
from typing import Optional

import jwt
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Integer,
    String,
    DateTime,
    select,
    Boolean
)
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, declarative_base

DB_URL = "postgresql+asyncpg://postgres:wer255678@localhost:5432/task_db"
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


engine = create_async_engine(DB_URL)
session_factory = async_sessionmaker(engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password: Mapped[str] = mapped_column(String)
    get_BTC_USD: Mapped[bool] = mapped_column(Boolean, default=False)
    get_ETH_USD: Mapped[bool] = mapped_column(Boolean, default=False)
    get_USDTERC_USD: Mapped[bool] = mapped_column(Boolean, default=False)
    get_USDTTRC_USD: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=True, index=True)


async def init_db():
    async with engine.begin() as conn:
        # Асинхронный вызов создания всех таблиц
        await conn.run_sync(Base.metadata.create_all)


async def get_user(**data: str | int):
    async with session_factory() as session:
        request = select(User).filter_by(**data)
        user = await session.execute(request)
        return user.scalar_one_or_none()


async def get_users(**data: str | int | bool):
    async with session_factory() as session:
        request = select(User).filter_by(**data)
        users = await session.execute(request)
        return users.scalars().all()


async def lifespan(app: FastAPI):
    # start
    await init_db()
    asyncio.create_task(binance_ws())
    yield
    # stop


main_app = FastAPI(lifespan=lifespan)


async def create_access_token(data: dict):
    to_encode = data.copy()
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)
    return encode_jwt


async def get_token_from_request(request: Request):
    token = request.cookies.get("access_token")
    return token


async def get_current_user(token: Optional[str] = Depends(get_token_from_request)):
    if not token:
        return HTTPException(status_code=401, detail="No authentication token provided")

    payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
    user_id = payload.get("sub")
    user = await get_user(id=int(user_id))
    return user


class SUserLog(BaseModel):
    email: EmailStr
    password: str


@main_app.post("/login")
async def login_user(user_data: SUserLog, response: Response):
    user = await get_user(email=user_data.email)
    if not user:
        raise HTTPException(status_code=404)

    if user.password != user_data.password:
        raise HTTPException(status_code=500)

    access_token = await create_access_token({"sub": str(user.id)})
    response.set_cookie("access_token", access_token, httponly=True)
    return access_token


class SetAlertRequest(BaseModel):
    pair: str
    enable: bool


@main_app.post("/set_alert")
async def create_alert(
    request: SetAlertRequest, current_user: User = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    async with session_factory() as session:
        async with session.begin():
            if request.pair == "BTC-USD":
                current_user.get_BTC_USD = request.enable
            elif request.pair == "ETH_USD":
                current_user.get_ETH_USD = request.enable
            elif request.pair == "USDTERC-USD":
                current_user.get_USDTERC_USD = request.enable
            elif request.pair == "USDTTRC-USD":
                current_user.get_USDTTRC_USD = request.enable
            else:
                raise HTTPException(status_code=400, detail="Invalid currency pair")
            session.add(current_user)
        await session.commit()
    return {
        "message": f"Alert for {request.pair} {'enabled' if request.enable else 'disabled'} successfully"
    }


# Эндпоинт для получения вебхуков о ценах
@main_app.post("/webhook/price_update")
async def price_update(request: Request):
    payload = await request.json()

    currency_pair = payload.get("currency_pair")
    new_price = payload.get("new_price")

    if not currency_pair or new_price is None:
        return {"status": "error", "message": "Некорректные данные"}

    print(f"Получен вебхук: пара {currency_pair}, новая цена: {new_price}")

    # Логика для уведомления пользователей или записи в базу данных
    return {"status": "success", "message": f"Цена {currency_pair} обновлена"}


webhook_url = "http://localhost:8000/webhook/price_update"
socket = "wss://stream.binance.com:9443/stream?streams=btcusdt@trade/ethusdt@trade/usdtercusdt@trade/usdttrcusdt@trade"

previous_prices = {
        "BTCUSDT": None,
        "ETHUSDT": None,
        "USDTERCUSDT": None,
        "USDTTRCUSDT": None,
    }


# Функция для отправки вебхука на сервер
def send_webhook(currency_pair: str, new_price: float):
    data = {
        "currency_pair": currency_pair,
        "new_price": new_price
    }
    response = requests.post(webhook_url, json=data)
    if response.status_code == 200:
        print(f"Вебхук для {currency_pair} успешно отправлен.")
    else:
        print(f"Ошибка при отправке вебхука: {response.status_code}")


# Функция для отправки уведомления пользователям (например, через e-mail или Telegram)
async def notify_user(user_email: str, currency_pair: str, old_price: float, new_price: float):
    message = (f"Уведомление пользователю: {user_email}\n"
               f"Цена для {currency_pair} изменилась с {old_price} на {new_price}")
    print(message)


async def binance_ws():
    while True:
        try:
            async with websockets.connect(socket) as websocket:
                data = await websocket.recv()
                stream_data = json.loads(data)
                if 'data' in stream_data:
                    stream = stream_data['data']

                    # Получаем название валютной пары (BTCUSDT, ETHUSDT и т.д.)
                    trading_pair = stream.get('s')  # Валютная пара
                    new_price = stream.get('p')  # Новая цена

                    if trading_pair and new_price:
                        new_price = float(new_price)  # Преобразуем строку в число
                        previous_price = previous_prices.get(trading_pair)

                        if previous_price is None:
                            previous_prices[trading_pair] = new_price
                        else:
                            if new_price != previous_price:
                                print(f"Цена {trading_pair} изменилась с {previous_price} на {new_price}")
                                # send_webhook(trading_pair, new_price)

                                users = await get_users()
                                for user in users:
                                    if trading_pair == "BTCUSDT" and user.get_BTC_USD:
                                        await notify_user(user.email, trading_pair, previous_price, new_price)
                                    if trading_pair == "ETHUSDT" and user.get_ETH_USD:
                                        await notify_user(user.email, trading_pair, previous_price, new_price)
                                    if trading_pair == "USDTERCUSDT" and user.get_USDTERC_USD:
                                        await notify_user(user.email, trading_pair, previous_price, new_price)
                                    if trading_pair == "USDTTRCUSDT" and user.get_USDTTRC_USD:
                                        await notify_user(user.email, trading_pair, previous_price, new_price)
                                # Обновляем предыдущую цену
                                previous_prices[trading_pair] = new_price
        except websockets.ConnectionClosed:
            # Обработка ошибок соединения и переподключение
            print("Соединение потеряно, пытаемся переподключиться...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    uvicorn.run("main:main_app")
