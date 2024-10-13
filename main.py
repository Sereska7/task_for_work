import asyncio
import logging

import websockets
import json
from datetime import datetime, timezone
from typing import Optional, Dict

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
from passlib.context import CryptContext
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

log = logging.getLogger()


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


class SUserLog(BaseModel):
    email: EmailStr
    password: str


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        # Асинхронный вызов создания всех таблиц
        await conn.run_sync(Base.metadata.create_all)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(data_user: SUserLog):
    user = await get_user(email=data_user.email)
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    else:
        if not verify_password(data_user.password, user.password):
            raise HTTPException(status_code=400)
    return user


async def add_user():
    data = [
        {"email": "user_1@example.com", "password": "password", "created_at": datetime.now()},
        {"email": "user_2@example.com", "password": "password", "created_at": datetime.now()}
    ]
    async with session_factory() as session:
        for person in data:
            user = User(
                email=person["email"],
                password=get_password_hash(person["password"]),
                created_at=person["created_at"]
            )
            session.add(user)
            await session.commit()
            return user


async def get_user(**data: str | int):
    async with session_factory() as session:
        request = select(User).filter_by(**data)
        user = await session.execute(request)
        return user.scalar_one_or_none()


async def get_users_for_pair(trading_pair: str):
    async with session_factory() as session:
        query = None
        # Определяем запрос в зависимости от валютной пары
        if trading_pair == "BTCUSDT":
            query = select(User).where(User.get_BTC_USD == True)
        elif trading_pair == "ETHUSDT":
            query = select(User).where(User.get_ETH_USD == True)
        elif trading_pair == "USDTERCUSDT":
            query = select(User).where(User.get_USDTERC_USD == True)
        elif trading_pair == "USDTTRCUSDT":
            query = select(User).where(User.get_USDTTRC_USD == True)

        if query is not None:
            result = await session.execute(query)
            users = result.scalars().all()  # Получаем список пользователей
            return users
        return []


async def lifespan(app: FastAPI):
    # start
    await init_db()
    await add_user()
    logging.basicConfig(level=logging.WARNING)
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


@main_app.post("/login")
async def login_user(user_data: SUserLog, response: Response):
    user = await authenticate_user(user_data)

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


# WebSocket URL для отслеживания цен на несколько пар
socket = "wss://stream.binance.com:9443/stream?streams=btcusdt@trade/ethusdt@trade/usdtercusdt@trade/usdtusdt@trade"

# Предыдущие цены для сравнения
previous_prices: Dict[str, float] = {
    "BTCUSDT": None,
    "ETHUSDT": None,
    "USDTERCUSDT": None,
    "USDTUSDT": None,
}


async def binance_ws():
    async with websockets.connect(socket) as websocket:
        while True:
            data = await websocket.recv()
            log.warning(data)
            stream_data = json.loads(data)
            log.warning(f"stream_data: {stream_data}")

            if 'data' in stream_data:
                streams = stream_data['data']

                # Для каждого потока проверяем цену и оповещаем при изменении
                trading_pair = streams.get('s')  # Валютная пара (например, BTCUSDT)
                new_price = float(streams.get('p'))  # Новая цена
                log.info(f"Валютная пара: {trading_pair} Новая цена: {new_price}")

                previous_price = previous_prices.get(trading_pair)
                if previous_price is None:
                    previous_prices[trading_pair] = new_price
                else:
                    if new_price != previous_price:
                        log.info(f"Цена {trading_pair} изменилась с {previous_price} на {new_price}")
                        await notify_user(trading_pair, previous_price, new_price)
                        previous_prices[trading_pair] = new_price


async def notify_user(trading_pair: str, old_price: float, new_price: float):
    users = await get_users_for_pair(trading_pair)
    for user in users:
        message = (f"Уведомление пользователю: {user.email}\n"
                   f"Цена для {trading_pair} изменилась с {old_price} на {new_price}")
        log.warning(message)


if __name__ == "__main__":
    uvicorn.run("main:main_app")
