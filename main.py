import asyncio
import logging
from datetime import datetime
from typing import Optional

import jwt
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from httpx import AsyncClient
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


async def get_user(**data: dict):
    async with session_factory() as session:
        request = select(User).filter_by(**data)
        user = await session.execute(request)
        return user.scalar_one_or_none()


async def get_users_for_pair(trading_pair: str):
    async with session_factory() as session:
        query = None
        # Определяем запрос в зависимости от валютной пары
        if trading_pair == "BTC-USD":
            query = select(User).where(User.get_BTC_USD == True)
        elif trading_pair == "ETH-USD":
            query = select(User).where(User.get_ETH_USD == True)
        elif trading_pair == "USDTERC-USD":
            query = select(User).where(User.get_USDTERC_USD == True)
        elif trading_pair == "USDTTRC-USD":
            query = select(User).where(User.get_USDTTRC_USD == True)

        if query is not None:
            result = await session.execute(query)
            users = result.scalars().all()  # Получаем список пользователей
            return users
        return []


async def lifespan(app: FastAPI):
    # start
    await init_db()
    logging.basicConfig(level=logging.WARNING)
    asyncio.create_task(fetch_prices())
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
            elif request.pair == "ETH-USD":
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


async def get_price(currency: str):
    await asyncio.sleep(1)
    async with AsyncClient() as client:
        response = await client.get(
            f"https://api.coingecko.com/api/v3/simple/price?ids={currency}&vs_currencies=usd"
        )
        return response.json().get(currency, {}).get("usd", None)


log = logging.getLogger()


async def fetch_prices():
    # Инициализируем пустой словарь для хранения предыдущих цен
    previous_prices = {
        "BTC-USD": None,
        "ETH-USD": None,
        "USDTERC-USD": None,
        "USDTTRC-USD": None,
    }
    while True:
        log.warning("Цикл запущен")
        new_prices = {
            "BTC-USD": await get_price("bitcoin"),
            "ETH-USD": await get_price("ethereum"),
            "USDTERC-USD": await get_price("usd-coin"),
            "USDTTRC-USD": await get_price("tether"),
        }

        for pair, new_price in new_prices.items():
            previous_price = previous_prices.get(pair)
            if previous_price is None:
                previous_prices[pair] = new_price
                continue
            if previous_price != new_price:
                log.info(f"Название: {pair} Старая цена: {previous_price} Новая цена: {new_price}")
                await notify_user(pair, previous_price, new_price)
        await asyncio.sleep(60)


async def notify_user(trading_pair: str, old_price: float, new_price: float):
    users = await get_users_for_pair(trading_pair)
    for user in users:
        message = (f"Уведомление пользователю: {user.email}\n"
                   f"Цена для {trading_pair} изменилась с {old_price} на {new_price}")
        log.warning(message)


if __name__ == "__main__":
    uvicorn.run("main:main_app")
