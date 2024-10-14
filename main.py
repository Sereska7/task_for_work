import asyncio
import logging
from datetime import datetime
from typing import Optional, Any

import jwt
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from httpx import AsyncClient
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Integer, String, DateTime, select, Boolean, Select, Update
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, declarative_base
from starlette import status

DB_URL = "postgresql+asyncpg://postgres:wer255678@localhost:5432/task_db"
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger()

# Инициализация движка и сессий для работы с базой данных
engine = create_async_engine(DB_URL)
session_factory = async_sessionmaker(engine)
Base = declarative_base()


# Описание модели пользователя
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


# Pydantic модель для логина пользователя
class SUserLog(BaseModel):
    email: EmailStr
    password: str


# Pydantic модель для установки уведомлений (выбор валютных пар)
class SetAlertRequest(BaseModel):
    btc_usd: bool
    eth_usd: bool
    usdterc: bool
    usdttrc: bool


# Функция для инициализации базы данных (создание и удаление таблиц)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)  # Удаление всех таблиц (для тестов)
        await conn.run_sync(Base.metadata.create_all)  # Создание всех таблиц


# Функция для инициализации приложения и запуска фоновой задачи
async def lifespan(app: FastAPI):
    # start
    await init_db()  # Инициализируем базу данных при запуске приложения
    await add_user()  # Добавляем тестовых пользователей
    logging.basicConfig(level=logging.WARNING)  # Настройка логирования
    asyncio.create_task(fetch_prices())  # Запускаем задачу для получения цен
    yield
    # stop

# Инициализация FastAPI приложения с использованием lifespan
main_app = FastAPI(lifespan=lifespan)


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


# Функция для добавления тестовых пользователей в базу данных
async def add_user():
    data = [
        {
            "email": "user_1@example.com",
            "password": "password",
            "created_at": datetime.now(),
        },
        {
            "email": "user_2@example.com",
            "password": "password",
            "created_at": datetime.now(),
        },
    ]
    async with session_factory() as session:
        for person in data:
            # Хеширование пароля при создании пользователя
            user = User(
                email=person["email"],
                password=get_password_hash(person["password"]),
                created_at=person["created_at"],
            )
            session.add(user)
            await session.commit()  # Фиксируем изменения
            return user  # Возвращаем созданного пользователя


# Получение пользователя из базы данных по указанным критериям
async def get_user(**kwargs) -> Any | None:
    async with session_factory() as session:
        request = select(User).filter_by(**kwargs)
        user = await session.execute(request)
        return user.scalar_one_or_none()


# Получение пользователей, которые подписаны на уведомления по определённой паре
async def get_users_for_pair(trading_pair: str):
    async with session_factory() as session:
        query: Select = Select()
        # Определяем запрос в зависимости от выбранной валютной пары
        if trading_pair == "BTC-USD":
            query = select(User).where(User.get_BTC_USD == True)
        elif trading_pair == "ETH-USD":
            query = select(User).where(User.get_ETH_USD == True)
        elif trading_pair == "USDTERC-USD":
            query = select(User).where(User.get_USDTERC_USD == True)
        elif trading_pair == "USDTTRC-USD":
            query = select(User).where(User.get_USDTTRC_USD == True)

        if query != Select():
            result = await session.execute(query)
            users = list(result.scalars().all())
            return users
        return []


# Создание JWT токена для пользователя
async def create_access_token(data: dict):
    to_encode = data.copy()
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)
    return encode_jwt


# Получение токена из запроса
async def get_token_from_request(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No authentication token provided")
    return token


# Получение текущего пользователя на основе токена
async def get_current_user(token: Optional[str] = Depends(get_token_from_request)):
    payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
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
    async with session_factory() as session:
        # Обновляем данные пользователя
        query = Update(User).where(User.id == current_user.id).values(
            get_BTC_USD=data.btc_usd,
            get_ETH_USD=data.eth_usd,
            get_USDTERC_USD=data.usdterc,
            get_USDTTRC_USD=data.usdttrc
        )
        await session.execute(query)
        await session.commit()
    return HTTPException(status_code=status.HTTP_200_OK, detail="Data update")


# Функция для получения актуальной цены валюты
async def get_price(currency: str):
    async with AsyncClient() as client:
        response = await client.get(
            f"https://api.coingecko.com/api/v3/simple/price?ids={currency}&vs_currencies=usd"
        )
        return response.json().get(currency, {}).get("usd", None)


# Фоновая задача для получения цен и оповещения пользователей
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

        # Получаем актуальные цены для каждой пары
        btc_usd = await get_price("bitcoin")
        await asyncio.sleep(1)
        etc_usd = await get_price("ethereum")
        await asyncio.sleep(1)
        usdterc_usd = await get_price("tether")
        await asyncio.sleep(1)
        usdttrc_usd = await get_price("tether")

        # Сравниваем новые цены с предыдущими
        new_prices = {
            "BTC-USD": btc_usd,
            "ETH-USD": etc_usd,
            "USDTERC-USD": usdterc_usd,
            "USDTTRC-USD": usdttrc_usd,
        }

        for pair, new_price in new_prices.items():
            previous_price = previous_prices.get(pair)

            if previous_price != new_price:
                previous_prices[pair] = new_price
                log.info(
                    f"Название: {pair} Старая цена: {previous_price} Новая цена: {new_price}"
                )
                # Уведомляем пользователя о смене цены
                await notify_user(pair, previous_price, new_price)
        await asyncio.sleep(60)  # Задержка на 60 секунд


# Функция для отправки уведомлений пользователям
async def notify_user(trading_pair: str, old_price: float, new_price: float):
    users = await get_users_for_pair(trading_pair)
    for user in users:
        message = (
            f"Уведомление пользователю: {user.email}\n"
            f"Цена для {trading_pair} изменилась с {old_price} на {new_price}"
        )
        log.warning(message)

# Запуск приложения
if __name__ == "__main__":
    uvicorn.run("main:main_app")
