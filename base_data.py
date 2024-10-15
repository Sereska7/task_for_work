import os


from datetime import datetime
from dotenv import load_dotenv
from pydantic import EmailStr
from sqlalchemy import select, Numeric, DECIMAL, Integer, ForeignKey, DateTime, String, delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, relationship, mapped_column, declarative_base


load_dotenv(dotenv_path=".env.example")


# Инициализация движка и сессий для работы с базой данных
engine = create_async_engine(os.getenv("DB_URL"))
session_factory = async_sessionmaker(engine)
Base = declarative_base()


# Описание модели пользователя
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=True, index=True)

    alarm: Mapped["AlarmPrice"] = relationship(back_populates="user")


# Описание модели валютных пар
class Pair(Base):
    __tablename__ = "pairs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, index=True)

    alarm: Mapped["AlarmPrice"] = relationship(back_populates="pair")

# Описание модели уведомление на цену валютных пар
class AlarmPrice(Base):
    __tablename__ = "alarm_prices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    pair_id: Mapped[int] = mapped_column(Integer, ForeignKey("pairs.id"))
    price: Mapped[DECIMAL] = mapped_column(Numeric(20, 10))

    user: Mapped["User"] = relationship(back_populates="alarm")
    pair: Mapped["Pair"] = relationship(back_populates="alarm")


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Создание всех таблиц

# Добавление нового пользователя в базу данных
async def add_user(email: EmailStr, password: str, date_reg: datetime):
    async with session_factory() as session:
        new_user = User(
            email=email,
            password=password,
            created_at=date_reg
        )
        session.add(new_user)
        await session.commit()
        return new_user


# Получение пользователя из базы данных по указанным критериям
async def get_user(**kwargs):
    async with session_factory() as session:
        request = select(User).filter_by(**kwargs)
        user = await session.execute(request)
        return user.scalar_one_or_none()

# Получение данных валютный пары, по названию
async def get_pair(pair: str):
    async with session_factory() as session:
        request = select(Pair).where(Pair.name == pair)
        pair = await session.execute(request)
        return pair.scalar_one_or_none()


# Добавление нового 'колокольчика' для цены валютной пары
async def add_alarm_for_price(pair_id: int, user_id: int, price: float):
    async with session_factory() as session:
        new_alarm = AlarmPrice(
            pair_id=pair_id,
            user_id=user_id,
            price=price
        )
        session.add(new_alarm)
        await session.commit()
        return new_alarm

# Удаление 'колокольчика' на цену для валютной пары
async def remove_alarm(alarm_id):
    async with session_factory() as session:
        stmt = delete(AlarmPrice).where(AlarmPrice.id == alarm_id)
        await session.execute(stmt)
        await session.commit()


# Получение все 'колокольчиков' для валютных пар
async def get_alarm_prices():
    async with session_factory() as session:
        alarm_prices = await session.execute(select(AlarmPrice.__table__.columns))
        return alarm_prices.mappings().all()

