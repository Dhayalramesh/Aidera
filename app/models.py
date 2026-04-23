from sqlalchemy import Column, Integer, String
from .db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password = Column(String)


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    phone = Column(String)
    address = Column(String)
    area = Column(String)