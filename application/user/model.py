from sqlalchemy import Integer, String, Column
from sqlalchemy.orm import Mapped, mapped_column
from marshmallow import fields, Schema
from app import db

class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    username: Mapped[str] = mapped_column(String(length=256))
    password: Mapped[str] = mapped_column(String(length=128))

class UserSchema(Schema):
    id: fields.Int
    email: fields.String
    username: fields.String
    password: fields.String