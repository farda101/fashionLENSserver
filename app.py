import bcrypt
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

app = Flask(__name__)
class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)
    
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://amer:walker987@34.101.38.135:3306/fashion_lens'
db.init_app(app)

JWT_SECRETKEY=bcrypt.hashpw(b'itsAs3cr34tkeyforJWT', bcrypt.gensalt())

