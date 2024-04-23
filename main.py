from flask_migrate import Migrate
from api import *
from migrations import *
from app import app, db

migrate=Migrate(app,db)