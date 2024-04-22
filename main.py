from app import db
from flask_migrate import Migrate
from migrations import *

from api import *

migrate=Migrate(app,db)