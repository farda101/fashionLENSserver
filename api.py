
from flask import request
from app import app
from application.user.controller import UserController

@app.route('/user/register', methods=['POST'])
def registerUser():
  controller = UserController()
  return controller.create()

@app.route('/user/login', methods=['POST'])
def login():
  controller = UserController()
  return controller.authenticate()