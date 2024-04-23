
from flask import request
from app import app
from application.user.controller import UserController
from auth import Auth
from response import Response

auth = Auth()

@app.route('/user/register', methods=['POST'])
def registerUser():
  controller = UserController()
  return controller.create()

@app.route('/health-test', methods=['GET'])
def healthcheck():
  print('OK')
  return 'OK'

@app.route('/user/login', methods=['POST'])
def login():
  controller = UserController()
  return controller.authenticate()

@app.route('/user/logout', methods=['GET'])
def logout():
  controller = UserController()
  return controller.logout()

@app.route('/check-access', methods=['GET'])
@auth.middleware
def checkAccess():
  return Response.make(msg='Authorized')
