from datetime import datetime, timedelta
import bcrypt
from app import JWT_SECRETKEY
from response import Response
from flask import request, make_response
from .model import User, UserSchema, db
import jwt

class UserController:
    def __init__(self):
        super().__init__()
        self.model = User
        self.schema = UserSchema
    
    def create(self):
        reqJson = request.form
        email = reqJson["email"]
        username = reqJson["username"]
        password = reqJson["password"]
        user = User(
            email=email,
            username=username,
            password=bcrypt.hashpw(
                password=password.encode('utf-8'),
                salt=bcrypt.gensalt()
            ).decode()
        )
        db.session.add(user)
        db.session.commit()
        return Response.make(True, 'User Created')

    def findUser(self, email):
        user = self.model.query.filter(
            User.email == email
        ).first()
        return user
    
    def changeUserName(self):
        form = lambda field: request.form.get(field)

        # Parse JWT Token
        parsedJWT = self.decodeToken()

        # Get email from parsed JWT
        email= parsedJWT["email"]
    
        new_username = form("new_username")

        # Find username with email from JWT
        user = self.findUser(email=email)

        # Update username
        user.username = new_username
        db.session.commit()

        return Response.make(msg="Username Updated")
    
    def deleteUser(self):
        # Parse JWT Token
        parsedJWT = self.decodeToken()

        # Get email from parsed JWT
        email= parsedJWT["email"]

        user = self.findUser(email=email)
        db.session.delete(user)
        db.session.commit()

        return Response.make(msg="User deleted")

    def authenticate(self):
        reqJson = request.form
        email = reqJson["email"]
        password = reqJson["password"]
        user = self.findUser(email=email)
        if not user:
            return Response.make(status=False, msg="User not found")
        elif bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            token = self.createToken(user=user)
            res = make_response(Response.make(
                msg="Login succeed",
                data=token
            ))

            res.set_cookie(
                'x-auth-token',
                token
            )

            return res
        else:
            return Response.make(
                status=False,
                msg="Login Failed"
            )

    def createToken(self, user):
        token = jwt.encode(
            payload={
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'exp':datetime.utcnow() + timedelta(minutes=30)
            },
            key=JWT_SECRETKEY,
            algorithm="HS256"
        )
        return token
    def logout(self):
        resp = make_response(Response.make(msg='Logged Out'))
        resp.delete_cookie('x-auth-token')

        return resp
    def encryptPassword(self, password):
        if password:
            return bcrypt.hashpw(
                    password=password.encode('utf-8'),
                    salt=bcrypt.gensalt()
                ).decode()
    def decodeToken(self):
        token = request.cookies.get('x-auth-token')
        return jwt.decode(token, JWT_SECRETKEY, algorithms="HS256", options={"verify_signature": False})



