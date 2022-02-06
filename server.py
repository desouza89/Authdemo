#FastAPI server
import base64
import hmac
import hashlib
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = 'b86ee0a79c01b6303bf1e012604bdb1c8b4fe45ba6b9b12825be39463f37cafc'
PASSWORD_SALT = 'bf75e177d83221f2aad9ac82cf00f52c844eea88dae4418006c7fff40bbbdfb6'

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()) \
        .hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash

users = {
    'stas@gmail.com': {
        'name': 'Stas',
        'password': '355be50698df7b82ecc96d2147e77dd36a66c92a021b7f6656ea137092a67973',
        'balance': 100_000
    },

    'petr@gmail.com': {
        'name': 'Petr',
        'password': '8ed35b896b37af09c778a0f34da77b1f4e6a8b082eaf79a622bb527a2d862733',
        'balance': 555_555
    }
    
}



def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)

    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get("/") 
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type='text/html')

    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f"Привет, {user['name']}!<br />"
                    f"Баланс: {user['balance']}", media_type='text/html')



@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
        json.dumps({
            "success": False,
            "message": "Я вас не знаю!"
        }),
        media_type='application/json')

    response =  Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        media_type='application/json')
    
    username_signed = base64.b64encode(username.encode()).decode() + '.' + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed, expires=60*60*24*36)
    return response
