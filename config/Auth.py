import base64, random, hashlib
import mariadb
from . import Database
import datetime, jwt
from flask import make_response,Flask, jsonify, request, render_template
from pytz import timezone

def get_time_now () :
    return datetime.datetime.now(timezone('Asia/Seoul'))

def get_salt () :
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars=[]
    for i in range(16):
        chars.append(random.choice(ALPHABET))
    return "".join(chars)

def sha256 ( pw ) :
    r = hashlib.sha256( pw.encode() )
    return r.hexdigest()

def get_db_conn (db_name):
    conn = mariadb.connect(user=Database.DB_USER,password=Database.DB_PASSWORD,host=Database.DB_HOST,port=Database.DB_PORT,database=db_name)
    return conn

def create_token_per_type(payload = {'exp':get_time_now() + datetime.timedelta(seconds = 24*60*60)}):
    encoded = jwt.encode(payload = payload,key = PRIVATE_KEY, algorithm = 'HS256')
    return encoded.decode('utf-8')

# token expire or invalid token then return {}
def decode_token( token ):
    try :
        decoded_token = jwt.decode(token, PRIVATE_KEY, algorithms=['HS256'])
        if decoded_token['exp'] < get_time_now().timestamp() : raise Exception("Token expired")
        return decoded_token
    except :
        return {}

def verify_token(access_token):
    decoded_token = decode_token(access_token)
    if decoded_token == {} :
        return "Access Token is not valid",401
    else :
        return (decoded_token) 

def refresh_access_token_response( access_token, refresh_token):
    
    response = make_response()
    response.headers['Access-Token'] = access_token.decode('utf-8')
    response.set_cookie(
        "refresh_token",value=refresh_token,max_age=24*60*60,path="/",samesite="Lax",
    )
    return response


PRIVATE_KEY = """MIIBOQIBAAJAUNfMAHNtDMS4wBuwxsVslbJuQel3OklBqICKIOvdrkzq8NBwmpZU 
Ie27KY4uCmjDouw+HRgULCOV1ok+szLjyQIDAQABAkBQwQ9lz+c5nvSR6dcu5xzt
d/xNWOIhVfYBVM0lz5Z0Of/mVbrJIXJOk95xGLx+68A16PPOmAjiKH6J6Gb5OdgB
AiEAkyJF4W6zsgxWnSuqa0I3zdAYoXLoQC4kvPYgl6DdqwECIQCMqN17DHGuUfWv
MzJd/ZSFTfWZX7pV7db9IA9dbUegyQIgdLfKgbPE3yiEiTf7gAzOoflDoMe70DYK
tM/3OPHHBwECIQCCcYPcPiEa4UUvshHummDm8vJlxyH92HC9E8NMCDEaCQIgXIDk
osXNoxRKCjx0//Gc8yMQpengBP9727068+rXF34="""