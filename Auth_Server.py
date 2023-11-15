from config.Database import *
from config.Auth import *
from flask import make_response,Flask, request
from flask_cors import CORS
import datetime, json
from pytz import timezone
import mariadb

import base64 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

from dotenv import load_dotenv
import os
load_dotenv()

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

conn_m = get_db_conn(MEMBER_DB)
conn_a = get_db_conn(AUTH_DB)
conn_l = get_db_conn(LOG_DB)
corsor_m = conn_m.cursor()
corsor_a = conn_a.cursor()
corsor_l = conn_l.cursor()


def decrypt(enc):
    key = os.environ.get('ECB_KEY')
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return unpad(cipher.decrypt(enc),16)



@app.route('/')
def board():

    return "4081 Auth_Server running"

def reconnect_db() :
    global conn_m
    global conn_a
    global conn_l
    global corsor_m
    global corsor_a
    global corsor_l
    conn_m = get_db_conn(MEMBER_DB)
    conn_a = get_db_conn(AUTH_DB)
    conn_l = get_db_conn(LOG_DB)
    corsor_m = conn_m.cursor()
    corsor_a = conn_a.cursor()
    corsor_l = conn_l.cursor()


#Token
#Login Request == Token Create
@app.route('/login', methods=['POST'])
def create_token():
    try:
        rq = request.get_json()
        # check user exist

        secretKey  = os.environ.get('SHA_KEY')
        
        print(rq['user_name'])

        if (rq['login_type']) == 'SSO' :
            key = os.environ.get('ECB_KEY')
            enc = base64.b64decode(rq['user_name'])
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
            encrypted_user_name =  ( unpad(cipher.decrypt(enc),16) )
            encrypted_user_name =  encrypted_user_name.decode('utf-8')
        else : 
            encrypted_user_name = rq['user_name']

        print(encrypted_user_name)

        corsor_m.execute(f"SELECT user_no FROM users WHERE user_name = ?", (encrypted_user_name,))
        user_no = corsor_m.fetchone() # (user_no,)
        if (user_no) is None: return "User name not exist", 400
        user_no = user_no[0]

        # get user information for inserting accesstoken
        corsor_m.execute(f"SELECT * FROM profile WHERE user_no = ?", (user_no,))
        profile_row = corsor_m.fetchone() # (user_no, cell_phone, email, cj_world_account, join_date, update_date, authentication_level)
        
        
        

        # check authorize
        if (rq['login_type']) == 'EXCEPT':
            corsor_a.execute(f"SELECT * FROM password WHERE user_no = ?", (user_no,))
            pw_row = corsor_a.fetchone() # (password_id, user_no, salt, update_date, password)
            pw = sha256( rq['pw'] + pw_row[2] ) # check pw
            if pw == pw_row[4] : pass 
            else : 
                #Login log insert ( Fail code : 0 )
                insert_tuple = (user_no, profile_row[7], 0)
                insert_query = f"INSERT INTO login_log (user_no, user_name, status_code) VALUES (%s, %s, %d)"
                corsor_l.execute(insert_query, insert_tuple)
                conn_l.commit()
                response = make_response({"detail":'Id or Password is not valid'},401)
                response.headers['server']=None
                return response
  
        elif (rq['login_type']) == 'SSO':
            if sha256(encrypted_user_name + secretKey) == rq['check_key']:
                pass
            else :
                response = make_response({"detail":'Check key is not valid'},401)
                response.headers['server']=None
                return response
        else: 
            #Login log insert ( Fail code : 0 )
            insert_tuple = (user_no, profile_row[7], 0)
            insert_query = f"INSERT INTO login_log (user_no, user_name, status_code) VALUES (%s, %s, %d)"
            corsor_l.execute(insert_query, insert_tuple)
            conn_l.commit()
            response = make_response({"detail":'Abnormal request'},404)
            response.headers['server']=None
            return response
        
        

        # create access token
        payload = {'exp':get_time_now() + datetime.timedelta(hours= 24), 'user_no':user_no, 'cell_phone':profile_row[2],'email':profile_row[3]
                , 'authentication_level':profile_row[6], "user_name":profile_row[7]}
        access_token = create_token_per_type(payload)

        #Login log insert ( Success code : 1 )
        insert_tuple = (user_no, profile_row[7], 1)
        insert_query = f"INSERT INTO login_log (user_no, user_name, status_code) VALUES (%s, %s, %d)"
        corsor_l.execute(insert_query, insert_tuple)

        #user activity log insert *(login success cases only)
        insert_tuple = (user_no, profile_row[7], "LOGIN", "login success")
        insert_query = f"INSERT INTO user_activity_log (user_no, user_name, action_type, meta_data) VALUES (%s, %s, %s, %s)"
        corsor_l.execute(insert_query, insert_tuple)

        conn_l.commit()


        #admin user case, return password expiration list
        user_authentication_level = profile_row[6] 
        if user_authentication_level == 'admin' : expiration_list = get_pw_expiration_list()
        else : expiration_list = []

        response = make_response({"access_token":access_token, 'user_info': payload, 'expiration_list':expiration_list})
        response.headers['server']=None
        
        return response
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/token', methods=['POST'])
def validate_token():
    try:
        rq = request.get_json() # access_token

        decoded_token = decode_token(rq['access_token'])

        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            response.headers['Server']=None
            return response
        else :  
            response = make_response({"status":"success"}, 200)
            response.headers['server']=None
            response.headers['Server']=None
            return response
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
        

#User
#------------------------------------------------------------#

@app.route('/users', methods=['POST'])
def create_users():
    try:
        rq = request.get_json()
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # Check authentication level with access_token user_no 
        user_authentication_level = decoded_token["authentication_level"] 
        if user_authentication_level == 'admin' : pass
        else : 
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response

        salt = get_salt()
        pw = sha256( rq['pw'] + salt )

        # Check duplicate
        corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", (rq['user_name'],))
        isExist = corsor_m.fetchone()
        if (isExist) is not None: 
            response = make_response({"status":"fail"}, 409)
            response.headers['server']=None
            return response

        # CJ_Websim_Member.users insert
        insert_tuple = (rq['user_name'],)
        insert_query = f"INSERT INTO users (user_name) VALUES (%s)"
        corsor_m.execute(insert_query, insert_tuple)

        conn_m.commit()

        # Get user_no ( Foreign key / automatically increase int value)
        corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", (rq['user_name'],))
        user = corsor_m.fetchone() # (user_no, user_name)
        user_no = user[0] 

        # CJ_Websim_Member.profile insert 
        insert_tuple = (user_no, str( rq['cell_phone'] ), rq['email'],  rq['authentication_level'], rq['name'])
        insert_query = f"INSERT INTO profile (user_no, cell_phone, email, authentication_level, user_name) VALUES (%d, %s, %s, %s, %s)"
        corsor_m.execute(insert_query, insert_tuple)

        conn_m.commit()
        
        # CJ_Websim_Auth.password insert
        insert_tuple = (user_no, salt, pw)
        insert_query = f"INSERT INTO password (user_no, salt, password) VALUES (%d, %s, %s)"
        corsor_a.execute(insert_query, insert_tuple)
        
        conn_a.commit()

        # join member.users, member.profile , return tuple array
        corsor_m.execute(f"SELECT * FROM users INNER JOIN profile ON users.user_no = profile.user_no")
        user_list = corsor_m.fetchall() # ( , , , )

        res = json.dumps({'user_list':user_list} , default=str)

        response = make_response(res, 201)
        response.headers['server']=None
        return response
    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/users', methods=['DELETE'])
def delete_users():
    try:
        rq = request.get_json() # access_token / taget_user_no
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # Check authentication level with access_token user_no 
        user_authentication_level = decoded_token["authentication_level"] 
        if user_authentication_level == 'admin' : pass
        else : 
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response

        #Delete CJ_Websim_Member.users => via ON DELTE cascade option, delete authomatically another table information
        corsor_m.execute(f"DELETE FROM users WHERE user_no = ?", (int( rq['target_user_no'] ),) )
        conn_m.commit()

        #Log insert query for Delete user history
        insert_tuple = (int (rq['target_user_no']), rq["target_user_name"] )
        insert_query = f"INSERT INTO withdrawal_log (user_no, user_name) VALUES (%s, %s)"
        corsor_l.execute(insert_query, insert_tuple)

        conn_l.commit()

        # join member.users, member.profile , return tuple array
        corsor_m.execute(f"SELECT * FROM users INNER JOIN profile ON users.user_no = profile.user_no")
        user_list = corsor_m.fetchall() # ( , , , )

        res = json.dumps({'user_list':user_list} , default=str)

        response = make_response(res, 200)
        response.headers['server']=None
        return response

    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/users', methods=['PUT'])
def update_users():
    try:
        rq = request.get_json()

        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # Check authentication level with access_token user_no 
        # User case (need to match access_token, target_user_no)
        user_authentication_level = decoded_token["authentication_level"] 
        if user_authentication_level == 'admin' : pass
        elif user_authentication_level == 'user' and decoded_token['user_no'] == rq['target_user_no'] : pass 
        else :
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response

        update_tuple_m = ''
        update_query_m = ''
        update_tuple_a = ''
        update_query_a = ''

        if rq['update_target'] == 'email' :
            update_tuple_m = ( rq['email'], rq['target_user_no'])
            update_query_m = f"UPDATE profile set email = ? WHERE user_no = ?"
        
        elif rq['update_target'] == 'cell_phone' :
            update_tuple_m = ( str(rq['cell_phone']), rq['target_user_no'])
            update_query_m = f"UPDATE profile set cell_phone = ? WHERE user_no = ?"

        elif rq['update_target'] == 'password' :
            corsor_a.execute(f"SELECT * FROM password WHERE user_no = ?", (rq['target_user_no'],))
            pw_row = corsor_a.fetchone() # (password_id, user_no, salt, update_date, password)
            pw = sha256( rq['current_password'] + pw_row[2] ) # check pw
            if pw == pw_row[4] : 
                new_pw = sha256( rq['new_password'] + pw_row[2] ) # make new pw
                update_tuple_a = ( new_pw, rq['target_user_no'])
                update_query_a = f"UPDATE password set password = ? WHERE user_no = ?"
            else :
                response = make_response({"status":"fail"}, 401)
                response.headers['server']=None
                return response
        else :
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response
        
        if  update_tuple_m != '' :
            corsor_m.execute(update_query_m, update_tuple_m)
            conn_m.commit()

        if  update_tuple_a != '' :
            corsor_a.execute(update_query_a, update_tuple_a)
            conn_a.commit()

        response = make_response({"status":"update"}, 200)
        response.headers['server']=None
        return response

    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/users/admin', methods=['PUT'])
def update_users_admin():
    try:
        rq = request.get_json()
        isUpdate = False

        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # Check authentication level with access_token user_no 
        user_authentication_level = decoded_token["authentication_level"] 
        if user_authentication_level == 'admin' : pass
        else : 
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response


        if rq['email_address'] != '' :
            update_tuple_m = ( rq['email_address'], rq['target_user_no'])
            update_query_m = f"UPDATE profile set email = ? WHERE user_no = ?" 
            corsor_m.execute(update_query_m, update_tuple_m)
            conn_m.commit()
            isUpdate = True

        if rq['phone_number'] != '' :
            update_tuple_m = ( rq['phone_number'], rq['target_user_no'])
            update_query_m = f"UPDATE profile set cell_phone = ? WHERE user_no = ?" 
            corsor_m.execute(update_query_m, update_tuple_m)
            conn_m.commit()
            isUpdate = True
        
        if rq['user_authentication_level'] == 'admin' or rq['user_authentication_level'] == 'user' :
            update_tuple_m = ( rq['user_authentication_level'], rq['target_user_no'])
            update_query_m = f"UPDATE profile set authentication_level = ? WHERE user_no = ?" 
            corsor_m.execute(update_query_m, update_tuple_m)
            conn_m.commit()
            isUpdate = True

        if rq['new_password'] != '' :
            corsor_a.execute(f"SELECT * FROM password WHERE user_no = ?", (rq['target_user_no'],))
            pw_row = corsor_a.fetchone()
            new_pw = sha256( rq['new_password'] + pw_row[2] ) # check pw
            update_tuple_a = ( new_pw, rq['target_user_no'])
            update_query_a = f"UPDATE password set password = ? WHERE user_no = ?" 

            corsor_a.execute(update_query_a, update_tuple_a)
            conn_a.commit()
            isUpdate = True
        
        #  change
        if isUpdate :
            # join member.users, member.profile , return tuple array
            corsor_m.execute(f"SELECT * FROM users INNER JOIN profile ON users.user_no = profile.user_no")
            user_list = corsor_m.fetchall() # ( , , , )

            res = json.dumps({'user_list':user_list} , default=str)
            response = make_response(res, 200)
            response.headers['server']=None
            return response

    
        else :
            res = json.dumps({'user_list':[]} , default=str)
            response = make_response(res, 200)
            response.headers['server']=None
            return response
        
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/users/list', methods=['POST'])
def read_users():
    try:
        rq = request.get_json()

        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # Check authentication level with access_token user_no 
        user_authentication_level = decoded_token["authentication_level"]  
        if user_authentication_level == 'admin' : pass
        else : 
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response

        # join member.users, member.profile , return tuple array
        corsor_m.execute(f"SELECT * FROM users INNER JOIN profile ON users.user_no = profile.user_no")
        user_list = corsor_m.fetchall() # ( , , , )

        res = json.dumps({'user_list':user_list} , default=str)
        response = make_response(res, 200)
        response.headers['server']=None
        return response

    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response

#Log
#------------------------------------------------------------#
@app.route('/log', methods=['POST'])
def create_log():
    try:
        rq = request.get_json()
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        #user activity log insert 
        insert_tuple = (decoded_token['user_no'], decoded_token['user_name'], rq['action_type'], rq['meta_data'])
        insert_query = f"INSERT INTO user_activity_log (user_no, user_name, action_type, meta_data) VALUES (%s, %s, %s, %s)"
        corsor_l.execute(insert_query, insert_tuple)
        conn_l.commit()
        
        response = make_response({"status":"insert"}, 200)
        response.headers['server']=None
        return response
    
    except mariadb.Error as err:
        reconnect_db()
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response

@app.route('/log/login', methods=['POST'])
def create_login_log():
    try:
        rq = request.get_json()
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass
        if rq['login_event_type'] == 0 : # login fail
            #Login log insert (fail)
            insert_tuple = (rq['user_no'], rq['user_name'], 0)
            insert_query = f"INSERT INTO login_log (user_no, user_name, status_code) VALUES (%s, %s, %d)"
            corsor_l.execute(insert_query, insert_tuple)
            conn_l.commit()
            #user activity log insert 
            insert_tuple = (rq['user_no'], rq['user_name'], "LOGIN", "login fail")
            insert_query = f"INSERT INTO user_activity_log (user_no, user_name, action_type, meta_data) VALUES (%s, %s, %s, %s)"
            corsor_l.execute(insert_query, insert_tuple)
        elif rq['login_event_type'] == 1 : # login success
            #Login log insert (success)
            insert_tuple = (rq['user_no'], rq['user_name'], 1)
            insert_query = f"INSERT INTO login_log (user_no, user_name, status_code) VALUES (%s, %s, %d)"
            corsor_l.execute(insert_query, insert_tuple)
            conn_l.commit()
            #user activity log insert 
            insert_tuple = (rq['user_no'], rq['user_name'], "LOGIN", "login success")
            insert_query = f"INSERT INTO user_activity_log (user_no, user_name, action_type, meta_data) VALUES (%s, %s, %s, %s)"
            corsor_l.execute(insert_query, insert_tuple)
        else:
            print()
        
        response = make_response({"status":"success"}, 200)
        response.headers['server']=None
        return response
    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


@app.route('/log/expire', methods=['POST'])
def get_expire_log():
    try:
        rq = request.get_json()
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        user_authentication_level = decoded_token["authentication_level"] 
        if user_authentication_level == 'admin' : pass

        expiration_list = get_pw_expiration_list()

        res = json.dumps({'expiration_list':expiration_list} , default=str)
        response = make_response(res, 200)
        response.headers['server']=None
        return response

    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response



@app.route('/log/list', methods=['POST'])
def read_log():
    try:
        rq = request.get_json()
        decoded_token = decode_token(rq['access_token'])
        if decoded_token == {} : 
            response = make_response({"status":"fail"}, 401)
            response.headers['server']=None
            return response
        else : pass

        # rq['request_type'] : 'ENTIRE' , 'SELF'
        if rq['request_type'] == 'ENTIRE' :
            # authentical level check
            user_authentication_level = decoded_token["authentication_level"] 
            if user_authentication_level == 'admin' : pass
            else : 
                response = make_response({"status":"fail"}, 404)
                response.headers['server']=None
                return response

            #return entire log list
            corsor_l.execute(f"SELECT * FROM user_activity_log")
            log_list = corsor_l.fetchall() 
        elif rq['request_type'] == 'OWN' :
            user_no = decoded_token["user_no"] 
            
            #return own log list
            corsor_l.execute(f"SELECT * FROM user_activity_log where user_no = ?", (user_no,))
            log_list = corsor_l.fetchall() 
        else :
            response = make_response({"status":"fail"}, 404)
            response.headers['server']=None
            return response
        

        res = json.dumps({'log_list':log_list} , default=str)
        response = make_response(res, 200)
        response.headers['server']=None
        return response

    
    except mariadb.Error as err:
        reconnect_db()
        print(err)
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response
    except:
        response = make_response({"status":"fail"}, 401)
        response.headers['server']=None
        return response


def get_pw_expiration_list():
    
    corsor_m.execute(f"SELECT * FROM cj_websim_auth.password INNER JOIN cj_websim_member.users ON password.user_no = users.user_no")
    entire_user_list = corsor_m.fetchall() 
    # entire_user_list[n][3] : recent update date /
    # entire_user_list[n][5] : user id  /  
    # entire_user_list[n][6] : user login type

    password_expiration_list = []
    now_datetime = get_time_now()
    now_timestamp = now_datetime.timestamp()

    STANDARD_TIMESTAMP_VALUE = 24 * 60 * 60 * 80 # 80 days
    print( entire_user_list)

    for i in range( len( entire_user_list ) ):
        
            print(entire_user_list[i])
            recent_update_datetime_obj = entire_user_list[i][3]

            recent_update_datetimestamp = recent_update_datetime_obj.timestamp()
            if ( now_timestamp - recent_update_datetimestamp > STANDARD_TIMESTAMP_VALUE) :
                corsor_m.execute(f"SELECT user_name FROM profile WHERE user_no = ?", (entire_user_list[i][1],))
                username = corsor_m.fetchone() # (username, )
                
                remain_days = int((now_timestamp - recent_update_datetimestamp) // (24*60*60) - 80 )
                if (remain_days < 0) :
                    remains = str( -1 * remain_days) + " days remain"
                else :
                    remains = str(  remain_days) + " days pass"
    
                recent_update_datetime = datetime.datetime.fromtimestamp(recent_update_datetimestamp, (timezone('Asia/Seoul')))

                print(recent_update_datetime_obj)
                print(recent_update_datetime)
                password_expiration_list.append([username[0], recent_update_datetime, remains ])



    return password_expiration_list




def create_admin():

    salt = get_salt()
    pw = sha256("cj1234!")
    pw = sha256( pw + salt )

    # Check duplicate
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('cj_admin',))
    isExist = corsor_m.fetchone()
    if (isExist) is not None: return "Admin already exist", 409

    # CJ_Websim_Member.users insert
    insert_tuple = ('cj_admin',)
    insert_query = f"INSERT INTO users (user_name) VALUES (%s)"
    corsor_m.execute(insert_query, insert_tuple)

    # Get user_no ( Foreign key / automatically increase int value)
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('cj_admin',))
    user = corsor_m.fetchone() # (user_no, user_name, login_type)
    user_no = user[0] 

    # CJ_Websim_Member.profile insert 
    insert_tuple = (user_no, '-', '-', 'admin', 'cj_admin')
    insert_query = f"INSERT INTO profile (user_no, cell_phone, email, authentication_level, user_name) VALUES (%d, %s, %s, %s, %s)"
    corsor_m.execute(insert_query, insert_tuple)

    conn_m.commit()
    
    # CJ_Websim_Auth.password insert
    insert_tuple = (user_no, salt, pw)
    insert_query = f"INSERT INTO password (user_no, salt, password) VALUES (%d, %s, %s)"
    corsor_a.execute(insert_query, insert_tuple)

    # commit db 
    conn_a.commit()

    return json.dumps({'Admin created'} , default=str), 201


def create_test_user():

    salt = get_salt()
    pw = sha256( "0000"  )
    pw = sha256( pw + salt )


    # Check duplicate
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('cjwsampleuser',))
    isExist = corsor_m.fetchone()
    if (isExist) is not None: return "cjwsampleuser already exist", 409

    # CJ_Websim_Member.users insert
    insert_tuple = ('cjwsampleuser',)
    insert_query = f"INSERT INTO users (user_name) VALUES (%s)"
    corsor_m.execute(insert_query, insert_tuple)

    # Get user_no ( Foreign key / automatically increase int value)
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('cjwsampleuser',))
    user = corsor_m.fetchone() # (user_no, user_name, login_type)
    user_no = user[0] 

    # CJ_Websim_Member.profile insert 
    insert_tuple = (user_no, '-', '-', 'admin', 'cjwsampleuser')
    insert_query = f"INSERT INTO profile (user_no, cell_phone, email,  authentication_level, user_name) VALUES (%d, %s, %s, %s, %s)"
    corsor_m.execute(insert_query, insert_tuple)

    conn_m.commit()

    # CJ_Websim_Auth.password insert
    insert_tuple = (user_no, salt, pw)
    insert_query = f"INSERT INTO password (user_no, salt, password) VALUES (%d, %s, %s)"
    corsor_a.execute(insert_query, insert_tuple)
    
    conn_a.commit()

    return json.dumps({'testuser created'} , default=str), 201


def create_test_user_2():

    salt = get_salt()
    pw = sha256( "0000"  )
    pw = sha256( pw + salt )


    # Check duplicate
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('pw_expire_test',))
    isExist = corsor_m.fetchone()
    if (isExist) is not None: return "cjwsampleuser already exist", 409

    # CJ_Websim_Member.users insert
    insert_tuple = ('pw_expire_test',)
    insert_query = f"INSERT INTO users (user_name) VALUES (%s)"
    corsor_m.execute(insert_query, insert_tuple)

    # Get user_no ( Foreign key / automatically increase int value)
    corsor_m.execute(f"SELECT * FROM users WHERE user_name = ?", ('pw_expire_test',))
    user = corsor_m.fetchone() # (user_no, user_name, login_type)
    user_no = user[0] 

    # CJ_Websim_Member.profile insert 
    insert_tuple = (user_no, '-', '-', 'user', 'pw_expire_test')
    insert_query = f"INSERT INTO profile (user_no, cell_phone, email,  authentication_level, user_name) VALUES (%d, %s, %s, %s, %s)"
    corsor_m.execute(insert_query, insert_tuple)

    conn_m.commit()

    # CJ_Websim_Auth.password insert
    insert_tuple = (user_no, salt, datetime.datetime(2023,1,1),pw)
    insert_query = f"INSERT INTO password (user_no, salt, update_date, password) VALUES (%d, %s, %s, %s)"
    corsor_a.execute(insert_query, insert_tuple)
    conn_a.commit()

    return json.dumps({'testuser created'} , default=str), 201


create_admin()
create_test_user()
create_test_user_2()



# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=4081)
    