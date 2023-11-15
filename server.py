from waitress import serve
import Auth_Server 
serve(Auth_Server.app, host='0.0.0.0', port=4081)