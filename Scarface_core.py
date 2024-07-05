import quart as scar
Quart, request, jsonify, send_file, make_response, Response, redirect = scar.Quart, scar.request, scar.jsonify, scar.send_file, scar.make_response, scar.Response, scar.redirect
from asyncio import run as asyncrun
from os.path import exists
from datetime import datetime as dt
from cryptography.fernet import Fernet
from os import environ, mkdir
from sys import exit
from ijson import items
from json import dump
from hmac import new as new_hmac
from hashlib import sha256
from base64 import urlsafe_b64encode

p = print

class Logging:
    def __init__(self) -> None:
        pass
    async def log_data(self, data):
        data = str(data)
        p(data)
        return data

logger = Logging()

class Safe:
    def __init__(self) -> None:
        self.safe_key = environ.get("safe_key", False)
        if not self.safe_key:
            exit("Safe key not found in the environment!")

    async def tool(self, og):
        try:
            if isinstance(og, (list)):
                data = Fernet(self.safe_key.encode()).encrypt(str(og[0]).encode("utf-8")).decode('utf-8')
            elif isinstance(og, (tuple)):
                data = Fernet(self.safe_key.encode()).decrypt(str(og[0]).encode("utf-8")).decode('utf-8')
            else:
                return None
            return data
        except Exception as e:
            p(e)
            return None
        
safe = Safe()

class Database():
    def __init__(self, db_dir = "Database") -> None:
        self.safe_key = environ.get("safe_key", False)
        if not self.safe_key:
            exit("Safe key not found in the environment!")
        self.key = self.safe_key.encode()
        self.db_items = f"{db_dir}/db_items"
        self.user_identifier = None
        self.do = None
        self.user_data = None
        self.og_user_identifier = None
        self.user_file_name = None
        if not exists(db_dir):
            mkdir(db_dir)
        if not exists(self.db_items):
            mkdir(self.db_items)

    async def hashing_tool(self, og: str):
        try:
            h = new_hmac(self.key, og.encode('utf-8'), sha256)
            data = urlsafe_b64encode(h.digest()).decode('utf-8')
            return str(data).split('=')[0]
        except Exception as e:
            p(e)
            return False

    async def dir_name(self, user_identifier=None):
        if user_identifier:
            self.user_identifier = user_identifier
        self.user_identity = await self.hashing_tool(self.user_identifier)
        if self.user_identity:
            user_file_name = f"{self.db_items}/{str(self.user_identity)}.json"
        return user_file_name

    async def identities(self, user_file_name=None):
        if not self.user_file_name:
            if user_file_name:
                self.user_file_name = user_file_name
            else:
                self.user_file_name = await self.dir_name()
        if self.user_file_name:
            if self.do == "get_user":
                if exists(self.user_file_name):
                    database = []
                    with open(self.user_file_name, 'rb') as f:
                        db = items(f, 'item')
                        for item in db:
                            database.append(item)

                    return ("user_found", database[0])
                else:
                    return (None, None)
                
            elif self.do == "create_user":
                if exists(self.user_file_name):
                    return (None, self.user_file_name)
                else:
                    with open(self.user_file_name, "w") as f:
                        dump([self.user_data], f, indent=4)
                        return ("user_created", self.user_file_name)
            
            elif self.do == "update_user":
                if exists(self.user_file_name) and self.user_data:
                    with open(self.user_file_name, "w") as f:
                        dump([self.user_data], f, indent=4)
                        return ("user_updated", self.user_file_name)
                else:
                    return (None, "user_not_found")
            else:
                return (None, self.user_file_name)

    async def db_actions(self, user_identifier=None, do=None, data=None, user_file_name=None):
        if user_file_name:
            self.user_file_name = user_file_name
        self.og_user_identifier, self.user_identifier, self.do, self.user_data = user_identifier, str(user_identifier), do, data

        job = await self.identities()
        return job
   
class Management:
    def __init__(app) -> None:
        app.db = Database(db_dir='db')
        app.token_lifespan = 1200 # 20 minutes
        app.maximum_sessions = 10

    async def register(app, user_identifier, user_data = None):
        token = await safe.tool([user_identifier])
        safe_data = {
            'user_identifier': user_identifier,
            'user_data': None,
            'sessions': [{
                'auth_key': {
                    'creation_time': await safe.tool([str(dt.now())]),
                    'token': token
                }
            }]
        }
        if user_data:
            safe_data['user_data'] = user_data
        else:
            del safe_data['user_data']

        for item, value in safe_data.items():
            if not isinstance(value, (list, dict, tuple)):
                safe_data[item] = await safe.tool([value])
        
        create_user = await app.db.db_actions(user_identifier=user_identifier, do='create_user', data=safe_data)
        if create_user[0]:
            return (token, {
                'detail': {
                    'auth_key': token
                }
            })
        else:
            return (None, {
                'detail': 'Identity already in our systems, please authenticate'
            })

    async def login(app, user_identifier):
        user = await app.db.db_actions(user_identifier=user_identifier, do='get_user')
        token = await safe.tool([user_identifier])

        if user[0]:
            for index, log in enumerate(user[1]['sessions']):
                created_at = await safe.tool((log['auth_key']['creation_time'],))
                
                created_at_dt = dt.fromisoformat(created_at)
                now = dt.now()
                difference = (now - created_at_dt).total_seconds()
                if difference > app.token_lifespan:
                    del user[1]['sessions'][index]
                                    
            if len(user[1]['sessions']) >= app.maximum_sessions:
                user[1]['sessions'] = []

            auth_key = {
                'auth_key': {
                    'creation_time': await safe.tool([str(dt.now())]),
                    'token': token
                }
            }

            user[1]['sessions'].append(auth_key)
            await app.db.db_actions(user_identifier, 'update_user', data=user[1])

            return (token, {
                'detail': {
                    'auth_key': token
                }
            })

        return (None, {
            'detail': 'not found'
        })

    async def auth_session(app, auth_key):
        token = await safe.tool((auth_key,))
        if not token:
            return (None, {
                'detail': 'Invalid or expired auth_key'
            })
        
        user = await app.db.db_actions(user_identifier=token, do='get_user')
        if not user[0]:
            return (None, {'detail': 'Invalid or expired auth key'})

        for index, log in enumerate(user[1]['sessions']):
            if log['auth_key']['token'] == auth_key:
                created_at = await safe.tool((log['auth_key']['creation_time'],))
                
                created_at_dt = dt.fromisoformat(created_at)
                now = dt.now()
                difference = (now - created_at_dt).total_seconds()
                if difference > app.token_lifespan:
                    del user[1]['sessions'][index]

                    await app.db.db_actions(token, 'update_user', data=user[1])
                    return (None, {
                        'detail':'Invalid or expired auth_key'
                    })

                return (f'Expires in {float(app.token_lifespan) - float(difference)} seconds!', user[1])

        return (None, {
            'detail': 'Invalid or expired auth_key'
        })

manage = Management()

class Middleware:
    def __init__(self, app, comps) -> None:
        self.app = app
        self.comps = comps
        self.db = "db.json"
        self.protected_routes = ["/api/"]
        self.allowed_methods = 'GET, POST'
        self.jwt_token = None
        self.ip = None
        self.request_url = None
        self.user_file_name = None
        self.return_exception = None
        self.allowed_hosts = ["127.0.0.1:8001"]
        self.static_dir = "static/"
        self.protect_data = False

    async def endpoint_validation(self):
        try:
            if not self.auth_key:
                self.return_exception = jsonify({'error': "csrf_middleware is missing from your request."}), 406
            else:
                auth = await manage.auth_session(self.auth_key)
                if not auth[0]:
                    self.return_exception = jsonify({'error': auth[1]}), 403
                    return False
                else:
                    pass
        except Exception as e:
            await logger.log_data(e)
            self.return_exception = jsonify({'error': "Something went wrong"}), 403
        
    async def before_request(self):
        self.auth_key, self.ip, self.user_file_name, self.return_exception, self.req_type, self.take_it_easy = None, None, None, None, request.method, True

        self.ip = request.headers.get("X-Forwarded-For", None)
        if not self.ip:
            self.ip = request.headers.get("X-Forwarded-For", "None")

        self.request_url = str(request.url)
        await logger.log_data(f"Processing request from {self.ip}:>> {self.req_type}@ {self.request_url}")

        host_app = request.headers.get("Host", None)
        if not host_app:
            host_app = request.headers.get("authority", None)
        if not host_app:
            host_app = request.headers.get("Origin", None).replace("https://", "").replace("http://", "")

        self.firewall = 'blocked'
        for domain in self.allowed_hosts:
            if str(host_app).endswith(str(domain)):
                self.firewall = 'allowed'

        if self.firewall == 'blocked':
            return jsonify({'error': "Understandable but i'm not gonna work with that kind of request"}), 406

        for x in self.protected_routes:
            if x in self.request_url:
                self.take_it_easy = False
                break

        if self.req_type not in self.allowed_methods.split(', '):
            return jsonify({'error': "We understand what you're asking for, but we currently do not support this method"}), 407

        if not self.take_it_easy:
            if self.req_type == "GET":
                headers = request.headers
                data = request.args
            elif self.req_type == "POST":
                headers = request.headers

                if 'multipart' in str(headers.get("Content-Type", "Content-Type")):
                    data = headers
                else:
                    data = await request.get_json()
            else:
                return jsonify({'error': "Unexpected server error"}), 500

            self.auth_key =  request.cookies.get('auth_key', None)
            if not self.auth_key:
                self.auth_key =  headers.get('X-auth_key', None)
            if not self.auth_key:
                self.auth_key =  data.get('auth_key', None)

            if not self.auth_key:
                return jsonify({'error': "Authentication required!"}), 409

            await self.endpoint_validation()
            if self.return_exception is not None:
                return self.return_exception
        else:
            pass

    async def after_request(self, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = self.allowed_methods
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['strict-transport-security'] = 'max-age=63072000; includeSubdomains'
        response.headers['x-frame-options'] = 'SAMEORIGIN'
        response.headers['x-xss-protection'] = '1; mode=block'
        response.headers['x-content-type-options'] = 'nosniff'
        response.headers['referrer-policy'] = 'origin-when-cross-origin'
        response.headers['Server'] = "Scarface"
        return response
    
    async def register_middleware(self):
        self.app.before_request(self.before_request)
        self.app.after_request(self.after_request)

class Components:
    def __init__(self, app) -> None:
        self.app = app

    async def get_request_data(self):
        req_type = request.method
        try:
            if req_type == "GET":
                headers = request.headers
                data = request.args

            elif req_type == "POST":
                data = await request.get_json()
                headers = request.headers
            else:
                data = False
                headers = False

            return data, headers
        except Exception as e:
            p(e)
            return False

class Setup:
    def __init__(self) -> None:
        self.app = Quart(__name__)
        self.comps = Components(self.app)
        self.middleware = Middleware(self.app, self.comps)
        self.app.config['UPLOAD_FOLDER'] = None
        self.app.config['MAX_CONTENT_LENGTH'] = 500000 * 1024 * 1024
        self.app.config['REQUEST_TIMEOUT'] = 500000
        self.app.config['QUART_SERVER'] = 'hypercorn'  # Use Hypercorn as the server
        self.app.config['HYPERCORN'] = {
            'keep_alive_timeout': 500000,
            'use_reloader': True
        }

    async def set_app(self):
        set_ = await self.middleware.register_middleware()
        if set_:
            return self.app, self.comps, self.middleware
    
    def main(self):
        asyncrun(self.set_app())
        return self.app, self.comps, self.middleware

setup = Setup()

class Elements:
    def __init__(self, setup):
        self.app, self.comps, self.middleware = setup.main()
    
    async def set_elements(self):
        return self.app, self.comps, self.middleware

elements = Elements(setup)

class Frontend:
    def __init__(self, elements):
        self.app = elements.app
        self.elements = elements
        self.secure_identity_items = [True, False][1]

    async def create_session_data(self, headers):
        try:
            session_data = {"headers": {}}

            for x in headers:
                x_data = await safe.tool([str(x[1])])     
                session_data["headers"].update({str(x[0]): x_data})

            return session_data
        except Exception as e:
            await logger.log_data(e)
            self.return_exception = jsonify({'error': "Something went wrong"}), 500
            return False

    async def serve_static(self, path):
        try:
            return await send_file(self.elements.middleware.static_dir + path)
        except PermissionError as e:
            p(f"Permission error: {e}")
            data = "Ohh no, you're onto something!"
        except FileNotFoundError:
            data = "Not found!"
        except Exception as e:
            p(f"Unexpected error: {e}")
            data = "Not found!"

        return jsonify({'error': data}), 404

    async def serve_pages(self, path="page/404"):
        session_data = await self.create_session_data(request.headers)
        path = str(path)
        self.path = path
        
        if not "page/" in path:
            return jsonify({'error': "The route specified doesn't match the style of our routes."}), 406
        path = path.split("page/")[1]

        while True:
            page_file = f'{self.elements.middleware.static_dir}page/{path}.html'
            if not exists(page_file):
                path = "404"
            else:
                break

        try:
            with open(page_file, 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            if '<!--auth_key-->' in html_content:
                html_content = html_content.replace('<!--auth_key-->', '')

                ip = str(request.headers.get("X-Forwarded-For", None))
                if not ip in ["127.0.0.1", "None"]:
                    identifyer = ip
                else:
                    identifyer = str(request.headers.get("User-Agent", "User-Agent"))

                create_user = await manage.register(identifyer, session_data)
                if create_user[0]:
                    html_content = html_content.replace('<!--app_reg-->', f'<script>document.cookie = "auth_key={create_user[0]}; expires=Thu, 01 Jan 00:00:00 UTC; path=/";</script>')
                else:
                    token = await manage.login(identifyer)
                    if token[0]:
                        html_content = html_content.replace('<!--app_reg-->', f'<script>document.cookie = "auth_key={create_user[0]}; expires=Thu, 01 Jan 00:00:00 UTC; path=/";</script>')
                    else:
                        return jsonify(token[1]), 403
                
        except Exception as e:
            await logger.log_data(e)
            return jsonify({'error': "Something went wrong"}), 500
        
        response = await make_response(html_content)
        return response

    def register_routes(self):
        self.app.add_url_rule('/app_data/<path:path>', 'serve_static', self.serve_static)
        self.app.add_url_rule('/<path:path>', 'serve_pages', self.serve_pages)

frontend = Frontend(elements)

if __name__ == '__main__':
    pass