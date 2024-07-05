# SSO auth management
from Scarface_core import scar, frontend, elements, manage, safe, dt, logger
from re import search
from httpx import AsyncClient
from random import randint
from asyncio import create_task, run
from os import environ
from hypercorn.asyncio import serve
from hypercorn.config import Config

p = print

app, comps, middleware = elements.app, elements.comps, elements.middleware
frontend.register_routes()

middleware.protected_routes = ["/app/"]
middleware.allowed_hosts = ["127.0.0.1:8001","localhost:8001", "ngrok-free.app"]

class Verification:
    def __init__(app) -> None:
        pass
    async def two_step_verification(app, email, name, ip, ua, verification_url = environ['app_url']):
        try:
            async with AsyncClient() as client:
                verification_code = randint(1000000, 9000000)

                json_data = {
                    'Messages': [
                        {
                            'From': {
                                'Email': f'{environ["mailjet_mail"]}',
                                'Name': f'{environ["mailjet_name"]}',
                            },
                            'To': [
                                {
                                    'Email': email,
                                    'Name': name,
                                },
                            ],
                            'Subject': f'{environ["mailjet_name"]} 2-Step Verification',
                            'TextPart': f'{name}',
                            'HTMLPart': f'''
                                <p>Hello {name},</p>
                                <p>Someone recently tried to log in to your account using -- {ua} -- from ip - {ip}. To help keep your account secure, we need you to verify this was you.</p>

                                <p>Here is your 6-digit verification code: <strong>{verification_code}</strong></p>
                                <p>Please <a href="{verification_url}/auth/login?verification_code={verification_code}&email={email}">click here</a> to validate your account.</p>

                                <p>This verification code will expire in 3 minutes.</p>

                                <p>If you did not try to log in to your account, please ignore this email.</p>

                                <p>Thank you for helping us keep your account secure.</p>

                                <p>Sincerely,<br>
                                The {environ["mailjet_name"]} Team</p>
                            ''',
                        },
                    ],
                }
                
                r = await client.post('https://api.mailjet.com/v3.1/send', headers={'Content-Type': 'application/json'}, json=json_data, auth=(environ['mailjet_api_key'], environ['mailjet_secret_key']))

                if r.status_code <= 300:
                    data = r.json()

                    return (verification_code, data)
                else:
                    p(r.text)
                    return
        except Exception as e:
            create_task(logger.log_data(e))
            return

# Identity Authentication
class Auth:
    def __init__(app) -> None:
        app.min_pwd_length = 8
        app.banned_agents = ['python', 'selenium', 'driver', 'chromedriver']
        app.verify = Verification()
        app.verification_url = 'https://unified-only-walleye.ngrok-free.app'

    # Filter suspicious requests
    async def forensicate(app):
        try:
            for key, value in app.headers.items():
                key, value = str(key), str(value)
                if key == 'User-Agent':
                    for agent in app.banned_agents:
                        if agent in value:
                            app.error = {
                                'detail': 'Our middleware flagged your request, you must be doing something wrong.'
                            }
                            return

            return 'ok'
        except Exception as e:
            create_task(logger.log_data(e))

    async def creds_check(app):
        try:
            if not await app.forensicate():
                return

            if not app.data.get('email', None) or not app.data.get('pwd', None):
                app.error = {
                    'detail': 'Invalid creditials'
                }
                return

            account_data = {
                'email': str(app.data.get('email', None)),
                'pwd': str(app.data.get('pwd', None)),
                'name': str(app.data.get('name', None)),
                'forensic_data': {}
            }

            if not "@" in account_data['email']:
                app.error = {
                    'detail': 'Invalid email'
                }
                return

            if len(account_data['pwd']) < app.min_pwd_length:
                app.error = {
                    'detail': f'Password must be {app.min_pwd_length} characters or more.'
                }
                return

            if not search(r'\d', account_data['pwd']):
                app.error = {
                    'detail': 'Password must contain at least one digit.'
                }
                return

            if not search(r'[!@#$%^&*()_+{}|:"<>?]', account_data['pwd']):
                app.error = {
                    'detail': 'Password must contain at least one symbol.'
                }
                return

            if not search(r'[A-Z]', account_data['pwd']):
                app.error = {
                    'detail': 'Password must contain at least one uppercase letter.'
                }
                return

            account_data['email'] = await safe.tool([account_data['email']])
            account_data['pwd'] = await safe.tool([account_data['pwd']])

            for k, v in app.headers.items():
                if not isinstance(v, (list, tuple)):                    
                    account_data['forensic_data'].update({
                        k: await safe.tool([v])
                    })

            return account_data
        except Exception as e:
            create_task(logger.log_data(e))

    async def two_step_verify(app):
        try:
            login = await manage.login(app.data['email'])
            if not login[0]: return scar.jsonify(login[1]), 403

            get_user_data = await manage.auth_session(login[1]['detail']['auth_key'])

            if not get_user_data[0]: return scar.jsonify(get_user_data[1]), 403

            if await safe.tool((get_user_data[1]['user_data']['email'],)) != app.data['email']:
                return scar.jsonify({'detail': 'Invalid email and or password combination'}), 403

            # Check and verify verification_code
            for i, v in enumerate(get_user_data[1]['verification']):
                if await safe.tool((v['verification_code']['code'],)) == str(app.data.get('verification_code')):
                    created_at = await safe.tool((v['verification_code']['creation_time'],))
                    
                    created_at_dt = dt.fromisoformat(created_at)
                    now = dt.now()
                    difference = (now - created_at_dt).total_seconds()
                    if difference <= 60*3:
                        auth_key = v['verification_code']['auth_key']
                        del get_user_data[1]['verification'][i]

                        await app.two_step_judge(get_user_data[1], login[1]['detail']['auth_key'], 'save')

                        # Run a background task and return auth_key concurrently
                        create_task(manage.db.db_actions(auth_key, 'update_user', data=get_user_data[1]))

                        page_file = f'{elements.middleware.static_dir}page/index.html'

                        with open(page_file, 'r', encoding='utf-8') as file:
                            html_content = file.read()
                        
                        html_content = html_content.replace('<!--app_reg-->', f'<script>document.cookie = "auth_key={auth_key}; expires=Thu, 01 Jan 00:00:00 UTC; path=/";</script>')

                        response = await scar.make_response(html_content)
                        return response
                    else:
                        auth_key = v['verification_code']['auth_key']
                        del get_user_data[1]['verification'][i]

                        create_task(manage.db.db_actions(auth_key, 'update_user', data=get_user_data[1]))
                        return scar.jsonify({
                            'detail': 'Invalid and or expired verification_code'
                        }), 403
            return scar.jsonify({
                'detail': 'Invalid and or expired verification_code'
            }), 403
        except Exception as e:
            create_task(logger.log_data(e))
            return scar.jsonify({'error': "Something went wrong"}), 500

    # Determine if we should ask for 2-step verification or not
    async def two_step_judge(app, identity, auth_key, save=None):
        ip = scar.request.headers.get("X-Forwarded-For") or scar.request.headers.get("X-Real-Ip") or scar.request.headers.get("Remote-Addr")

        if not ip:
            return scar.jsonify({
                'detail': 'We were unable to process your request due to missing or corrupted headers.'
            }), 403

        try:
            if identity['user_data'].get('ip_history', None):
                for i, j in enumerate(identity['user_data']['ip_history']):
                    if await safe.tool((j['ip_info']['ip'],)) == ip:
                        identity['user_data']['ip_history'][i]['ip_info']['used_times'] += 1
                        create_task(manage.db.db_actions(auth_key, 'update_user', data=identity))

                        with open(f'{elements.middleware.static_dir}page/index.html', 'r', encoding='utf-8') as file:
                            html_content = file.read()
                        
                        html_content = html_content.replace('<!--app_reg-->', f'<script>document.cookie = "auth_key={auth_key}; expires=Thu, 01 Jan 00:00:00 UTC; path=/";</script>')

                        response = await scar.make_response(html_content)
                        return response
        except Exception as e:
            create_task(logger.log_data(e))
            return scar.jsonify({'error': "Something went wrong"}), 500

        if save:
            ip_info = {
                'ip_info': {
                    'ip': await safe.tool([ip]),
                    'time': await safe.tool([str(dt.now())]),
                    'used_times': 1,
                }
            }

            if not identity['user_data'].get('ip_history', None):
                identity['user_data'].update({'ip_history': [ip_info]})
            else:
                identity['user_data']['ip_history'].append(ip_info)

            create_task(manage.db.db_actions(auth_key, 'update_user', data=identity))
        return

    async def login(app, data, headers):
        app.data, app.headers, app.error = None, None, None
        if not data or not headers: return scar.jsonify({'detail': 'Prerequisites not met.'}), 400
        app.data, app.headers = data, headers
        if not await app.forensicate(): return scar.jsonify(app.error), 403

        if data.get('verification_code', None):
            response = await app.two_step_verify()
            return response

        login = await manage.login(app.data['email'])
        if not login[0]: return scar.jsonify(login[1]), 403

        get_user_data = await manage.auth_session(login[1]['detail']['auth_key'])

        if not get_user_data[0]: return scar.jsonify(get_user_data[1]), 403

        if await safe.tool((get_user_data[1]['user_data']['email'],)) != app.data['email']:
            return scar.jsonify({'detail': 'Invalid email and or password combination'}), 403

        elif await safe.tool((get_user_data[1]['user_data']['pwd'],)) != app.data['pwd']:
            return scar.jsonify({
                'detail': 'Invalid email and or password combination'
            }), 403

        res = await app.two_step_judge(get_user_data[1], login[1]['detail']['auth_key'])
        if res:
            return res

        verify = await app.verify.two_step_verification(app.data['email'], app.data['email'], scar.request.headers.get("X-Forwarded-For", None), scar.request.headers.get("User-Agent", None))

        if verify:
            verify_code = verify[0]

            verification_code = {
                'verification_code': {
                    'creation_time': await safe.tool([str(dt.now())]),
                    'code': await safe.tool([str(verify_code)]),
                    'auth_key': login[1]['detail']['auth_key']
                }
            }
            if not get_user_data[1].get('verification', None):
                get_user_data[1].update({'verification': [verification_code]})
            else:
                if len(get_user_data[1]['verification']) >= 10:
                    get_user_data[1]['verification'] = []

                get_user_data[1]['verification'].append(verification_code)

            create_task(manage.db.db_actions(user_identifier=login[1]['detail']['auth_key'], do='update_user', data=get_user_data[1]))
            return scar.jsonify({
                'detail': 'Click the link sent to your email to authenticate'
            }), 200

    async def register(app, data, headers):
        app.data, app.headers, app.error = None, None, None
        if not data or not headers: return scar.jsonify({'detail': 'Prerequisites not met.'}), 400

        app.data, app.headers = data, headers
        account_data = await app.creds_check()

        if app.error:
            return scar.jsonify(app.error), 403

        identifier = await safe.tool((account_data['email'],))

        res_data = await manage.register(identifier, user_data=account_data)
        if res_data[0]:
            return scar.jsonify({'detail': 'registration successful.'}), 200
        else:
            return scar.jsonify(res_data[1]), 403

# Authenticated sessions
class Session:
    def __init__(app) -> None:
        app.auth = Auth()

    async def access_user_data(app, data, headers):
        # reset set instance request data and headers
        app.auth.data, app.auth.headers, app.auth.error = None, None, None
        if not data or not headers: return scar.jsonify({'detail': 'Prerequisites not met.'}), 400

        app.auth.data, app.auth.headers = data, headers
        if not await app.auth.forensicate():
            return scar.jsonify(app.auth.error), 403

        # get auth_key from the middleware since it sets it when it verifies it, then use it to get_user data
        get_user_data = await manage.db.db_actions(user_identifier=elements.middleware.auth_key, do=data.get('action', 'get_user'))

        if get_user_data[0]:
            user_data = get_user_data[1]['user_data']
            del user_data['pwd']

            # Decrypt user items
            for k, v in user_data.items():
                if not isinstance(v, (list, tuple, dict)):                    
                    user_data[k] = await safe.tool((v,))
                elif isinstance(v, (dict)):
                    for k2, v2 in v.items():
                        if not isinstance(v2, (list, tuple, dict)):                    
                            user_data[k][k2] = await safe.tool((v2,))

        return scar.jsonify(user_data), 200

session = Session()

@app.route('/', methods=['GET'])
async def index():
    return scar.redirect("/page/login")

# Identity login auth
@app.route('/auth/login', methods=['GET','POST'])
async def login():
    data, headers = await comps.get_request_data()
    response = await session.auth.login(data, headers)
    if response:
        return response

# Identity registration auth
@app.route('/auth/register', methods=['GET','POST'])
async def register():
    data, headers = await comps.get_request_data()
    response = await session.auth.register(data, headers)
    if response:
        return response

# Authenticated route
@app.route('/app/me', methods=['GET','POST'])
async def access_user_data():
    data, headers = await comps.get_request_data()
    response = await session.access_user_data(data, headers)
    if response:
        return response

if __name__ == '__main__':
    # app.run(host="0.0.0.0", port=int(middleware.allowed_hosts[0].split(":")[1]), debug=False)
    config = Config()
    config.bind = [f"0.0.0.0:{int(middleware.allowed_hosts[0].split(":")[1])}"]
    run(serve(app, config))
