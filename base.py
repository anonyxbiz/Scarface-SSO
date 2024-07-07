import app

# Authenticated sessions
class Session:
    def __init__(app) -> None:
        app.auth = app.Auth()

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
