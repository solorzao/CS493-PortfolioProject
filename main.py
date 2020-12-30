from google.cloud import datastore
from flask import Flask, render_template, jsonify, redirect, request, url_for, session, make_response, abort
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests as id_requests
import requests
import constants
import random
import json
import sys

app = Flask(__name__)
client = datastore.Client()
app.secret_key = constants.app_secret_key

CLIENT_ID = constants.client_id
CLIENT_SECRET = constants.client_secret
SCOPE = constants.scope
REDIRECT_URI = constants.redirect_uri

def get_sub_info():
    if 'Authorization' in request.headers:
        user_jwt = request.headers['Authorization']
        user_jwt = user_jwt.replace('Bearer ', '')
        req = id_requests.Request()

        try:
            id_info = id_token.verify_oauth2_token(user_jwt, req, CLIENT_ID)
            sub_info = id_info['sub']
            return sub_info
        except:
            return "Error"
    else:
        return "Error"

def get_results(resultType, cursor, owner=None):
    if resultType == constants.loads:
        query = client.query(kind=resultType)
        results = query.fetch(start_cursor=cursor, limit=5)
        page = next(results.pages)
        resultList = list(page)
        nextCursor = results.next_page_token
    else:
        query = client.query(kind=resultType)
        results = query.fetch(start_cursor=cursor, limit=5)
        query.add_filter("owner", "=", owner)
        page = next(results.pages)
        resultList = list(page)
        nextCursor = results.next_page_token
    return resultList, nextCursor

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/oauth')
def oauth():
    if 'credentials' not in session:
        session['state'] = "randomstate" + str(random.randint(1, 9999999))
        request_url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={session['state']}"
        return redirect(request_url)
    credentials = json.loads(session['credentials'])
    if credentials['expires_in'] <= 0:
        session['state'] = "randomstate" + str(random.randint(1, 9999999))
        request_url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={session['state']}"
        return redirect(request_url)
    else:
        return render_template('oauth.html')
        
@app.route('/userinfo')
def user_info():
    if 'code' not in request.args and 'credentials' not in session:
        return render_template('userinfobad.html', message="Please navigate to the Login tab for authorization first.")
    if 'credentials' in session:
        credentials = json.loads(session['credentials'])
        req = id_requests.Request()
        try:
            id_info = id_token.verify_oauth2_token(credentials['id_token'], req, CLIENT_ID)
            sub_info = id_info['sub']
            return render_template('userinfo.html', jwt_var=credentials['id_token'], sub=sub_info)
        except:
            return (jsonify(Error="Invalid credentials, session may have expired. Please login again."), 401)
    if request.args.get('state') == session.get('state'):
        auth_code = request.args.get('code')
        data = {'code': auth_code,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'}
        res = requests.post(
            'https://oauth2.googleapis.com/token', data=data)
        session['credentials'] = res.text
        credentials = json.loads(session['credentials'])
        req = id_requests.Request()
        try:
            id_info = id_token.verify_oauth2_token(credentials['id_token'], req, CLIENT_ID)
            sub_info = id_info['sub']
            query = client.query(kind=constants.users)
            results = list(query.fetch())

            user_exists = False

            for e in results:
                if e['user_id'] == sub_info:
                    user_exists = True

            if user_exists == False:
                credentials = json.loads(session['credentials'])
                headers = {'Authorization': 'Bearer {}'.format(credentials['access_token'])}
                req_uri = 'https://people.googleapis.com/v1/people/me?personFields=names'
                res = requests.get(req_uri, headers=headers)
                user_info = json.loads(res.text)
                user_info = user_info['names']
                user_last_name = user_info[0]['familyName']
                user_first_name = user_info[0]['givenName']
                
                new_user = datastore.entity.Entity(key=client.key(constants.users))
                new_user.update({"user_id": sub_info, "First Name": user_first_name, "Last Name":user_last_name})               
                client.put(new_user)

            return render_template('userinfo.html', jwt_var=credentials['id_token'], sub=sub_info)
        except:
            return (jsonify(Error="Missing or invalid JWT"), 401)
    else:
        return (jsonify(Error="Session states did not match"), 400)

@app.route('/users', methods=['GET'])
def users_get():
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            query = client.query(kind=constants.users)
            results = list(query.fetch())
            return (json.dumps(results), 200)
        else:
            return (jsonify(Error="Response not acceptable"), 406)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        try:
            content = request.get_json()
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({"name": content["name"], "type": content["type"],
                             "length": content["length"], "loads": None})

            owner = get_sub_info()

            if owner != "Error":
                new_boat.update({"owner": owner})
                client.put(new_boat)

                new_boat["id"] = new_boat.key.id
                new_boat["self"] = (
                    f"{request.url}/" + str(new_boat["id"]))
                return (json.dumps(new_boat), 201)
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)
        except:
            return (jsonify(Error="The request object is missing at least one of the required attributes"), 400)
    elif request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        owner = get_sub_info()

        if owner != "Error":
            pass
        else:
            return (jsonify(Error="Missing or invalid JWT"), 401)

        cursor = None
        results, nextCursor = get_results(constants.boats, cursor, owner)

        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", owner)
        boat_list = list(query.fetch())
        total_count = len(boat_list)

        for result in results:
            if result["loads"] != None:
                loads = json.loads(result["loads"])
                for load in loads:
                    self_url = f"{request.url}/" + str(load["id"])
                    load["self"] = self_url.replace("boats", "loads")
                result["loads"] = loads
            result["id"] = result.key.id
            result["self"] = (
                f"{request.url}/" + str(result["id"]))
        if len(results) < 5:
            query = client.query(kind=constants.boats)
            query.add_filter("owner", "=", owner)
            boat_list = list(query.fetch())
            
            total_count = len(boat_list)

            res = {}
            loads = json.dumps(results)
            res["boats"] = json.loads(loads)
            res["total boats in collection"] = total_count
            return (json.dumps(res), 200)
        else:
            if nextCursor != None:
                res = {}
                boats = json.dumps(results)
                res["boats"] = json.loads(boats)
                next_url = (f"{request.url}/results/" +
                            str(nextCursor, 'UTF-8'))
                res["next"] = next_url
                res["total boats in collection"] = total_count
                return (json.dumps(res), 200)
            else:
                return (json.dumps(results), 200)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/boats/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def boat_get_put_patch_delete(id):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)
        boat_key = client.key(constants.boats, int(id))
        query = client.query(kind=constants.boats)
        query.key_filter(boat_key, '=')
        results = list(query.fetch())
        if len(results) == 0:
            return (jsonify(Error="No boat with this boat_id exists"), 404)
        else:
            owner = get_sub_info()

            if owner != "Error":
                pass
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)

            for e in results:
                if e["owner"] != owner:
                    return (jsonify(Error="The boat associated with this ID is owned by someone else, it can only be retrieved by the owner."), 403)
            
            for result in results:
                if result["loads"] != None:
                    loads = json.loads(result["loads"])
                    for load in loads:
                        self_url = f"{request.url}/" + str(load["id"])
                        load["self"] = self_url.replace(f"boats/{id}", "loads")
                    result["loads"] = loads
                result["id"] = result.key.id
                result["self"] = (
                    f"{request.url}")
        return (json.dumps(results[0]), 200)
    elif request.method == 'PUT':
        if request.content_type == 'application/json':
            content = request.get_json()
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat is None:
                return (jsonify(Error="No boat with this boat_id exists"), 404)
            else:
                try:
                    owner = get_sub_info()

                    if owner != "Error":
                        pass
                    else:
                        return (jsonify(Error="Missing or invalid JWT"), 401)

                    if boat["owner"] != owner:
                        return (jsonify(Error="The boat associated with this ID is owned by someone else, it can only be modified by the owner."), 403)
                    
                    boat.update({"name": content["name"], "type": content["type"],
                                 "length": content["length"]})
                    
                    client.put(boat)
                    
                    boat["id"] = boat.key.id
                    boat["self"] = (f"{request.url}")

                    if 'application/json' in request.accept_mimetypes:
                        res = make_response()
                        res.headers.set('Location', f'{boat["self"]}')
                        res.status_code = 303
                        return res
                    else:
                        return (jsonify(Error="Response not acceptable"), 406)
                except:
                    return (jsonify(Error="The request object is missing at least one of the required attributes"), 400)
        else:
            return (jsonify(Error="Bad request, data must be in JSON format"), 415)
    elif request.method == 'PATCH':
        if request.content_type == 'application/json':
            content = request.get_json()
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat is None:
                return (jsonify(Error="No boat with this boat_id exists"), 404)
            else:
                owner = get_sub_info()

                if owner != "Error":
                    pass
                else:
                    return (jsonify(Error="Missing or invalid JWT"), 401)

                if boat["owner"] != owner:
                        return (jsonify(Error="The boat associated with this ID is owned by someone else, it can only be modified by the owner."), 403)
                
                boat.update({"name": content["name"], "type": content["type"],
                             "length": content["length"]})
                
                client.put(boat)

                boat["id"] = boat.key.id
                boat["self"] = (f"{request.url}")

                if 'application/json' in request.accept_mimetypes:
                    return (json.dumps(boat), 200)
                else:
                    return (jsonify(Error="Response not acceptable"), 406)
        else:
            return (jsonify(Error="Bad request, data must be in JSON format"), 415)
    elif request.method == 'DELETE':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        boat_key = client.key(constants.boats, int(id))
        query = client.query(kind=constants.boats)
        query.key_filter(boat_key, '=')
        results = list(query.fetch())
        if len(results) == 0:
            return (jsonify(Error="No boat with this boat_id exists"), 404)
        else:
            owner = get_sub_info()

            if owner != "Error":
                pass
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)

            for e in results:
                if e["owner"] != owner:
                    return (jsonify(Error="The boat associated with this ID is owned by someone else, it can only be deleted by the owner."), 403)
            
            for result in results:
                if result["loads"] != None:
                    loads = json.loads(result["loads"])
                    for load in loads:
                        load_key = client.key(constants.loads, load["id"])
                        load = client.get(key=load_key)
                        load["carrier"] = None
                        client.put(load)
                client.delete(boat_key)
            return ('', 204)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/boats/<id>/loads', methods=['GET'])
def boat_loads_get(id):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)
        boat_key = client.key(constants.boats, int(id))
        query = client.query(kind=constants.boats)
        query.key_filter(boat_key, '=')
        results = list(query.fetch())
        if len(results) == 0:
            return (jsonify(Error="No boat with this boat_id exists"), 404)
        else:
            owner = get_sub_info()

            if owner != "Error":
                pass
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)
            
            for e in results:
                if e["owner"] != owner:
                    return (jsonify(Error="The boat associated with this ID is owned by someone else, its info can only be retrieved by the owner."), 403)
            
            loads = {}
            loads = json.loads(results[0]['loads'])
            for load in loads:
                self_url = f"{request.url}/" + str(load["id"])
                load["self"] = self_url.replace(f"boats/{id}/", "")
            return (json.dumps(loads), 200)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/boats/results/<cursor>', methods=['GET'])
def boats_get(cursor):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        if cursor != None:
            try:
                owner = get_sub_info()

                if owner != "Error":
                    pass
                else:
                    return (jsonify(Error="Missing or invalid JWT"), 401)

                results, nextCursor = get_results(constants.boats, cursor, owner)

                for result in results:
                    if result["loads"] != None:
                        loads = json.loads(result["loads"])
                        for load in loads:
                            self_url = f"{request.url}/" + str(load["id"])
                            self_url = self_url.replace("%3D%3D", "==")
                            load["self"] = self_url.replace(
                                f"boats/results/{cursor}", "loads")
                        result["loads"] = loads
                    result["id"] = result.key.id
                    self_url = (
                        f"{request.url}")
                    self_url = self_url.replace("%3D%3D", "==")
                    self_url = self_url.replace("/results", "")
                    self_url = self_url.replace(cursor, str(result.key.id))
                    result["self"] = self_url
                if len(results) < 5:
                    query = client.query(kind=constants.boats)
                    query.add_filter("owner", "=", owner)
                    boat_list = list(query.fetch())
                    
                    total_count = len(boat_list)

                    res = {}
                    loads = json.dumps(results)
                    res["boats"] = json.loads(loads)
                    res["total boats in collection"] = total_count
                    return (json.dumps(res), 200)
                else:
                    if nextCursor != None:
                        query = client.query(kind=constants.boats)
                        query.add_filter("owner", "=", owner)
                        boat_list = list(query.fetch())
                        
                        total_count = len(boat_list)

                        res = {}
                        boats = json.dumps(results)
                        res["boats"] = json.loads(boats)
                        next_url = f"{request.url}"
                        next_url = next_url.replace("%3D%3D", "==")
                        next_url = next_url.replace(
                            cursor, str(nextCursor, 'UTF-8'))
                        res["next"] = next_url
                        res["total boats in collection"] = total_count
                        return (json.dumps(res), 200)
                    else:
                        return (json.dumps(results), 200)
            except:
                return (jsonify(Error="Invalid cursor provided"), 400)
        else:
            return (jsonify(Error="Cursor provided is null"), 400)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        try:
            content = request.get_json()
            new_load = datastore.entity.Entity(key=client.key(constants.loads))
            new_load.update({"weight": content["weight"], "carrier": None,
                             "content": content["content"], "delivery_date": content["delivery_date"]})
            client.put(new_load)
            new_load["id"] = new_load.key.id
            new_load["self"] = (
                f"{request.url}/" + str(new_load["id"]))
            return (json.dumps(new_load), 201)
        except:
            return (jsonify(Error="The request object is missing at least one of the required attributes"), 400)
    elif request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        cursor = None
        results, nextCursor = get_results(constants.loads, cursor)

        query = client.query(kind=constants.loads)
        load_list = list(query.fetch())
        total_count = len(load_list)

        for result in results:
            if result["carrier"] != None:
                carrier = json.loads(result["carrier"])
                carrier_url = f"{request.url}/" + str(carrier["id"])
                carrier_url = carrier_url.replace("loads", "boats")
                carrier["self"] = carrier_url
                result["carrier"] = carrier
            result["id"] = result.key.id
            result["self"] = (
                f"{request.url}/" + str(result["id"]))
        if len(results) < 5:
            query = client.query(kind=constants.loads)
            load_list = list(query.fetch())
            total_count = len(load_list)
            res = {}
            loads = json.dumps(results)
            res["loads"] = json.loads(loads)
            res["total loads in collection"] = total_count
            return (json.dumps(res), 200)
        else:
            if nextCursor != None:
                res = {}
                loads = json.dumps(results)
                res["loads"] = json.loads(loads)
                next_url = (f"{request.url}/results/" +
                            str(nextCursor, 'UTF-8'))
                res["next"] = next_url
                res["total loads in collection"] = total_count
                return (json.dumps(res), 200)
            else:
                return (json.dumps(results), 200)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/loads/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def load_get_put_patch_delete(id):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        load_key = client.key(constants.loads, int(id))
        query = client.query(kind=constants.loads)
        query.key_filter(load_key, '=')
        results = list(query.fetch())
        if len(results) == 0:
            return (jsonify(Error="No load with this load_id exists"), 404)
        else:
            for result in results:
                if result["carrier"] != None:
                    carrier = json.loads(result["carrier"])
                    carrier_url = f"{request.url}/" + str(carrier["id"])
                    carrier_url = carrier_url.replace(f"loads/{id}", "boats")
                    carrier["self"] = carrier_url
                    result["carrier"] = carrier
                result["id"] = result.key.id
                result["self"] = (
                    f"{request.url}")
        return (json.dumps(results[0]), 200)
    elif request.method == 'PUT':
        if request.content_type == 'application/json':
            content = request.get_json()
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            if load is None:
                return (jsonify(Error="No load with this load_id exists"), 404)
            else:
                try:
                    load.update({"weight": content["weight"], "content": content["content"],
                                     "delivery_date": content["delivery_date"]})
                    client.put(load)
                    load["id"] = load.key.id
                    load["self"] = (f"{request.url}")

                    if 'application/json' in request.accept_mimetypes:
                        res = make_response()
                        res.headers.set('Location', f'{load["self"]}')
                        res.status_code = 303
                        return res
                    else:
                        return (jsonify(Error="Response not acceptable"), 406)
                except:
                    return (jsonify(Error="The request object is missing at least one of the required attributes"), 400)
        else:
            return (jsonify(Error="Bad request, data must be in JSON format"), 415)
    elif request.method == 'PATCH':
        if request.content_type == 'application/json':
            content = request.get_json()
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            if load is None:
                return (jsonify(Error="No load with this load_id exists"), 404)
            else:
                load.update({"weight": content["weight"], "content": content["content"],
                    "delivery_date": content["delivery_date"]})
                client.put(load)

                load["id"] = load.key.id
                load["self"] = (
                    f"{request.url}")

                if 'application/json' in request.accept_mimetypes:
                    return (json.dumps(load), 200)
                else:
                    return (jsonify(Error="Response not acceptable"), 406)
        else:
            return (jsonify(Error="Bad request, data must be in JSON format"), 415)
    elif request.method == 'DELETE':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        load_key = client.key(constants.loads, int(id))
        query = client.query(kind=constants.loads)
        query.key_filter(load_key, '=')
        results = list(query.fetch())
        if len(results) == 0:
            return (jsonify(Error="No load with this load_id exists"), 404)
        else:
            for result in results:
                if result["carrier"] != None:
                    carrier = json.loads(result["carrier"])
                    boat_key = client.key(constants.boats, carrier["id"])
                    boat = client.get(key=boat_key)
                    all_loads = json.loads(boat["loads"])
                    for load in all_loads:
                        if load["id"] == load_key.id:
                            all_loads.remove(load)

                    if len(all_loads) == 0:
                        boat.update({"loads": None})
                    else:
                        all_loads = json.dumps(all_loads)
                        boat.update({"loads": all_loads})

                    client.put(boat)
                client.delete(load_key)
        return ('', 204)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/loads/results/<cursor>', methods=['GET'])
def loads_get(cursor):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        if cursor != None:
            try:
                results, nextCursor = get_results(constants.loads, cursor)
                for result in results:
                    if result["carrier"] != None:
                        carrier = json.loads(result["carrier"])
                        carrier_url = f"{request.url}/" + str(carrier["id"])
                        carrier_url = carrier_url.replace("%3D%3D", "==")
                        carrier_url = carrier_url.replace(
                            f"loads/results/{cursor}", "boats")
                        carrier["self"] = carrier_url
                        result["carrier"] = carrier
                        result["carrier"] = carrier
                    result["id"] = result.key.id
                    self_url = (
                        f"{request.url}")
                    self_url = self_url.replace("%3D%3D", "==")
                    self_url = self_url.replace("/results", "")
                    self_url = self_url.replace(cursor, str(result.key.id))
                    result["self"] = self_url
                if len(results) < 5:
                    query = client.query(kind=constants.loads)
                    load_list = list(query.fetch())
                    total_count = len(load_list)
                    res = {}
                    loads = json.dumps(results)
                    res["loads"] = json.loads(loads)
                    res["total loads in collection"] = total_count
                    return (json.dumps(res), 200)

                else:
                    if nextCursor != None:
                        query = client.query(kind=constants.loads)
                        load_list = list(query.fetch())
                        total_count = len(load_list)

                        res = {}
                        loads = json.dumps(results)
                        res["loads"] = json.loads(loads)
                        next_url = f"{request.url}"
                        next_url = next_url.replace("%3D%3D", "==")
                        next_url = next_url.replace(
                            cursor, str(nextCursor, 'UTF-8'))
                        res["next"] = next_url
                        res["total loads in collection"] = total_count
                        return (json.dumps(res), 200)
                    else:
                        return (json.dumps(results), 200)
            except:
                return (jsonify(Error="Invalid cursor provided"), 400)
        else:
            return (jsonify(Error="Cursor provided is null"), 400)
    else:
        return (jsonify(Error="Method not allowed"), 405)


@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boats_loads_put_delete(boat_id, load_id):
    if request.method == 'PUT':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        
        if boat is not None:
            load_key = client.key(constants.loads, int(load_id))
            load = client.get(key=load_key)
            if load is None:
                return (jsonify(Error="The specified boat and/or load does not exist"), 404)
            query = client.query(kind=constants.loads)  # get load object
            query.key_filter(load_key, '=')
            load_entity = list(query.fetch())

            query = client.query(kind=constants.boats)  # get boat object
            query.key_filter(boat_key, '=')
            boat_entity = list(query.fetch())
            
            owner = get_sub_info()

            if owner != "Error":
                pass
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)

            if boat_entity[0]["owner"] != owner:
                    return (jsonify(Error="The boat associated with this ID is owned by someone else, its loads can only be modified by the owner."), 403)

            if load_entity[0]["carrier"] == None:
                boat_info = {}  # add boat info to load
                boat_info["name"] = boat_entity[0]["name"]
                boat_info["id"] = boat.key.id
                boat_info = json.dumps(boat_info)
                load_entity[0].update({"carrier": boat_info})
                client.put(load_entity[0])

                # add load info to boat
                if boat_entity[0]["loads"] != None:
                    all_loads = json.loads(boat_entity[0]["loads"])
                else:
                    all_loads = []

                load_info = {}
                load_info["id"] = load.key.id
                all_loads.append(load_info)
                all_loads = json.dumps(all_loads)
                boat_entity[0].update({"loads": all_loads})
                client.put(boat_entity[0])

                return ('', 204)
            else:
                return (jsonify(Error="The current load is already assigned to a boat"), 403)

        else:
            return (jsonify(Error="The specified boat and/or load does not exist"), 404)

    elif request.method == 'DELETE':
        if 'application/json' in request.accept_mimetypes:
            pass
        else:
            return (jsonify(Error="Response not acceptable"), 406)

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is not None:
            load_key = client.key(constants.loads, int(load_id))
            load = client.get(key=load_key)
            if load is None:
                return (jsonify(Error="The specified boat and/or load does not exist"), 404)
            query = client.query(kind=constants.loads)  # get load object
            query.key_filter(load_key, '=')
            load_entity = list(query.fetch())

            query = client.query(kind=constants.boats)  # get boat object
            query.key_filter(boat_key, '=')
            boat_entity = list(query.fetch())
            
            owner = get_sub_info()

            if owner != "Error":
                pass
            else:
                return (jsonify(Error="Missing or invalid JWT"), 401)

            if boat_entity[0]["owner"] != owner:
                return (jsonify(Error="The boat associated with this ID is owned by someone else, its loads can only be removed by the owner."), 403)

            if load_entity[0]["carrier"] != None:
                try:
                    boat_info = {}  # remove boat info from load
                    boat_info["name"] = boat_entity[0]["name"]
                    boat_info["id"] = boat.key.id
                    boat_info = json.dumps(boat_info)
                    load_entity[0].update({"carrier": None})

                    # remove load info from boat
                    if boat_entity[0]["loads"] != None:
                        all_loads = json.loads(boat_entity[0]["loads"])
                    else:
                        all_loads = []

                    for load in all_loads:
                        if load["id"] == load_key.id:
                            all_loads.remove(load)

                    if len(all_loads) == 0:
                        boat_entity[0].update({"loads": None})
                    else:
                        all_loads = json.dumps(all_loads)
                        boat_entity[0].update({"loads": all_loads})

                    client.put(boat_entity[0])
                    client.put(load_entity[0])
                    return ('', 204)
                except:
                    return (jsonify(Error="The current load is not assigned to this boat"), 403)
            else:
                return (jsonify(Error="The specified boat and/or load does not exist"), 404)

        else:
            return (jsonify(Error="The specified boat and/or load does not exist"), 404)
    else:
        return (jsonify(Error="Method not allowed"), 405)

@ app.route('/about')
def about():
    return render_template('about.html')

@ app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)
   
