# -*- coding: utf-8 -*-
"""

Allows the exporting and importing of reddit preferences.

"""

from flask import Flask, abort, request, redirect
from uuid import uuid4
import requests
import requests.auth
import argparse
import webbrowser
import json
import threading
import time
import logging
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

CLIENT_ID = '7fPE1QshJ4xXmQ'
CLIENT_SECRET = None
REDIRECT_URI = "http://127.0.0.1:65010/authorize_callback"

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

authenticated = False
access_token = None
session = requests.Session()

  
def user_agent():
    return "Reddit Preferences"
    
def base_headers():
    return {"User-Agent": user_agent()}
    
def authenticate():
    auth_url = create_authorization_url()
    print('Please visit the following URL to authenticate your account:')
    print(auth_url)
    webbrowser.open(auth_url)
    
def create_authorization_url():
    state = str(uuid4())
    params = {"client_id": CLIENT_ID,
              "response_type": "code",
              "state": state,
              "redirect_uri": REDIRECT_URI,
              "duration": "temporary",
              "scope": "identity account subscribe read"}
    url = "https://ssl.reddit.com/api/v1/authorize?" + urlencode(params)
    return url
    
def get_access_token(code):
    client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": REDIRECT_URI}
    headers = base_headers()
    response = requests.post("https://ssl.reddit.com/api/v1/access_token",
                             auth=client_auth,
                             headers=headers,
                             data=post_data)
    token = response.json()
    return token["access_token"]

@app.route('/authorize_callback')
def authorize_callback():
    global authenticated, access_token
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not valid_state:
        abort(403)
    code = request.args.get('code')
    access_token = get_access_token(code)
    authenticated = True
    print("Authenticated")
    return 'Authenticated. You can now close this tab.'
    
def valid_state(state):
    if (state == state):
        return True
    else:
        return False

def read_preferences(filename):
    data = None
    with open(filename) as fname:
        data = json.load(fname)
    return data
        
def write_preferences(filename, preferences):
    with open(filename, 'w') as fname:
        json.dump(preferences, fname)
        
def import_preferences(filename):
    preferences = read_preferences(filename)
    
    # Set preferences
    print("Adding Preferences")
    set_preferences(preferences['preferences'])
    
    # Set Friends
    for friend in preferences['friends']['data']['children']:
        print("Adding friend {}".format(friend['name']))
        add_friend(friend['name'])
    
def export_preferences(filename):
    export = {}
    export['preferences'] = get_preferences()
    export['friends'] = get_friends()
    write_preferences(filename, export)
    print("Exported preferences to {}".format(filename))
    

def authenticated_request(method, endpoint, data='{}', extra_headers={}):
    headers = {"Authorization": "bearer " + access_token}
    headers.update(base_headers())
    headers.update(extra_headers)
    response = session.request(method, 'https://oauth.reddit.com/' + endpoint, json=data, headers=headers)
    return response.json()
        

def get_preferences():
    preferences = authenticated_request('GET', 'api/v1/me/prefs')
    return preferences

def set_preferences(prefs):
    preferences = authenticated_request('PATCH', 'api/v1/me/prefs', prefs, extra_headers={"Content-Type": "application/json"})
    return preferences

def get_friends():
    friends = authenticated_request('GET', 'api/v1/me/friends')
    return friends
    
def add_friend(username):
    friend = authenticated_request('PUT', 'api/v1/me/friends/' + username, extra_headers={"Content-Type": "application/json"})
    return friend
    
def get_blocked():
    # /api/v1/me/blocked appears to be broken?
    blocked = authenticated_request('GET', 'api/v1/me/blocked')
    return blocked
    
def flask_run():
    app.run(port=65010)
    
if __name__ == '__main__':
    t = threading.Thread(target=flask_run)
    t.daemon = True
    t.start()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest="file", default="preferences.json", help="File to read/write preferences to.")
    parser.add_argument("-i", "--import", dest="import_prefs", action="store_true", default=False, help="Use -i to import preferences. Defaults to export.")

    args = parser.parse_args()

    authenticate()
    while not authenticated:
        time.sleep(1)

    if args.import_prefs:
        import_preferences(args.file)
    else:
        export_preferences(args.file)