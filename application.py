
# Web modules/functions
import httplib2
import requests
import os
from datetime import datetime
import random
import string
import json
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Flask modules/funct
from flask import Flask, render_template, abort, request, redirect, url_for,\
                jsonify, flash, make_response
from flask import session as login_session

# Authentication modules/functions
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

# SQLAlchemy modules/functions
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError
from db.models import Base, User, Note


from flask import Flask
app = Flask(__name__)


engine = create_engine('sqlite:///db/calendar.db')
Base.metadata.bind = engine

# create a DBSession instance for reflecting changes to db
DBSession = sessionmaker(bind=engine)
session = DBSession()

# client id retreival
with open('client_secrets.json', 'r') as f:
    client_web_data_json = json.loads(f.read())['web']
    CLIENT_ID = client_web_data_json['client_id']

# login view
@app.route('/login')
def show_login():
    """
    shows the login page
    """

    if 'gplus_id' in login_session:
        return redirect(url_for('home'))

    # Create anti-forgery state token(csrf token)
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    # storing in  the session for verification ahead
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    print("Get request")
    return render_template('login.html', STATE=state)


# google connect method
@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''
    Uses google authentication
    '''
    # access token validation
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # retrieving authorization code
    code = request.data

    try:
        # from authorization code into a credential object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # access token validation
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)  # noqa
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # if there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    print(login_session['email'])
    if not user_id:
        print("no id")
        user_id = createUser(login_session)
        login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/logout')
def logout():
    """
    Log out of current session
    """
    if "gplus_id" in login_session:
        print("in logout")
        return redirect(url_for('gdisconnect'))
    else:
        return redirect(url_for('main'))


@app.route('/logout/google')
def gdisconnect():
    """
    Log user out of google plus session
    """
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print("============================")
    print(login_session['email'])

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('main'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(current_login_session):
    """
    Create New User
    :param current_login_session:
    :return: new user's id
    """
    new_user = User(name=current_login_session['username'],
                    email=current_login_session['email'],
                    profile_pic=current_login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=current_login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/main')
def main():
    """
    Page to show if a user is not logged in.
    """
    return render_template('main.html')

# @app.route('/home')
@app.route('/')
def home():
    if 'username' not in login_session:
        return redirect('/login')
    logged_in_user_id = getUserID(login_session.get('email'))
    print(logged_in_user_id)
    return render_template('home.html', logged_in_user_id = logged_in_user_id)

if __name__ == '__main__':
    app.secret_key = "thisismysupersecret"
    app.debug = True
    app.run(host='127.0.0.1', port=8000)
