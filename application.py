


# Web modules/functions
import httplib2
import requests
# SQLAlchemy modules/functions
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError
from db.models import Base, User, Category, Item


from flask import Flask
app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World'
