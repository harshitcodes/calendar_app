from datetime import datetime

# sqlalchemy modules/functions
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# project models
from models import Base, User, Note

# create engine to existing db and bind to it
engine = create_engine('sqlite:///calendar.db')
Base.metadata.bind = engine

# create a DBSession instance for reflecting changes to db
DBSession = sessionmaker(bind=engine)
session = DBSession()

# methods to populate the Database


def addUser(email, name, pic_url, location):
    '''add a user to the db'''
    user = User(email=email, name=name, profile_pic=pic_url, location=location)
    session.add(user)
    session.commit()
    print("added user: {}".format(user.id))
    return user


def addNote(title, description, date, user_id, shared_user_id):
    '''add a note to the db'''
    datetime_obj = datetime.strptime(date, '%b %d %Y %I:%M%p')
    note = Note(timestamp=datetime.now(), title = title, text=description, date_time = datetime_obj, \
                author_id=user_id, shared_users_id=shared_user_id
                )
    session.add(note)
    session.commit()
    print('added item: %s' % note.id)
    return note


# delete all data in the db first
session.query(User).delete()
session.query(Note).delete()
print('deleted all data in db')
print()

# add test user
user1 = addUser('test@test.com', 'Test', 'test.png', 'Boston')
user2 = addUser('test2@test.com', 'Test2', 'test2.png', 'New Delhi')
# print(user1.id  "added")


# add test categories
baseball = addNote('Baseball', "Buy new basketball tomorrow", 'Jul 8 2017 1:30PM', user1.id, user2.id)
print()
