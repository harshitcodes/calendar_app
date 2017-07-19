'''

Author: Harshit Tyagi
Models to create Calendar Database schema
'''


# SQLAlchemy packages import==========
from sqlalchemy import Integer, String, DateTime, Column, ForeignKey, TEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# Base Class instance
Base = declarative_base()

# Models for the applciation

class User(Base):
    '''
    User class so that every user has his/her
    own instance of the Calendar and share it
    with other users.
    '''

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    name = Column(String(250), nullable=False)
    profile_pic = Column(String(250))
    country_code = Column(String(2))  # to convert note datetime as per the shared_user timezone

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return{
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'picture': self.profile_pic,
        }


class Note(Base):

    __tablename__ = 'note'

    id = Column(Integer, primary_key = True)
    timestamp = Column(DateTime, nullable = False)
    date_time = Column(DateTime, nullable = False)
    title = Column(TEXT, nullable = False)
    text = Column(String(250))
    author_id = Column(Integer, ForeignKey('user.id'), nullable = False)
    shared_users_id = Column(Integer, ForeignKey('user.id'))
    author = relationship('User', foreign_keys="Note.author_id")
    shared_users = relationship('User', foreign_keys="Note.shared_users_id")

    @property
    def serialize(self):
        return{
            'timestamp': self.timestamp,
            'note_id': self.id,
            'title': self.title,
            'text': self.text,
            'author_id': self.author_id,
            'user': self.user,
        }


if __name__ == '__main__':
    from sqlalchemy import create_engine
    engine = create_engine('sqlite:///calendar.db')
    Base.metadata.create_all(engine)
