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

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return{
            'id': self.id,
            'email': self.email,
            'name': self.name,
        }

class Note(Base):

    __tablename__ = 'note'

    id = Column(Integer, primary_key = True)
    title = Column(String(250), nullable = False)
    text = Column(TEXT, nullable = True)
