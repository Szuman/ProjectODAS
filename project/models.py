from enum import unique
from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    auth = db.Column(db.String(100))
    masterpassword = db.Column(db.String(100))
    name = db.Column(db.String(100))
    attempts = db.Column(db.Integer)
    lastloginAt = db.Column(db.DateTime)
    passwords = db.relationship("Passwords", backref = 'user')

class Passwords(db.Model):
    __tablename__ = 'passwords'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(1000), nullable=False, unique=True)
    password = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)