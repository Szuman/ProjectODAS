from nis import match
from flask import Blueprint, render_template, redirect, url_for, request, flash
import passlib.hash
from flask_login import login_user, login_required, logout_user
from password_strength import PasswordPolicy
from password_strength import PasswordStats
import re
from .models import User
from . import db
import time
from datetime import datetime

SLEEP_TIME = 1

auth = Blueprint('auth', __name__)

policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits
    strength=0.5 # need a password that scores at least 0.5 with its entropy bits
)

def validate_email(email):
    url_pattern =  '^[a-zA-Z0-9 _\\.@]*$'
    url_regex = re.compile(url_pattern)
    if re.match(url_regex, email):
        return False
    return True

def validate_username(username):
    if re.match('^[A-Za-z0-9]{1,}$', username):
        return False
    return True

def validate_password(password):
    if re.match('^.{8,30}$', password):
        return False
    return True


@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST']) 
def login_post():
    time.sleep(SLEEP_TIME)
    if validate_email(request.form.get('email')) or validate_password(request.form.get('password')):
        flash('Incorrect data')
        return redirect(url_for('auth.login'))
    
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
    
    lastlogin = user.lastloginAt
    if lastlogin:
        timenow = datetime.now()
        diff = timenow - user.lastloginAt
        if diff.seconds < 600:
            user.lastloginAt = datetime.now()
            flash('You reached login attempts limit. Please wait 10 min before next attempt')
            return redirect(url_for('auth.login'))
        if user.attempts == 6:
            user.attempts = 0
            db.session.commit()


    if not user or not passlib.hash.bcrypt.verify(password, user.password):
        att = user.attempts
        user.attempts = att + 1
        if user.attempts == 6:
            user.lastloginAt = datetime.now()
            flash('You reached login attempts limit. Please wait 10 min before next attempt')
            return redirect(url_for('auth.login'))
        flash('Please check your login details and try again.')
        db.session.commit()
        return redirect(url_for('auth.login'))

    login_user(user)
    user.attempts = 0
    db.session.commit()
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    if validate_email(request.form.get('email')) or validate_password(request.form.get('password')) \
         or validate_username(request.form.get('name')) or validate_password(request.form.get('repeat')):
        flash('Incorrect data')
        return redirect(url_for('auth.signup'))
    
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    reapeated = request.form.get('repeat')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    if password != reapeated:
        flash('Two different passwords was writen')
        return redirect(url_for('auth.signup'))

    stats = PasswordStats(password)
    if stats.strength() < 0.5:
        print(stats.strength())
        flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, attempts=0, password=passlib.hash.bcrypt.using(rounds=16, salt='1234567890098765432112').hash(password))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))