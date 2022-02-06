from flask import Blueprint, render_template, redirect, url_for, request, flash
import passlib.hash
from flask_login import login_user, login_required, logout_user, current_user
import re
from .models import User
from . import db
import time
from datetime import datetime

SLEEP_TIME = 5
MAX_ATTEMPTS = 5
TIMEOUT_PERIOD = 600

auth = Blueprint('auth', __name__)

def validate_email(email):
    url_pattern =  '^[a-zA-Z0-9 _\\.@]{1,}$'
    url_regex = re.compile(url_pattern)
    if re.match(url_regex, email):
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
    
    lastlogin = user.lastFailedAttempt
    if lastlogin:
        timenow = datetime.now()
        diff = timenow - user.lastFailedAttempt
        if diff.seconds < TIMEOUT_PERIOD:
            flash('You reached your attempts limit. Please wait 10 min before next attempt')
            return redirect(url_for('auth.login'))
        if user.attempts >= MAX_ATTEMPTS:
            user.attempts = 0
            db.session.commit()

    auth = email + password

    if not user or not passlib.hash.pbkdf2_sha512.verify(auth, user.auth):
        att = user.attempts
        user.attempts = att + 1
        if user.attempts == MAX_ATTEMPTS:
            user.lastFailedAttempt = datetime.now()
            flash('You reached login attempts limit. Please wait 10 min before next attempt')
            db.session.commit()
            return redirect(url_for('auth.login'))
        flash('Please check your login details and try again.')
        db.session.commit()
        return redirect(url_for('auth.login'))

    login_user(user)
    user.logedNow = datetime.now()
    user.attempts = 0
    db.session.commit()
    return redirect(url_for('main.profile'))

@auth.route('/logout')
@login_required
def logout():
    user = User.query.filter_by(email=current_user.email).first()
    loged = user.logedNow
    user.lastlogedAt = loged
    logout_user()
    db.session.commit()
    return redirect(url_for('auth.login'))