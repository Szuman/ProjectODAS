from crypt import methods
from Crypto.Cipher import AES
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
import passlib.hash
from .models import Passwords, User
from .encryption import encrypt, decrypt
from . import db
import re
import time
from datetime import datetime

SLEEP_TIME = 5
MAX_ATTEMPTS = 5

main = Blueprint('main', __name__)

def validate_url(url):
    url_pattern =  '^[a-zA-Z0-9 _\\/-:()!.?,]*$'
    url_regex = re.compile(url_pattern)
    if (re.match(url_regex, url)):
        return False
    return True

def validate_password(password):
    if re.match('^.{,30}$', password):
        return False
    return True

def validate_masterpassword(password):
    if re.match('^.{8,30}$', password):
        return False
    return True

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    user = User.query.filter_by(email=current_user.email).first()
    passwords = Passwords.query.filter_by(user_id = current_user.id).all()
    
    if user.lastlogedAt:
        lastLoged = user.lastlogedAt
        last = lastLoged.strftime("%m/%d/%Y, %H:%M:%S")
    else:
        last ='none'

    if user.lastFailedAttempt:
        failedLogin = user.lastFailedAttempt
        failed = failedLogin.strftime("%m/%d/%Y, %H:%M:%S")
    else:
        failed = 'none'

    return render_template('profile.html', name=current_user.name, passw_list=passwords, last=last, failed=failed)

@main.route('/add', methods=['POST'])
@login_required
def add():
    return redirect(url_for('main.addpassword'))

@main.route('/addpassword')
@login_required
def addpassword():
    return render_template('addpassword.html')

@main.route('/addpassword', methods=["POST"])
@login_required
def addpassword_post():
    if validate_url(request.form.get('url')) or validate_password(request.form.get('new_password')):
        flash('Incorrect data')
        return redirect(url_for('main.addpassword'))
    
    url = request.form.get('url')
    password = request.form.get('new_password')

    thepassword = Passwords.query.filter_by(url=url, user_id=current_user.id).first()

    if thepassword:
        flash('This name/url is already on the list. Please choose another one')
        return redirect(url_for('main.addpassword'))

    user = User.query.filter_by(id=current_user.id).first()

    masterhash = user.masterpassword

    e_password = encrypt(password, masterhash)

    new_password = Passwords(url = url, password = e_password, user_id = current_user.id)

    db.session.add(new_password)
    db.session.commit()
    
    return redirect(url_for('main.profile'))

@main.route('/show', methods=['POST'])
@login_required
def show():
    return redirect(url_for('main.display'))

@main.route('/displaypassword')
@login_required
def display():
    passwords = Passwords.query.filter_by(user_id = current_user.id).all()
    return render_template('showpassword.html', passw_list=passwords)

@main.route('/displaypassword', methods=['POST'])
@login_required
def display_post():
    if validate_masterpassword(request.form.get('masterp')):
        flash('Incorrect data')
        return redirect(url_for('main.display'))

    pname = request.form.get('options')
    if not pname:
        flash('Please choose password to display')
        return redirect(url_for('main.display'))

    masterp = request.form.get('masterp')

    user = User.query.filter_by(id=current_user.id).first()
    masterhash = current_user.email + masterp

    time.sleep(SLEEP_TIME)
    if not passlib.hash.bcrypt.verify(masterhash, current_user.masterpassword):
        att = user.attempts
        user.attempts = att + 1
        if user.attempts == MAX_ATTEMPTS:
            user.lastFailedAttempt = datetime.now()
            db.session.commit()
            flash('You reached your attempts limit. Please wait 10 min before next attempt')
            return redirect(url_for('auth.logout'))
        flash('Wrong Master Password')
        db.session.commit()
        return redirect(url_for('main.display'))

    user.attempts = 0
    db.session.commit()
    return thepassword_decode(pname)

def thepassword_decode(url):
    passw_list = Passwords.query.filter_by(user_id = current_user.id).all()

    thepassword = Passwords.query.filter_by(url=url, user_id=current_user.id).first()

    masterp = current_user.masterpassword

    d_password = decrypt(thepassword.password, masterp)
    password_str = bytes.decode(d_password)
    return render_template('showpassword.html', passw_list=passw_list, url=url, thepassword=password_str)

@main.route('/goback', methods=['POST'])
def goback_post():
    return redirect(url_for('main.profile'))