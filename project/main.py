from crypt import methods
from Crypto.Cipher import AES
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
import passlib.hash
from .models import Passwords, User
from .encryption import encrypt, decrypt
from . import db
import re

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

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    passwords = Passwords.query.filter_by(user_id = current_user.id).all()
    return render_template('profile.html', name=current_user.name, passw_list=passwords)

@main.route('/profile', methods=['POST'])
def profile_post():
    if validate_url(request.form.get('url')) or validate_password(request.form.get('new_password')):
        flash('Incorrect data')
        return redirect(url_for('main.profile'))
    
    url = request.form.get('url')
    password = request.form.get('new_password')

    thepassword = Passwords.query.filter_by(url=url).first()

    if thepassword:
        flash('This name/url is already on the list. Please choose another one')
        return redirect(url_for('main.profile'))

    user = User.query.filter_by(id=current_user.id).first()

    masterp = user.masterpassword

    e_password = encrypt(password, masterp)

    new_password = Passwords(url = url, password = e_password, user_id = current_user.id)

    db.session.add(new_password)
    db.session.commit()
    
    return redirect(url_for('main.profile'))

@main.route('/show', methods=['POST'])
def show():
    url_name = request.form.get('url_name')
    print(url_name)
    return redirect(url_for('main.display', page=url_name))

@main.route('/verify', methods=['GET','POST'])
@login_required
def verify():
        if request.method == 'POST':
            if validate_password(request.form.get('master')):
                flash('Incorrect data')
                return redirect(url_for('main.profile'))
            master = request.form.get('master')
            masterhash = current_user.email + master
            if not passlib.hash.bcrypt.verify(masterhash, current_user.masterpassword):
                flash('Wrong Master Password')
                return redirect(url_for('main.profile'))
            #isverify = true
            return redirect(url_for('main.display'))
        return render_template('masterp.html')

@main.route('/verify', methods=['POST'])
def verify_post():
    return redirect(url_for('main.profile'))

@main.route('/display/<page>')
@login_required
def display(page):
    isverified = 0
    if isverified == 0:
        return redirect(url_for('main.verify'))
    thepassword = Passwords.query.filter_by(url=page).first()
    d_password = decrypt(thepassword.password, current_user.masterpassword) #isverified = false
    return render_template('password.html', url=thepassword.url, password=d_password)

@main.route('/goback', methods=['POST'])
def goback_post():
    return redirect(url_for('main.profile'))