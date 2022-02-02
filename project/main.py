# from Crypto.Cipher import AES
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from .models import Passwords
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

    # key = b'Sixteen byte key'
    # data = bytes(password,'utf-8')

    # e_cipher = AES.new(key, AES.MODE_EAX)
    # e_data = e_cipher.encrypt(data) #Encryption

    # d_cipher = AES.new(key, AES.MODE_EAX, e_cipher.nonce)
    # d_data = d_cipher.decrypt(e_data) Original Message

    # passw = d_data.decode("utf-8") 

    new_password = Passwords(url = url, password = password, user_id = current_user.id)

    db.session.add(new_password)
    db.session.commit()
    
    return redirect(url_for('main.profile'))