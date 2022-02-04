from flask import Blueprint, render_template, redirect, url_for, request, flash
import passlib.hash
from password_strength import PasswordPolicy
from password_strength import PasswordStats
import re
from . import db
from .models import User

register = Blueprint('register', __name__)

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

@register.route('/signup')
def signup():
    return render_template('signup.html')

@register.route('/signup', methods=['POST'])
def signup_post():
    if validate_email(request.form.get('email')) or validate_password(request.form.get('password')) \
         or validate_username(request.form.get('name')) or validate_password(request.form.get('repeat')) \
             or validate_password(request.form.get('master')) or validate_password(request.form.get('repeat_master')):
        flash('Incorrect data')
        return redirect(url_for('register.signup'))
    
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    reapeated = request.form.get('repeat')
    master = request.form.get('master')
    reapeated_master = request.form.get('repeat_master')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists')
        return redirect(url_for('register.signup'))

    if password != reapeated:
        flash('Two different passwords was writen')
        return redirect(url_for('register.signup'))

    if master != reapeated_master:
        flash('Two different master passwords was writen')
        return redirect(url_for('register.signup'))

    stats = PasswordStats(password)
    if stats.strength() < 0.5:
        print(stats.strength())
        flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
        return redirect(url_for('register.signup'))

    stats = PasswordStats(master)
    if stats.strength() < 0.5:
        print(stats.strength())
        flash("Master Password not strong enough. Avoid consecutive characters and easily guessed words.")
        return redirect(url_for('register.signup'))

    auth = passlib.hash.bcrypt.using(rounds=16, salt='1234567890098765432112').hash(email + password)
    masterpassword = passlib.hash.bcrypt.using(rounds=16, salt='1234567890098765432112').hash(email + master)
    new_user = User(email=email, name=name, attempts=0, auth=auth, masterpassword=masterpassword)

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))