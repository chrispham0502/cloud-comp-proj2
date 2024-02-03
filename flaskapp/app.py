from collections.abc import Mapping, Sequence
from typing import Any
from flask import Flask, render_template, url_for, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisakey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username   = db.Column(db.String(20), nullable=False,unique=True)
  password   = db.Column(db.String(80), nullable=False)
  email      = db.Column(db.String(80), nullable=False)
  first_name = db.Column(db.String(80), nullable=False)
  last_name  = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
  
  username = StringField(validators=[InputRequired(),Length(min=4, max=20)],render_kw={"placeholder":"Username"})
  password = PasswordField(validators=[InputRequired(),Length(min=4, max=20)],render_kw={"placeholder":"Password"})
  email = EmailField(validators=[InputRequired(), Email()],render_kw={"placeholder":"Email"})
  first_name = StringField(validators=[InputRequired()],render_kw={"placeholder":"First Name"})
  last_name = StringField(validators=[InputRequired()],render_kw={"placeholder":"Last Name"})
  
  submit = SubmitField("Register")
  
  def validate_username(self, username):
    existing_username = User.query.filter_by(username = username.data).first()
    if existing_username:
      raise ValidationError("Username taken ")
    
class LoginForm(FlaskForm):
  
  username = StringField(validators=[InputRequired(),Length(min=4, max=20)],render_kw={"placeholder":"Username"})
  password = PasswordField(validators=[InputRequired(),Length(min=4, max=20)],render_kw={"placeholder":"Password"})
  



@app.route("/")
def home():
  return render_template('index.html')


@app.route("/profile", methods=['GET','POST'])
@login_required
def profile():
  
  with open('Limerick.txt', 'r', encoding='utf-8') as file:
    content = file.read()
  # Calculate word count
  word_count = len(content.split())
  return render_template('profile.html', user=current_user, word_count = word_count)

@app.route('/download')
@login_required
def download():
    # Provide the file for download
    return send_file('Limerick.txt', as_attachment=True)

@app.route("/login", methods=['GET','POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user and bcrypt.check_password_hash(user.password, form.password.data):
      login_user(user)
      return redirect(url_for('profile'))
  return render_template('login.html', form = form)


@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
  logout_user()
  return redirect(url_for('home'))

@app.route("/signup", methods=['GET','POST'])
def signup():
  
  form = RegisterForm()
  
  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(username = form.username.data, password=hashed_password,email = form.email.data,first_name=form.first_name.data, last_name=form.last_name.data)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))
    
  return render_template('signup.html', form = form)

if __name__ == "__main__":
  app.run(debug=True)