from flask import current_app, Blueprint, render_template, url_for, flash, redirect, request
from flask_bcrypt import Bcrypt
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import logging
from .models import User, db
from sqlalchemy.exc import OperationalError, IntegrityError
from time import sleep
from PIL import Image
import secrets
from .forms import UpdateAccountForm

bcrypt = Bcrypt()
main = Blueprint('main', __name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/images', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

def retry_on_lock(session, max_retries=5, retry_interval=0.1):
    retries = 0
    while retries < max_retries:
        try:
            session.commit()
            break
        except OperationalError as e:
            if 'database is locked' in str(e):
                session.rollback()
                retries += 1
                sleep(retry_interval)
            else:
                raise
    else:
        raise RuntimeError(f"Could not commit session after {max_retries} retries due to database locks")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        image_file = request.files.get('image_file')
        stocks = request.form.get('stocks', '')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # 检查邮箱是否已经存在
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered.', 'danger')
            return redirect(url_for('main.register'))

        # 设置默认图像文件
        image_filename = 'default.jpg'

        # 确定保存路径，并检查文件是否允许上传
        if image_file and allowed_file(image_file.filename):
            image_filename = save_picture(image_file)
        else:
            logging.debug("No image uploaded or invalid file type. Using default.jpg")

        user = User(username=username, email=email, password=hashed_password, image_file=image_filename, stocks=stocks)
        db.session.add(user)
        try:
            retry_on_lock(db.session)
            flash('Your account has been created! You can now log in', 'success')
            return redirect(url_for('main.login'))
        except IntegrityError as e:
            db.session.rollback()
            logging.error(f"IntegrityError: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('main.register'))

    return render_template('register.html')

@main.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful.', 'success')

            # 获取 next 参数，如果没有则默认重定向到主页
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@main.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route("/")
@main.route("/home")
def home():
    return render_template('index.html')

@main.route("/profile")
@login_required
def profile():
    return render_template('profile.html')

@main.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('main.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='images/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)