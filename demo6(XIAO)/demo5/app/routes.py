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



from flask import Blueprint, render_template, request, redirect, url_for, current_app
import pandas as pd
import numpy as np
import yfinance as yf
from datetime import datetime, timedelta
from scipy.optimize import minimize
import os
import matplotlib
import uuid  # 导入 uuid 模块
matplotlib.use('Agg')
import matplotlib.pyplot as plt

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('index.html')

@main.route('/new_page', methods=['GET', 'POST'])
def new_page():
    if request.method == 'POST':
        tickers = [ticker.strip() for ticker in request.form.get('tickers').split(',')]
        score = int(request.form.get('score'))
        portfolio_weights, explanation = recommend_portfolio(tickers, score)

        # 调试信息
        print(f"Tickers: {tickers}")
        print(f"Score: {score}")
        print(f"Portfolio Weights: {portfolio_weights}")
        print(f"Explanation: {explanation}")

        # 生成唯一的文件名
        unique_filename = f"portfolio_{uuid.uuid4().hex}.png"
        plt_path = os.path.join(current_app.root_path, 'static/images', unique_filename)
        plot_weights(portfolio_weights, tickers, plt_path)
        # 调试信息
        print(f"Saved plot to {plt_path}")

        portfolio_weights = {ticker: f"{weight*100:.2f}" for ticker, weight in zip(tickers, portfolio_weights)}

        return render_template('new_page.html', portfolio_weights=portfolio_weights, explanation=explanation, image_filename=unique_filename)

    return render_template('new_page.html', portfolio_weights=None, explanation=None, image_filename=None)

@main.route('/profile')
def profile():
    # 实现你的profile逻辑
    return render_template('profile.html')

@main.route('/logout')
def logout():
    # 实现你的logout逻辑
    return redirect(url_for('main.home'))

@main.route('/login')
def login():
    # 实现你的login逻辑
    return render_template('login.html')

@main.route('/register')
def register():
    # 实现你的register逻辑
    return render_template('register.html')

def get_stock_data(tickers, start_date, end_date):
    data = yf.download(tickers, start=start_date, end=end_date)['Adj Close']
    returns = data.pct_change().dropna()
    return returns

def portfolio_annualized_return(weights, returns):
    return np.sum(weights * returns.mean()) * 252

def portfolio_annualized_volatility(weights, returns):
    return np.sqrt(np.dot(weights.T, np.dot(returns.cov() * 252, weights)))

def minimize_volatility(weights, returns):
    return portfolio_annualized_volatility(weights, returns)

def weight_sum_constraint(weights):
    return np.sum(weights) - 1

def recommend_portfolio(tickers, score):
    start_date = datetime.now() - timedelta(days=365)
    end_date = datetime.now()
    returns = get_stock_data(tickers, start_date, end_date)

    if score <= 20:
        bounds = tuple((0.05, 0.2) for _ in range(len(tickers)))
        explanation = "低风险组合：权重限制在5%到20%之间，以降低单只股票的风险暴露。"
    elif score <= 40:
        bounds = tuple((0.05, 0.25) for _ in range(len(tickers)))
        explanation = "中低风险组合：权重限制在5%到25%之间，适度降低风险。"
    elif score <= 60:
        bounds = tuple((0.05, 0.3) for _ in range(len(tickers)))
        explanation = "中等风险组合：权重限制在5%到30%之间，平衡风险和收益。"
    elif score <= 80:
        bounds = tuple((0.05, 0.35) for _ in range(len(tickers)))
        explanation = "中高风险组合：权重限制在5%到35%之间，适度提高潜在收益。"
    else:
        bounds = tuple((0.05, 0.5) for _ in range(len(tickers)))
        explanation = "高风险组合：权重限制在5%到50%之间，以寻求更高的潜在收益。"

    constraints = {'type': 'eq', 'fun': weight_sum_constraint}
    initial_weights = np.ones(len(tickers)) / len(tickers)
    optimized_result = minimize(minimize_volatility, initial_weights,
                                args=(returns,), method='SLSQP',
                                bounds=bounds, constraints=constraints)
    return optimized_result.x, explanation

def plot_weights(weights, tickers, save_path, title='Recommended Portfolio Weights'):
    # 调试信息
    print(f"Plotting weights: {weights}")
    print(f"Tickers: {tickers}")
    
    plt.figure(figsize=(8, 8))
    plt.pie(weights, labels=tickers, autopct='%1.1f%%', startangle=140)
    plt.title(title)
    plt.savefig(save_path)
    plt.close()

    # 检查生成的调试图像是否正确
    debug_path = os.path.join(current_app.root_path, 'static/images', 'debug_plot.png')
    if os.path.exists(debug_path):
        print(f"Debug plot saved to {debug_path}")
    else:
        print("Failed to save debug plot")

   
