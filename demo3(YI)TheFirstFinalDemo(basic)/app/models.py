from . import db  # 从 __init__.py 导入 db 实例
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    image_file = db.Column(db.String(255), nullable=False, default='default.jpg')
    stocks = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"