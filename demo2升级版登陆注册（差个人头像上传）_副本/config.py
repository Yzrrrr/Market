# backend/config.py
class Config:
    SECRET_KEY = 'yoursecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False