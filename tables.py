from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from app_config import *

m883lfs = SQLAlchemy(app)

class Users(m883lfs.Model):
    id = m883lfs.Column(m883lfs.Integer, primary_key=True, autoincrement=True)
    username = m883lfs.Column(m883lfs.String(80), unique=True, nullable=False)
    password = m883lfs.Column(m883lfs.String(120), nullable=False)
    user_type = m883lfs.Column(m883lfs.String(20), nullable=False, default='user')
    locked = m883lfs.Column(m883lfs.Boolean, nullable=False, default=False)
    failed_attempts = m883lfs.Column(m883lfs.Integer, nullable=False, default=0) 

class Uploads(m883lfs.Model):
    id = m883lfs.Column(m883lfs.Integer, primary_key=True, autoincrement=True)
    filename = m883lfs.Column(m883lfs.String(120), nullable=False)
    uploaded_by = m883lfs.Column(m883lfs.String(80), nullable=False)
    upload_date = m883lfs.Column(m883lfs.DateTime, nullable=False, default=datetime.utcnow)
    uploaded_ip = m883lfs.Column(m883lfs.String(45), nullable=True)
    scan_result = m883lfs.Column(m883lfs.String(255), nullable=True)

class MacAdrs(m883lfs.Model):
    id = m883lfs.Column(m883lfs.Integer, primary_key=True, autoincrement=True)
    mac_adrs = m883lfs.Column(m883lfs.String(128), unique=True, nullable=False)  
    is_locked = m883lfs.Column(m883lfs.Boolean, nullable=False, default=False)

class MontyHallGames(m883lfs.Model):
    id = m883lfs.Column(m883lfs.Integer, primary_key=True)
    doors = m883lfs.Column(m883lfs.String(10), nullable=False)
    car = m883lfs.Column(m883lfs.Integer, nullable=False)
    first_choice = m883lfs.Column(m883lfs.Integer, nullable=False)
    revealed_door = m883lfs.Column(m883lfs.Integer, nullable=False)
    remaining_door = m883lfs.Column(m883lfs.Integer, nullable=True)
    final_choice = m883lfs.Column(m883lfs.Integer, nullable=True)
    win = m883lfs.Column(m883lfs.Boolean, nullable=True)
    switch = m883lfs.Column(m883lfs.String(10), nullable=True)

    def __repr__(self):
        return f'<MontyHallGame {self.id}>'

# Veritabanını oluşturma
with app.app_context():
    m883lfs.create_all()