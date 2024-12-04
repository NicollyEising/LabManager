from flask import Flask, request, jsonify
from firebase_admin import credentials, firestore, initialize_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime
import pytz
import os


class Config:
    app = Flask(__name__)

    # Configuração do Firebase
    cred = credentials.Certificate("firebase_credentials.json")
    initialize_app(cred)

    tz = pytz.timezone('America/Sao_Paulo')
    datetime.now(tz)

    # Banco de dados Firestore
    db = firestore.client()

    # Referência para usuários e laboratórios no Firestore
    users_ref = db.collection("users")
    labs_ref = db.collection("laboratorios")


    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # 'default_secret_key' é um valor de fallback
