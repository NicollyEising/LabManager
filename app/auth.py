import os
import logging
import uuid
from flask import Flask, request, jsonify
from firebase_admin import firestore, credentials
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, ValidationError, validator
from config import Config
import firebase_admin
import traceback


from flask import Flask

app = Flask(__name__)



# Inicialização do Firestore (após a inicialização do Firebase)
db = firestore.client()

# Referências ao Firestore
users_ref = db.collection('users')
labs_ref = db.collection('laboratorios')

# Definindo a chave secreta de forma segura via variável de ambiente
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret")

# Função para gerar hash de senha de forma segura
def hash_password(password: str) -> str:
    return generate_password_hash(password)

# Função para verificar a senha
def verify_password(stored_password: str, provided_password: str) -> bool:
    return check_password_hash(stored_password, provided_password)

# Função para gerar token JWT
def generate_jwt(username: str) -> str:
    expiration = datetime.utcnow() + timedelta(hours=1)
    return jwt.encode({'username': username, 'exp': expiration}, SECRET_KEY, algorithm="HS256")

# Função para gerar ID único usando UUID
def generate_unique_id() -> str:
    return str(uuid.uuid4())

# Classe para validação de dados de entrada
class RegisterUserModel(BaseModel):
    username: str
    password: str
    email: str
    user_type: str

    @validator('user_type')
    def validate_user_type(cls, value):
        if value not in ["admin", "professor"]:
            raise ValueError('Tipo de usuário inválido')
        return value

    @validator('email')
    def validate_email(cls, value):
        if '@' not in value:
            raise ValueError('Email inválido')
        return value


# Função para verificar se o email já está em uso
def email_ja_utilizado(email: str) -> bool:
    # Verificar se já existe um usuário com o mesmo email
    user_doc = users_ref.where("email", "==", email).limit(1).get()
    if len(user_doc) > 0:  # Se um documento for retornado, o email já está em uso
        return True
    return False

# Rota de registro de usuário
@app.route("/register", methods=["POST"])
def register_user():
    try:
        data = request.get_json()
        user_data = RegisterUserModel(**data)  # Validação dos dados recebidos

        # Verifica se o email já está em uso
        if email_ja_utilizado(user_data.email):
            return jsonify({"error": "Email já está em uso"}), 400

        hashed_password = hash_password(user_data.password)
        user_data_dict = user_data.dict()
        user_data_dict['password'] = hashed_password  # Substitui a senha pelo hash
        
        # Gerar um ID único para o usuário
        user_data_dict['id'] = generate_unique_id()

        # Adiciona o documento ao Firestore (com o email incluído)
        user_data_dict['email'] = user_data.email  # Garantindo que o email seja salvo

        # Adiciona o usuário no Firestore
        users_ref.add(user_data_dict)

        return jsonify({"message": "Usuário registrado com sucesso!", "user_id": user_data_dict['id']}), 201
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

# Rota de login de usuário
@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user_doc = users_ref.where("username", "==", username).limit(1).get()

    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()

    if not verify_password(user["password"], password):
        return jsonify({"error": "Senha incorreta"}), 401

    token = generate_jwt(username)

    return jsonify({"message": f"Bem-vindo {username}!", "token": token}), 200

@app.route("/professores/<professor>/reservas/conflitos", methods=["GET"])
def verificar_conflitos_reservas(professor):
 
    # Inicializando lista de conflitos
    conflitos = []

    try:
        # Recupera todos os laboratórios que o professor tem reservas
        labs = labs_ref.stream()

        for lab in labs:
            reservas = lab.to_dict().get("reservas", [])
            # Filtrando reservas do professor específico
            reservas_professor = [r for r in reservas if "professor" in r and r["professor"] == professor]

            # Comparando reservas do professor para verificar conflitos
            for i, r1 in enumerate(reservas_professor):
                for r2 in reservas_professor[i + 1:]:
                    # Convertendo os horários para objetos datetime
                    horario_inicio_r1 = datetime.strptime(r1["horario_inicio"], "%Y-%m-%dT%H:%M:%S")
                    horario_fim_r1 = datetime.strptime(r1["horario_fim"], "%Y-%m-%dT%H:%M:%S")
                    horario_inicio_r2 = datetime.strptime(r2["horario_inicio"], "%Y-%m-%dT%H:%M:%S")
                    horario_fim_r2 = datetime.strptime(r2["horario_fim"], "%Y-%m-%dT%H:%M:%S")

                    # Verifica se as reservas se sobrepõem
                    if not (horario_fim_r1 <= horario_inicio_r2 or horario_inicio_r1 >= horario_fim_r2):
                        conflitos.append({
                            "lab_id": lab.id,
                            "reserva1": r1,
                            "reserva2": r2
                        })

        if conflitos:
            return jsonify({"conflitos": conflitos}), 200
        else:
            return jsonify({"message": "Sem conflitos encontrados"}), 200
    except Exception as e:
        logging.error(f"Erro ao verificar conflitos: {e}")
        traceback.print_exc()
        return jsonify({"error": "Erro ao verificar conflitos"}), 500