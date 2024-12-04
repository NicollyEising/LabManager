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
import pytz


from flask import Flask

app = Flask(__name__)




# Inicialização do Firestore (após a inicialização do Firebase)
db = firestore.client()

# Definindo a chave secreta de forma segura via variável de ambiente
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret")


# Referências às coleções no Firestore
users_ref = db.collection("users")
labs_ref = db.collection("laboratorios")
pre_reservas_ref = db.collection("pre_reservas")
reservas_ref = db.collection("reservas")
solicitacoes_instalacao_ref = db.collection("solicitacoes_instalacao")

@app.route("/laboratorios", methods=["POST"])
def create_lab():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    data = request.get_json()
    lab_data = {
        "nome": data.get("nome"),
        "num_pcs": data.get("num_pcs"),
        "localizacao": data.get("localizacao"),
        "status": data.get("status"),
        "softwares": data.get("softwares", []),
        "reservas": [],
        "pre_reservas": [],
        "bloqueado": False
    }
    
    

    lab_ref = labs_ref.add(lab_data)
    return jsonify({"message": "Laboratório criado com sucesso!", "lab_id": lab_ref[1].id}), 201

@app.route("/laboratorios", methods=["GET"])
def list_labs():
    labs = labs_ref.stream()
    labs_list = [lab.to_dict() for lab in labs]
    return jsonify(labs_list), 200

# Função para atualizar laboratório
@app.route("/laboratorios/<lab_id>", methods=["PUT"])
def update_lab(lab_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    lab_ref = labs_ref.document(lab_id)
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    data = request.get_json()
    lab_ref.update(data)
    return jsonify({"message": "Laboratório atualizado com sucesso!"}), 200

# Função para remover laboratório
@app.route("/laboratorios/<lab_id>", methods=["DELETE"])
def delete_lab(lab_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    lab_ref = labs_ref.document(lab_id)
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.delete()
    return jsonify({"message": "Laboratório removido com sucesso!"}), 200

# Função para adicionar software a um laboratório
@app.route("/laboratorios/<lab_id>/softwares", methods=["POST"])
def add_software(lab_id):
    data = request.get_json()
    software = data.get("software")

    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()

    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    softwares = lab["softwares"]
    if software not in softwares:
        softwares.append(software)
        lab_ref.update({"softwares": softwares})
        return jsonify({"message": f"Software {software} adicionado ao laboratório!"}), 200
    else:
        return jsonify({"message": "Software já está instalado no laboratório"}), 400

# Função para remover software de um laboratório
@app.route("/laboratorios/<lab_id>/softwares", methods=["DELETE"])
def remove_software(lab_id):
    data = request.get_json()
    software = data.get("software")

    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()

    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    softwares = lab["softwares"]
    if software in softwares:
        softwares.remove(software)
        lab_ref.update({"softwares": softwares})
        return jsonify({"message": f"Software {software} removido do laboratório!"}), 200
    else:
        return jsonify({"message": "Software não encontrado no laboratório"}), 400

# Função para modificar o status de manutenção do laboratório
@app.route("/laboratorios/<lab_id>/manutencao", methods=["PUT"])
def set_lab_maintenance(lab_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    data = request.get_json()
    status = data.get("status")
    if status not in ["em manutencao", "disponivel", "ocupado"]:
        return jsonify({"error": "Status inválido. Use 'em manutencao', 'disponivel' ou 'ocupado'."}), 400

    lab_ref = labs_ref.document(lab_id)
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.update({"status": status})
    return jsonify({"message": f"Status do laboratório alterado para {status}!"}), 200

# Funções adicionais (Implementações dos requisitos US004, US008, US011 e US013)

# Função para reservar laboratório
@app.route("/laboratorios/<lab_id>/reserva", methods=["POST"])
def reservar_lab(lab_id):
    data = request.get_json()
    professor = data.get("professor")
    horario_inicio = data.get("horario_inicio")
    horario_fim = data.get("horario_fim")

    # Convertendo os horários para datetime se forem do tipo DatetimeWithNanoseconds
    if isinstance(horario_inicio, firestore.SERVER_TIMESTAMP.__class__):
        horario_inicio = horario_inicio.datetime
    if isinstance(horario_fim, firestore.SERVER_TIMESTAMP.__class__):
        horario_fim = horario_fim.datetime

    # Verificar se os horários são strings e convertê-los
    if isinstance(horario_inicio, str):
        horario_inicio = datetime.strptime(horario_inicio, "%Y-%m-%d %H:%M")
    if isinstance(horario_fim, str):
        horario_fim = datetime.strptime(horario_fim, "%Y-%m-%d %H:%M")

    # Garantir que os horários sejam 'naive' (sem fuso horário)
    if horario_inicio.tzinfo is not None:
        horario_inicio = horario_inicio.replace(tzinfo=None)
    if horario_fim.tzinfo is not None:
        horario_fim = horario_fim.replace(tzinfo=None)

    # Verifique se o laboratório existe
    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()
    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    # Verificar conflitos de reserva
    reservas = lab.get("reservas", [])
    for reserva in reservas:
        # Convertendo os horários das reservas para objetos datetime se necessário
        reserva_inicio = reserva["horario_inicio"]
        reserva_fim = reserva["horario_fim"]

        # Caso sejam objetos DatetimeWithNanoseconds
        if isinstance(reserva_inicio, firestore.SERVER_TIMESTAMP.__class__):
            reserva_inicio = reserva_inicio.datetime
        if isinstance(reserva_fim, firestore.SERVER_TIMESTAMP.__class__):
            reserva_fim = reserva_fim.datetime

        # Certificar que ambos reserva_inicio e reserva_fim são do tipo datetime
        if isinstance(reserva_inicio, str):
            reserva_inicio = datetime.strptime(reserva_inicio, "%Y-%m-%d %H:%M")
        if isinstance(reserva_fim, str):
            reserva_fim = datetime.strptime(reserva_fim, "%Y-%m-%d %H:%M")

        # Garantir que as datas da reserva também sejam 'naive'
        if reserva_inicio.tzinfo is not None:
            reserva_inicio = reserva_inicio.replace(tzinfo=None)
        if reserva_fim.tzinfo is not None:
            reserva_fim = reserva_fim.replace(tzinfo=None)

        # Verificação de conflito de reserva
        if not (horario_fim <= reserva_inicio or horario_inicio >= reserva_fim):
            return jsonify({"error": "Conflito de reserva"}), 400

    # Adicionar nova reserva
    reserva_data = {
        "professor": professor,
        "horario_inicio": horario_inicio,
        "horario_fim": horario_fim
    }
    reservas.append(reserva_data)
    lab_ref.update({"reservas": reservas})

    # Retornar as informações da reserva, incluindo o lab_id
    reserva_data["lab_id"] = lab_id  # Inclui o lab_id nas informações da reserva

    return jsonify({"message": "Laboratório reservado com sucesso!", "reserva": reserva_data}), 201
# Função para bloquear/desbloquear laboratório
@app.route("/laboratorios/<lab_id>/bloqueio", methods=["PUT"])
def bloquear_lab(lab_id):
    data = request.get_json()
    bloqueado = data.get("bloqueado", False)  # True para bloquear, False para desbloquear

    lab_ref = labs_ref.document(lab_id)
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.update({"bloqueado": bloqueado})
    status_msg = "bloqueado" if bloqueado else "desbloqueado"
    return jsonify({"message": f"Laboratório {status_msg} com sucesso!"}), 200



# Função para pré-reservar laboratório
@app.route("/laboratorios/<lab_id>/pre-reserva", methods=["POST"])
def pre_reservar_lab(lab_id):
    data = request.get_json()
    lab_id = data.get("lab_id")
    
    # Definir o fuso horário
    tz = pytz.timezone("America/Sao_Paulo")  # Exemplo de fuso horário
    
    # Criar datetime 'aware' com o fuso horário
    horario_inicio = datetime.strptime(data.get("horario_inicio"), "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    horario_fim = datetime.strptime(data.get("horario_fim"), "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    
    # Consultar pré-reservas para o laboratório
    existing_pre_reservations = pre_reservas_ref.where("lab_id", "==", lab_id).get()
    
    # Filtrar conflitos manualmente no código
    conflicting_reservations = [
        r for r in existing_pre_reservations
        if not (horario_fim <= r.to_dict()["horario_inicio"] or horario_inicio >= r.to_dict()["horario_fim"])
    ]
    
    if conflicting_reservations:
        return jsonify({"error": "Conflito de horário com outra pré-reserva"}), 400
    
    # Caso não haja conflitos, permitir a criação da pré-reserva
    pre_reserva_ref = pre_reservas_ref.add({
    "lab_id": lab_id,
    "horario_inicio": horario_inicio,
    "horario_fim": horario_fim,
    "data_criacao": firestore.SERVER_TIMESTAMP
})

    # Agora, acessa o id diretamente
    pre_reserva_id = pre_reserva_ref[1].id  # Segundo item da tupla contém o id

    # Retorna o id da pré-reserva
    return jsonify({"message": "Pré-reserva criada com sucesso!", "id": pre_reserva_id}), 201

# Função para aprovar ou rejeitar pré-reservas
@app.route("/laboratorios/<lab_id>/pre-reserva/<pre_reserva_id>", methods=["PUT"])
def gerenciar_pre_reserva(lab_id, pre_reserva_id):
    data = request.get_json()
    acao = data.get("acao")  # "aprovar" ou "rejeitar"

    # Consultar o laboratório
    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()
    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    # Buscar a pré-reserva na coleção de pré-reservas
    pre_reserva_ref = pre_reservas_ref.document(pre_reserva_id)
    pre_reserva = pre_reserva_ref.get().to_dict()

    if not pre_reserva:
        return jsonify({"error": "Pré-reserva não encontrada"}), 404

    # Atualizar a pré-reserva com a ação (aprovar ou rejeitar)
    if acao == "aprovar":
        pre_reserva["status"] = "aprovada"
        reservas = lab.get("reservas", [])
        reservas.append(pre_reserva)
        lab_ref.update({"reservas": reservas})
    elif acao == "rejeitar":
        pre_reserva["status"] = "rejeitada"

    # Atualizar a coleção de pré-reservas
    pre_reserva_ref.update({"status": pre_reserva["status"]})

    return jsonify({"message": f"Pré-reserva {acao} com sucesso!"}), 200

# Rota para testar conexão


# Função para cancelar reserva de laboratório
@app.route("/laboratorios/<lab_id>/reserva/<reserva_id>", methods=["DELETE"])
def cancelar_reserva(lab_id, reserva_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()
    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    reservas = lab.get("reservas", [])
    reserva_to_remove = None
    for reserva in reservas:
        if reserva["reserva_id"] == reserva_id:
            reserva_to_remove = reserva
            break

    if reserva_to_remove:
        reservas.remove(reserva_to_remove)
        lab_ref.update({"reservas": reservas})
        return jsonify({"message": "Reserva cancelada com sucesso!"}), 200
    else:
        return jsonify({"error": "Reserva não encontrada"}), 404


# Função para criar reserva recorrente
@app.route("/laboratorios/<lab_id>/reserva/recorrente", methods=["POST"])
def reserva_recorrente(lab_id):
    data = request.get_json()
    professor = data.get("professor")
    horario_inicio = data.get("horario_inicio")  # Ex: "2024-12-05 10:00"
    horario_fim = data.get("horario_fim")  # Ex: "2024-12-05 12:00"
    frequencia = data.get("frequencia")  # Ex: "semanal"

    # Verifique se o laboratório existe
    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()
    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    reservas = lab.get("reservas", [])
    new_reservas = []
    
    # Adiciona reservas recorrentes conforme a frequência
    # Exemplo simples de lógica de recorrência
    if frequencia == "semanal":
        for i in range(4):  # Criar reservas para 4 semanas
            new_reserva = {
                "professor": professor,
                "horario_inicio": horario_inicio,  # Implementação simples para uma semana
                "horario_fim": horario_fim
            }
            new_reservas.append(new_reserva)

    # Adiciona as reservas recorrentes ao laboratório
    lab_ref.update({"reservas": reservas + new_reservas})

    return jsonify({"message": "Reserva recorrente criada com sucesso!"}), 201


# Função para pesquisar laboratórios por número de PCs ou softwares instalados
@app.route("/laboratorios/pesquisa", methods=["GET"])
def pesquisa_laboratorios():
    num_pcs = request.args.get("num_pcs")
    software = request.args.get("software")

    query = labs_ref
    if num_pcs:
        query = query.where("num_pcs", "==", int(num_pcs))
    if software:
        query = query.where("softwares", "array_contains", software)

    labs = query.stream()
    labs_list = [lab.to_dict() for lab in labs]

    return jsonify(labs_list), 200


# Função para cancelar pré-reserva
@app.route("/laboratorios/<lab_id>/pre-reserva/<pre_reserva_id>", methods=["DELETE"])
def cancelar_pre_reserva(lab_id, pre_reserva_id):
    data = request.get_json()
    professor = data.get("professor")

    # Consultar a pré-reserva
    pre_reserva_ref = pre_reservas_ref.document(pre_reserva_id)
    pre_reserva = pre_reserva_ref.get().to_dict()
    if not pre_reserva:
        return jsonify({"error": "Pré-reserva não encontrada"}), 404

    if pre_reserva["professor"] != professor:
        return jsonify({"error": "Somente o professor pode cancelar a pré-reserva"}), 403

    # Remover a pré-reserva
    pre_reserva_ref.delete()

    return jsonify({"message": "Pré-reserva cancelada com sucesso!"}), 200