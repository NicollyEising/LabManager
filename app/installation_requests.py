from flask import Flask, request, jsonify
from firebase_admin import credentials, firestore, initialize_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import pytz
app = Flask(__name__)
db = firestore.client()
users_ref = db.collection("users")
labs_ref = db.collection("laboratorios")
SECRET_KEY = "your_secret_key"  # Use uma chave secreta segura

app = Flask(__name__)

# Inicializar a referência ao Firestore
db = firestore.client()


# Referências às coleções no Firestore
labs_ref = db.collection('laboratorios')
pre_reservas_ref = db.collection('pre_reservas')
reservas_ref = db.collection('reservas')
solicitacoes_instalacao_ref = db.collection('solicitacoes_instalacao')

# Função para solicitar instalação de software
@app.route("/solicitacoes/instalacao", methods=["POST"])
def solicitar_instalacao():
    data = request.get_json()
    professor = data.get("professor")
    software = data.get("software")
    lab_id = data.get("lab_id")

    # Verificar se o professor existe no sistema
    user_doc = users_ref.where("username", "==", professor).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Professor não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "professor":
        return jsonify({"error": "Somente professores podem solicitar instalação de software"}), 403

    # Criar a solicitação
    solicitacao = {
        "professor": professor,
        "software": software,
        "lab_id": lab_id,
        "status": "pendente",
        "data_solicitacao": firestore.SERVER_TIMESTAMP
    }

    solicitacao_ref = db.collection("solicitacoes_instalacao").add(solicitacao)

    # Enviar notificação ao administrador (simples inserção em uma coleção ou log)
    admin_msg = {
        "message": f"Solicitação de instalação de software '{software}' para o laboratório {lab_id} solicitada pelo professor {professor}.",
        "status": "pendente",
        "data_notificacao": firestore.SERVER_TIMESTAMP
    }
    db.collection("notificacoes_admin").add(admin_msg)

    return jsonify({"message": "Solicitação de instalação enviada com sucesso!", "solicitacao_id": solicitacao_ref[1].id}), 201




# Função para aprovar ou rejeitar solicitação de software
@app.route("/solicitacoes/softwares/<solicitacao_id>", methods=["PUT"])
def gerenciar_solicitacao_software(solicitacao_id):
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

    # Verificar se o usuário é um administrador
    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Apenas administradores podem gerenciar solicitações de software"}), 403

    # Buscar solicitação
    solicitacao_ref = db.collection("solicitacoes_instalacao").document(solicitacao_id)
    solicitacao = solicitacao_ref.get()

    if not solicitacao.exists:
        return jsonify({"error": "Solicitação não encontrada"}), 404

    data = request.get_json()
    acao = data.get("acao")  # "aprovar" ou "rejeitar"

    if acao not in ["aprovar", "rejeitar"]:
        return jsonify({"error": "Ação inválida. Use 'aprovar' ou 'rejeitar'."}), 400

    # Atualizar o status da solicitação
    status = "aprovada" if acao == "aprovar" else "rejeitada"
    solicitacao_ref.update({"status": status})

    return jsonify({"message": f"Solicitação {status} com sucesso!"}), 200



