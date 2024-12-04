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

# Função para exibir mapa de utilização dos laboratórios

@app.route("/mapa-utilizacao", methods=["GET"])
def mapa_utilizacao():
    labs = labs_ref.stream()
    mapa = []

    for lab in labs:
        lab_data = lab.to_dict()
        lab_id = lab.id
        reservas = lab_data.get("reservas", [])
        pre_reservas = lab_data.get("pre_reservas", [])
        status = lab_data.get("status", "disponivel")
        
        lab_status = {
            "lab_id": lab_id,
            "nome": lab_data.get("nome"),
            "status": status,
            "reservas": [],
            "pre_reservas": []
        }

        # Processar as reservas
        for reserva in reservas:
            # Garantir que horario_inicio é convertido para string se for datetime
            reserva_inicio = reserva["horario_inicio"]
            if isinstance(reserva_inicio, datetime):
                reserva_inicio = reserva_inicio.strftime("%Y-%m-%d %H:%M")
            reserva_fim = reserva["horario_fim"]
            if isinstance(reserva_fim, datetime):
                reserva_fim = reserva_fim.strftime("%Y-%m-%d %H:%M")
            
            # Verificar se a chave 'professor' existe antes de acessar
            professor = reserva.get("professor", "Desconhecido")

            lab_status["reservas"].append({
                "professor": professor,
                "horario_inicio": reserva_inicio,
                "horario_fim": reserva_fim
            })

        # Processar as pré-reservas
        for pre_reserva in pre_reservas:
            # Garantir que horario_inicio é convertido para string se for datetime
            pre_reserva_inicio = pre_reserva["horario_inicio"]
            if isinstance(pre_reserva_inicio, datetime):
                pre_reserva_inicio = pre_reserva_inicio.strftime("%Y-%m-%d %H:%M")
            pre_reserva_fim = pre_reserva["horario_fim"]
            if isinstance(pre_reserva_fim, datetime):
                pre_reserva_fim = pre_reserva_fim.strftime("%Y-%m-%d %H:%M")
            
            # Verificar se a chave 'professor' existe antes de acessar
            professor = pre_reserva.get("professor", "Desconhecido")

            lab_status["pre_reservas"].append({
                "professor": professor,
                "horario_inicio": pre_reserva_inicio,
                "horario_fim": pre_reserva_fim
            })

        mapa.append(lab_status)

    return jsonify(mapa), 200


