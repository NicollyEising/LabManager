from flask import Flask
from .auth import register_user, login_user
from .map import mapa_utilizacao
from .installation_requests import solicitar_instalacao, gerenciar_solicitacao_software
from config import Config

def create_app():
    # Cria a instância da aplicação Flask
    app = Flask(__name__)

    # Configurações podem ser carregadas aqui
    app.config.from_object('C:/Users/nicol/Desktop/flask_lab_managet/config.Config')  # Certifique-se de ter um arquivo config.py com a classe Config

    # Registra as rotas da aplicação
    app.add_url_rule("/register", "register_user", register_user, methods=["POST"])
    app.add_url_rule("/login", "login_user", login_user, methods=["POST"])
    app.add_url_rule("/mapa-utilizacao", "mapa_utilizacao", mapa_utilizacao, methods=["GET"])
    app.add_url_rule("/solicitacoes/instalacao", "solicitar_instalacao", solicitar_instalacao, methods=["POST"])
    app.add_url_rule("/solicitacoes/softwares/<solicitacao_id>", "gerenciar_solicitacao_software", gerenciar_solicitacao_software, methods=["PUT"])

    return app
