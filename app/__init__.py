from flask import Flask
from .auth import register_user, login_user, verificar_conflitos_reservas
from .map import mapa_utilizacao
from .installation_requests import solicitar_instalacao, gerenciar_solicitacao_software
from config import Config
from .labs import (
    create_lab,
    list_labs,
    update_lab,
    delete_lab,
    add_software,
    remove_software,
    set_lab_maintenance,
    reservar_lab,
    bloquear_lab,
    pre_reservar_lab,
    gerenciar_pre_reserva,
    cancelar_reserva,
    reserva_recorrente,
    pesquisa_laboratorios,
    cancelar_pre_reserva
)


def create_app():
    app = Flask(__name__)

    # Configurações
    app.config.from_object(Config)  # Se houver um arquivo de configurações

    # Registra as rotas
# Registra as rotas de usuários
    app.add_url_rule("/register", "register_user", register_user, methods=["POST"])
    app.add_url_rule("/login", "login_user", login_user, methods=["POST"])

    # Rota para mapa de utilização
    app.add_url_rule("/map", "mapa_utilizacao", mapa_utilizacao, methods=["GET"])

    # Rota para solicitações de instalação
    app.add_url_rule("/solicitacoes/instalacao", "solicitar_instalacao", solicitar_instalacao, methods=["POST"])

    # Rota para gerenciar solicitação de software
    app.add_url_rule("/solicitacoes/softwares/<solicitacao_id>", "gerenciar_solicitacao_software", gerenciar_solicitacao_software, methods=["PUT"])

    # Registra as rotas de laboratórios
    app.add_url_rule("/laboratorios", "create_lab", create_lab, methods=["POST"])
    app.add_url_rule("/laboratorios", "list_labs", list_labs, methods=["GET"])
    app.add_url_rule("/laboratorios/<lab_id>", "update_lab", update_lab, methods=["PUT"])
    app.add_url_rule("/laboratorios/<lab_id>", "delete_lab", delete_lab, methods=["DELETE"])
    app.add_url_rule("/laboratorios/<lab_id>/softwares", "add_software", add_software, methods=["POST"])
    app.add_url_rule("/laboratorios/<lab_id>/softwares", "remove_software", remove_software, methods=["DELETE"])
    app.add_url_rule("/laboratorios/<lab_id>/manutencao", "set_lab_maintenance", set_lab_maintenance, methods=["PUT"])
    app.add_url_rule("/laboratorios/<lab_id>/reserva", "reservar_lab", reservar_lab, methods=["POST"])
    app.add_url_rule("/laboratorios/<lab_id>/bloqueio", "bloquear_lab", bloquear_lab, methods=["PUT"])
    app.add_url_rule("/laboratorios/<lab_id>/pre-reserva", "pre_reservar_lab", pre_reservar_lab, methods=["POST"])
    app.add_url_rule("/laboratorios/<lab_id>/pre-reserva/<pre_reserva_id>", "gerenciar_pre_reserva", gerenciar_pre_reserva, methods=["PUT"])
    app.add_url_rule("/laboratorios/<lab_id>/reserva/<reserva_id>", "cancelar_reserva", cancelar_reserva, methods=["DELETE"])
    app.add_url_rule("/laboratorios/<lab_id>/reserva/recorrente", "reserva_recorrente", reserva_recorrente, methods=["POST"])
    app.add_url_rule("/laboratorios/pesquisa", "pesquisa_laboratorios", pesquisa_laboratorios, methods=["GET"])
    app.add_url_rule("/laboratorios/<lab_id>/pre-reserva/<pre_reserva_id>", "cancelar_pre_reserva", cancelar_pre_reserva, methods=["DELETE"])
    app.add_url_rule("/professores/<professor>/reservas/conflitos", "verificar_conflitos_reservas", verificar_conflitos_reservas, methods=["GET"])


    # Middleware para capturar erros globais

    return app
