from app import create_app
from flask import jsonify
import logging


# Cria a instância da aplicação Flask
app = create_app()

# Se o arquivo for executado diretamente, a aplicação Flask será iniciada
if __name__ == "__main__":
    app.run(debug=True)