from flask import Flask
from webapp import routes

def create_app():
    app = Flask(__name__)
    app.secret_key = 'penkit-web-2026-secure-key'
    routes.register_routes(app)
    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
