import os
from flask import Flask, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_swagger_ui import get_swaggerui_blueprint
from flasgger import Swagger
import os



db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)

    with app.app_context():
        from .models import User
        db.create_all()

        # Define the path to the static swagger.json file
    SWAGGER_URL = '/swagger'  # URL for exposing Swagger UI
    API_URL = '/static/swagger.json'  # Our API URL (static file)

    # Initialize Swagger using the static JSON file
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec_1',
                "route": API_URL,
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": SWAGGER_URL
    }

    Swagger(app, config=swagger_config)


    from .routes import userBlueprint
    app.register_blueprint(userBlueprint)

    return app