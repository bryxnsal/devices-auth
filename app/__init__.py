import os
from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

jwt = JWTManager()
mongo_client = None
db = None

def create_app():
    app = Flask(__name__)
    
    # Configuración
    app.config['MONGO_URI'] = os.getenv('MONGO_URI')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES'))
    app.config['SERVER_PORT'] = os.getenv('SERVER_PORT')
    
    # Initialize MongoDB
    global mongo_client, db
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db = mongo_client[os.getenv('MONGO_DBNAME')]
    
    # Initialize JWT
    jwt.init_app(app)
    
    # Registrar blueprints
    from app.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    return app