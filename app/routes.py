from flask import Blueprint, request, jsonify
from app.models import Device
from app.auth import is_valid_public_key, verify_signature, generate_jwt_token, validate_jwt_token
import os
import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

@auth_bp.route('/register', methods=['POST'])
def register_device():
    data = request.get_json()

    required_fields = ['device_id', 'public_key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Faltan campos requeridos'}), 400

    if Device.find_by_id(data['device_id']):
        return jsonify({'error': 'El dispositivo ya está registrado'}), 409
    
    if not is_valid_public_key(data['public_key']):
        return jsonify({'error': 'Clave pública inválida'}), 400

    device_data = {
        'device_id': data['device_id'],
        'public_key': data['public_key'],
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }

    Device.create(device_data)
    return jsonify({'message': 'Dispositivo registrado correctamente'}), 201

@auth_bp.route('/login', methods=['POST'])
def login_device():
    data = request.get_json()

    required_fields = ['device_id', 'message', 'signature']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Faltan campos requeridos'}), 400

    device = Device.find_by_id(data['device_id'])
    if not device:
        return jsonify({'error': 'El dispositivo no existe'}), 404

    if not verify_signature(
        data['message'],
        data['signature'],
        device['public_key']
    ):
        return jsonify({'error': 'Firma inválida'}), 401

    token = generate_jwt_token(data['device_id'])
    return jsonify({'token': token}), 200

@auth_bp.route('/renew-certificate', methods=['POST'])
def renew_certificate():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No se encuentra el token'}), 401

    device_id = validate_jwt_token(token.split(' ')[1])
    if not device_id:
        return jsonify({'error': 'Token inválido o expirado'}), 401

    data = request.get_json()
    if 'new_public_key' not in data:
        return jsonify({'error': 'Se requiere la clave pública'}), 400
    
    if not is_valid_public_key(data['new_public_key']):
        return jsonify({'error': 'Clave pública inválida'}), 400

    Device.update_public_key(device_id, data['new_public_key'])
    return jsonify({'message': 'Clave pública actualizada correctamente'}), 200

@auth_bp.route('/verify', methods=['GET'])
def verify_authentication():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No se encuentra el token'}), 401

    device_id = validate_jwt_token(token.split(' ')[1])
    if not device_id:
        return jsonify({'error': 'Token inválido o expirado'}), 401

    return jsonify({
        'message': 'Dispositivo autenticado',
        'device_id': device_id
    }), 200
