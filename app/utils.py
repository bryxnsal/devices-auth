from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

def generate_key_pair():
    """Genera un par de claves RSA (privada y pública)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serializar claves
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key, private_pem, public_pem

def sign_message(private_key, message):
    """Firma un mensaje con la clave privada"""
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, message, signature_b64):
    """Verifica una firma usando la clave pública"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"❌ Error en verificación: {str(e)}")
        return False

def display_signature_verification(public_pem, message, signature):
    """Muestra el resultado de la verificación de forma detallada"""
    print("\n" + "="*50)
    print("🔎 VERIFICACIÓN AUTOMÁTICA DE FIRMA")
    print("="*50)
    print(f"Mensaje original: {message}")
    print(f"Firma (base64): {signature}")
    
    is_valid = verify_signature(public_pem, message, signature)
    
    print("\nResultado:")
    if is_valid:
        print("✅ FIRMA VÁLIDA - El mensaje es auténtico e íntegro")
    else:
        print("❌ FIRMA INVÁLIDA - Posibles causas:")
        print("- La clave pública no corresponde a la privada que firmó")
        print("- El mensaje fue alterado")
        print("- La firma fue corrupta o mal generada")
    
    print("="*50 + "\n")

def display_keys(private_pem, public_pem):
    """Muestra las claves en formato PEM legible y como string con escapes"""
    # Versión formateada para lectura humana
    print("\n" + "="*50)
    print("🔑 CLAVE PRIVADA (Mantenla segura!)")
    print("="*50)
    print(private_pem)
    
    print("\n" + "="*50)
    print("🔐 CLAVE PÚBLICA (Puedes compartirla)")
    print("="*50)
    print(public_pem)
    print("="*50 + "\n")
    
    # Versión en string para programación (con \n explícitos)
    print("\n" + "="*50)
    print("📋 CLAVES EN FORMATO STRING (para usar en código)")
    print("="*50)
    print("Clave Privada como string:")
    print(repr(private_pem).strip("'"))
    
    print("\nClave Pública como string:")
    print(repr(public_pem).strip("'"))
    print("="*50 + "\n")

def main():
    print("🔐 Generador de Claves RSA y Firma Digital 🔐")
    print("1. Generar nuevas claves y firmar mensaje")
    print("2. Firmar un mensaje con clave existente")
    print("3. Verificar firma con clave pública")
    choice = input("Selecciona una opción (1/2/3): ")
    
    if choice == '1':
        # Generar nuevas claves
        private_key, private_pem, public_pem = generate_key_pair()
        display_keys(private_pem, public_pem)
        
        # Preguntar si quiere firmar un mensaje
        if input("¿Deseas firmar un mensaje con esta clave? (s/n): ").lower() == 's':
            message = input("Ingresa el mensaje a firmar: ")
            signature = sign_message(private_key, message)
            print("\n✍️ Firma digital generada (base64):")
            print(signature)
            
            # Verificación automática
            display_signature_verification(public_pem, message, signature)
    
    elif choice == '2':
        # Usar clave privada existente
        private_pem = input("Pega tu clave privada PEM (completa):\n")
        try:
            private_key = serialization.load_pem_private_key(
                private_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            message = input("Ingresa el mensaje a firmar: ")
            signature = sign_message(private_key, message)
            print("\n✍️ Firma digital generada (base64):")
            print(signature)
            
            # Obtener clave pública para verificación automática
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Verificación automática
            display_signature_verification(public_pem, message, signature)
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif choice == '3':
        # Verificar firma existente
        public_pem = input("Pega la clave pública PEM:\n")
        message = input("Ingresa el mensaje original: ")
        signature_b64 = input("Ingresa la firma en base64: ")
        
        display_signature_verification(public_pem, message, signature_b64)
    
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()