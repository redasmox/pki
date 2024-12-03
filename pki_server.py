from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import NameOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import os

# Configuration
PKI_PORT = 9000

# Flask application
app = Flask(__name__)

# Génération de la clé privée et du certificat racine pour la PKI
def create_pki_keys_and_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"PKI Root CA")])
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(private_key, hashes.SHA256(), default_backend())
    return private_key, cert

pki_private_key, pki_cert = create_pki_keys_and_certificate()

# Fonction pour déchiffrer une clé publique avec la clé privée de la PKI
def decrypt_with_private_key(private_key, encrypted_data):
    symmetric_key = private_key.decrypt(
        encrypted_data[:256],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    tag = encrypted_data[256:272]
    nonce = encrypted_data[272:284]
    ciphertext = encrypted_data[284:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Fonction pour signer un certificat avec la clé privée de la PKI
def sign_certificate(pki_private_key, pki_cert, public_key, name):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = pki_cert.subject
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
        .sign(pki_private_key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.PEM)

@app.route('/request_certificate', methods=['POST'])
def request_certificate():
    try:
        data = request.json
        encrypted_public_key = bytes.fromhex(data['public_key'])  # Clé publique encodée en hexadécimal
        name = data['name']

        # Déchiffrer la clé publique envoyée par le client
        public_key_pem = decrypt_with_private_key(pki_private_key, encrypted_public_key)
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        # Générer un certificat signé
        certificate = sign_certificate(pki_private_key, pki_cert, public_key, name)

        # Retourner le certificat en hexadécimal
        return jsonify({"certificate": certificate.hex()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def run_pki_server():
    app.run(host='0.0.0.0', port=PKI_PORT, debug=False)

if __name__ == "__main__":
    run_pki_server()
