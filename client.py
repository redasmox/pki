import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
import os

# Fonction pour chiffrer une clé publique avant de l'envoyer à la PKI
def encrypt_with_public_key(public_key, plaintext):
    symmetric_key = os.urandom(32)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return encrypted_symmetric_key + encryptor.tag + nonce + ciphertext

# Demande de certificat à la PKI
def request_certificate_from_pki(pki_url, node_name, public_key, pki_cert):
    encrypted_public_key = encrypt_with_public_key(
        pki_cert.public_key(),
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    response = requests.post(
        f"{pki_url}/request_certificate",
        json={
            "name": node_name,
            "public_key": encrypted_public_key.hex()
        }
    )
    if response.status_code == 200:
        cert_data = response.json()['certificate']
        return load_pem_x509_certificate(bytes.fromhex(cert_data), default_backend())
    else:
        print(f"Error: {response.json()['error']}")
        return None

if __name__ == "__main__":
    # Générer une paire de clés pour le client
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # Adresse du serveur PKI
    pki_url = "http://localhost:9000"
    node_name = "Node A"

    # Chargement du certificat racine de la PKI (dans un cas réel, il doit être distribué)
    pki_cert_pem = """
    -----BEGIN CERTIFICATE-----
    ... (Certificat racine en PEM) ...
    -----END CERTIFICATE-----
    """
    pki_cert = load_pem_x509_certificate(pki_cert_pem.encode(), default_backend())

    # Demander un certificat
    cert = request_certificate_from_pki(pki_url, node_name, public_key, pki_cert)
    if cert:
        print(f"Certificat reçu pour {node_name}:\n{cert.public_bytes(serialization.Encoding.PEM).decode()}")
