import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import string
import socket
from queue import Queue
import queue
import select
import pickle
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from datetime import datetime, timedelta
from cryptography.x509 import load_pem_x509_certificate

PKI_ADDRESS = ("localhost", 9000)
BUFFER_SIZE = 1024
PKI_PORT = 9000


# Génération de la paire de clés et certificat racine autosigné pour le serveur PKI
def create_pki_keys_and_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"PKI Root CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.now() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    return private_key, cert


def encrypt_with_public_key(public_key, plaintext):
    plaintext = plaintext.encode() if isinstance(plaintext, str) else plaintext

    # Generate a random symmetric key
    symmetric_key = os.urandom(32)

    # Encrypt the symmetric key with the public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt the plaintext with the symmetric key
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return encrypted_symmetric_key + encryptor.tag + nonce + ciphertext


def decrypt_with_private_key(private_key, encrypted_data):
    # Decrypt the symmetric key with the private key
    encrypted_symmetric_key = encrypted_data[:256]
    # import pdb; pdb.set_trace()
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt the ciphertext with the symmetric key
    tag = encrypted_data[256:272]
    nonce = encrypted_data[272:284]
    encrypted_data = encrypted_data[284:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


def sign_certificate(pki_private_key, pki_cert, public_key, name):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    issuer = pki_cert.subject

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow().replace(microsecond=0))
        .not_valid_after(datetime.utcnow().replace(microsecond=0) + timedelta(days=365))
        .sign(pki_private_key, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(Encoding.PEM)


def sign_with_private_key(private_key, message):
    signature = private_key.sign(
        message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_with_public_key(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False


class Node:
    def __init__(self, name, pki_address, pki_cert):
        self.name = name
        self.pki_address = pki_address
        self.pki_cert = pki_cert
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificates = {}
        self.certificates[self.name] = None
        self.shared_secrets = {}

    def request_signed_certificate(self, node_name):
        encrypted_public_key = encrypt_with_public_key(self.pki_cert.public_key(),
                                                       self.public_key.public_bytes(Encoding.PEM,
                                                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
        request = {
            "request_type": "request_certificate",
            "name": node_name,
            "public_key": encrypted_public_key
        }
        serialized_request = pickle.dumps(request)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.pki_address)
        print(f"Connected to PKI at: {self.pki_address[0]}:{self.pki_address[1]}")  # line for debugging
        s.sendall(serialized_request)
        # time.sleep(2)
        response = b""
        while True:
            ready_to_read, _, _ = select.select([s], [], [], 2.0)  # Attend jusqu'à 2 secondes pour les données
            if ready_to_read:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            else:
                break
            response += data
        print(f"Received data of size: {len(response)}")  # line for debugging
        s.close()
        signed_certificate_bytes = pickle.loads(response)
        signed_certificate = load_pem_x509_certificate(signed_certificate_bytes, default_backend())
        self.certificates[node_name] = signed_certificate

    def generate_shared_secret(self, node_name, node_public_key):
        shared_secret = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        self.shared_secrets[node_name] = shared_secret
        encrypted_secret = encrypt_with_public_key(node_public_key, shared_secret.encode())

        # afficher les valeurs
        print(f"Shared secret for {node_name}: {shared_secret}")
        print(f"Current shared_secrets dictionary: {self.shared_secrets}")

        return encrypted_secret

    def get_shared_secret(self, node_name):
        return self.shared_secrets.get(node_name)

    def encrypt_message(self, node_name, message):
        secret = self.get_shared_secret(node_name)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(secret.encode()), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_message(self, node_name, encrypted_message):
        secret = self.get_shared_secret(node_name)
        if secret is None:
            raise ValueError(f"No shared secret found for {node_name}")
        iv, ciphertext = encrypted_message[:16], encrypted_message[16:]
        cipher = Cipher(algorithms.AES(secret.encode()), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(padded_message) + unpadder.finalize()
        return decrypted_message.decode('utf-8')

    def send_encrypted_message(self, recipient_name, message, recipient_address, recipient_port):
        recipient_cert = self.certificates[recipient_name]
        recipient_public_key = recipient_cert.public_key()
        encrypted_message = encrypt_with_public_key(recipient_public_key, message.encode())
        print("Encrypted message: ", encrypted_message)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((recipient_address, recipient_port))
            s.sendall(encrypted_message)
            print(f"Message sent to {recipient_name}: {message}")

    def receive_encrypted_message(self, bind_address, bind_port, node_a_name, node_b_name, message_queue):
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((bind_address, bind_port))
            s.listen()

            print(f"Listening on {bind_address}:{bind_port}")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connection established with: {addr}")
                    encrypted_message = conn.recv(4096)
                    print(f"Connected by {addr}")

                    try:
                        if addr[0] == '127.0.0.1':
                            node_name = node_b_name if self.name == node_a_name else node_a_name
                            decrypted_message = self.decrypt_message(node_name, encrypted_message)
                        else:
                            decrypted_message = self.decrypt_message(addr[0], encrypted_message)

                        print(f"Decrypted message: {decrypted_message.decode()}")
                        message_queue.put(decrypted_message.decode())
                    finally:
                        break


    def get_shared_secret(self, node_name):
        return self.shared_secrets.get(node_name)


def pki_server(pki_private_key, pki_cert):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", PKI_PORT))
    server_socket.listen(5)

    while True:
        conn, addr = server_socket.accept()
        data = conn.recv(4096)
        if not data:
            break

        request = pickle.loads(data)

        if "request_type" in request:
            if request["request_type"] == "shutdown":
                break

            if request["request_type"] == "request_certificate":
                encrypted_public_key_pem = request["public_key"]
                name = request["name"]

                # Decrypt the public key before loading it
                public_key_pem = decrypt_with_private_key(pki_private_key, encrypted_public_key_pem)
                public_key = load_pem_public_key(public_key_pem, backend=default_backend())

                certificate = sign_certificate(pki_private_key, pki_cert, public_key, name)
                response = pickle.dumps(certificate)
                print(f"Sending data of size: {len(response)}")
                conn.sendall(response)

        conn.close()

    server_socket.close()


def main():
    PKI_ADDRESS = ('localhost', 9000)
    pki_private_key, pki_cert = create_pki_keys_and_certificate()
    pki_server_thread = threading.Thread(target=pki_server, args=(pki_private_key, pki_cert))
    pki_server_thread.start()

    node_a = Node("Node A", PKI_ADDRESS, pki_cert)
    node_b = Node("Node B", PKI_ADDRESS, pki_cert)

    print("Node A private key:\n", node_a.private_key)
    print("Node A public key:\n", node_a.public_key)
    print("Node B private key:\n", node_b.private_key)
    print("Node B public key:\n", node_b.public_key)

    node_a.request_signed_certificate(node_b.name)
    print("Node A certificate:\n", node_a.certificates[node_b.name])
    node_b.request_signed_certificate(node_a.name)
    print("Node B certificate:\n", node_b.certificates[node_a.name])

    node_a_message_queue = Queue()
    node_b_message_queue = Queue()
    message_queue = queue.Queue()


    node_a_listen_thread = threading.Thread(target=node_a.receive_encrypted_message, args=("localhost", 9001, node_a.name, node_b.name, message_queue))

    node_a_listen_thread.start()

    node_b_listen_thread = threading.Thread(target=node_b.receive_encrypted_message, args=("localhost", 9002, node_a.name, node_b.name, message_queue))
    node_b_listen_thread.start()

    node_a.send_encrypted_message(node_b.name, "Hello, Node B!", "localhost", 9002)
    print(f"Node A sent message: {'Hello, Node B!'}")

    node_b.send_encrypted_message(node_a.name, "Hi, Node A! I got your message.", "localhost", 9001)
    print(f"Node B sent message: {'Hi, Node A! I got your message.'}")
   
    node_a_listen_thread.join()
    node_b_listen_thread.join()

    node_a_public_key_from_cert = node_a.certificates[node_b.name].public_key()
    node_b_public_key_from_cert = node_b.certificates[node_a.name].public_key()

    print("Node A public key from certificate:\n", node_a_public_key_from_cert)
    print("Node B public key from certificate:\n", node_b_public_key_from_cert)

    if node_a.public_key.public_numbers() == node_a_public_key_from_cert.public_numbers():
        print("Node A public keys match")
    else:
        print("Node A public keys do not match")

    if node_b.public_key.public_numbers() == node_b_public_key_from_cert.public_numbers():
        print("Node B public keys match")
    else:
        print("Node B public keys do not match")

    # Génération des secrets partagés
    node_a.generate_shared_secret("Node B", node_b_public_key_from_cert)
    node_b.generate_shared_secret("Node A", node_a_public_key_from_cert)


if __name__ == "__main__":
    main()