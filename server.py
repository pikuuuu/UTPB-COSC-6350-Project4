import socket
import secrets
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

PORT = 12345
BUFFER_SIZE = 4096

def generate_key_pair():
    return ECC.generate(curve='P-256')

def generate_shared_secret(private_key, public_key):
    
    shared_point = private_key.d * public_key.pointQ
   
    shared_secret = int(shared_point.x).to_bytes((shared_point.x.size_in_bits() + 7) // 8, byteorder='big')
    
    return HKDF(shared_secret, 16, b'', SHA256)

def encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data

def decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

def bytes_to_hex(data):
    return ''.join(f'{b:02X}' for b in data)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(1)
        print(f"AP Server is listening on port {PORT}")
        
        conn, addr = server_socket.accept()
        with conn:
            print("Client connected.")
            ap_nonce = secrets.token_bytes(16)
            conn.sendall(ap_nonce)
            print("AP Nonce sent.")

            client_nonce = conn.recv(16)
            print("Client Nonce received.")

            ap_key_pair = generate_key_pair()
            ap_public_key = ap_key_pair.public_key().export_key(format='DER')
            conn.sendall(len(ap_public_key).to_bytes(4, 'big') + ap_public_key)
            print(f"AP Public Key (hex): {bytes_to_hex(ap_public_key)}")

            client_public_key_length = int.from_bytes(conn.recv(4), 'big')
            client_public_key_bytes = conn.recv(client_public_key_length)
            print(f"Client Public Key (hex): {bytes_to_hex(client_public_key_bytes)}")

            client_public_key = ECC.import_key(client_public_key_bytes)
            
            shared_key = generate_shared_secret(ap_key_pair, client_public_key)
            print(f"Shared Key (hex): {bytes_to_hex(shared_key)}")

            confirmation_message = b"Confirmation"
            encrypted_confirmation = encrypt(confirmation_message, shared_key)
            conn.sendall(len(encrypted_confirmation).to_bytes(4, 'big') + encrypted_confirmation)
            print(f"Encrypted Confirmation (hex): {bytes_to_hex(encrypted_confirmation)}")

            client_ack = conn.recv(BUFFER_SIZE).decode()
            print(f"Client acknowledgment received: {client_ack}")

            message = b"Hello from AP!"
            encrypted_message = encrypt(message, shared_key)
            conn.sendall(len(encrypted_message).to_bytes(4, 'big') + encrypted_message)
            print(f"Encrypted Message (hex): {bytes_to_hex(encrypted_message)}")

if __name__ == "__main__":
    main()