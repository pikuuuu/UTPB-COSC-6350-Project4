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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', PORT))
        print("Connected to AP Server.")

        ap_nonce = client_socket.recv(16)
        print("AP Nonce received.")

        client_nonce = secrets.token_bytes(16)
        client_socket.sendall(client_nonce)
        print("Client Nonce sent.")

        ap_public_key_length = int.from_bytes(client_socket.recv(4), 'big')
        ap_public_key_bytes = client_socket.recv(ap_public_key_length)
        print(f"AP Public Key (hex): {bytes_to_hex(ap_public_key_bytes)}")

        client_key_pair = generate_key_pair()
        client_public_key_bytes = client_key_pair.public_key().export_key(format='DER')
        client_socket.sendall(len(client_public_key_bytes).to_bytes(4, 'big') + client_public_key_bytes)
        print(f"Client Public Key (hex): {bytes_to_hex(client_public_key_bytes)}")

        ap_public_key = ECC.import_key(ap_public_key_bytes)
        
        shared_key = generate_shared_secret(client_key_pair, ap_public_key)
        print(f"Shared Key (hex): {bytes_to_hex(shared_key)}")

        encrypted_confirmation_length = int.from_bytes(client_socket.recv(4), 'big')
        encrypted_confirmation = client_socket.recv(encrypted_confirmation_length)
        confirmation_message = decrypt(encrypted_confirmation, shared_key)
        print(f"Decrypted Confirmation: {confirmation_message.decode()}")

        acknowledgment_message = "Acknowledged"
        client_socket.sendall(acknowledgment_message.encode())
        print("Acknowledgment sent.")

        encrypted_message_length = int.from_bytes(client_socket.recv(4), 'big')
        encrypted_message = client_socket.recv(encrypted_message_length)
        message_decrypted = decrypt(encrypted_message, shared_key)
        print(f"Decrypted Message: {message_decrypted.decode()}")

if __name__ == "__main__":
    main()