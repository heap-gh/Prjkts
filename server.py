
import socket
import argparse
import random

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

def diffie_hellman_key_exchange(client_socket: socket, secret: int) -> bytes:

    print("[STATUS] Establishing a shared secret with DH")

    try:

        if secret is None:
            secret = random.randint(1, pow(2, 10))

        # receive g, n, gxmodn

        message = client_socket.recv(1024)

        n = int.from_bytes(message[0:32], "big")
        g = int.from_bytes(message[32:33], "big")
        gxmodn = int.from_bytes(message[33:], "big")


        # calculate g^xy mod n and send g^y mod n

        client_socket.sendall(pow(g, secret, n).to_bytes(32, "big"))

        key = pow(gxmodn, secret, n).to_bytes(32, "big")

        print(f"[INFO] established_secret: {key.hex()}")

        return key

    # in case exchange
    except Exception as e:

        print(f"Exception : {e}")
        return b''



def hkdf(secret: bytes, hkdflabel: bytes, length: int) -> bytes:

    hkdf_ye = HKDFExpand(
        algorithm=hashes.SHA384(),
        length=length,
        info=hkdflabel,
    )
    key = hkdf_ye.derive(secret)

    return key


def generate_hkdflabel(sender: str, purpose: str, length: int) -> bytes:

    length_bytes = length.to_bytes(2, "big")
    label = ("tls13 " + sender + " ap traffic " + purpose).encode()
    label_length = len(label).to_bytes(1, "big")
    context = "".encode()
    context_length = len(context).to_bytes(1, "big")

    return length_bytes + label_length + label + context_length + context


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:

    # Create an AES-GCM cipher object with the provided key
    cipher = AESGCM(key)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    return plaintext

# Chat-GPT -> "Encrypt a text message with AESGCM in python"
def encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:

    # Create an AES-GCM cipher object with the provided key
    cipher = AESGCM(key)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    return ciphertext


def receive_message(client_socket: socket, client_key: bytes, sequence_number: int, padding: bytes, client_iv: bytes) -> str:

    message_received = client_socket.recv(1024)

    length = int.from_bytes(message_received[:1], "big")

    aead = padding + sequence_number.to_bytes(8, "big")

    nonce = xor_bytes(aead, client_iv)

    ciphertext = message_received[1:]


    print(f"[INFO] received_data: {message_received.hex()}")
    print(f"[INFO] nonce_receiving: {nonce.hex()}")

    message_decrypted = decrypt(ciphertext, client_key, nonce).decode()

    print(f"[INFO] received_decrypted_message: {message_decrypted}")

    return message_decrypted

def xor_bytes(byte_str1, byte_str2):

    return bytes(x ^ y for x, y in zip(byte_str1, byte_str2))


def send_message(client_socket: socket, message: str, iv: bytes, key: bytes, sequence_number: int, padding: bytes):

    new_message = "echo: " + message

    length = len(new_message).to_bytes(1, "big")

    aead = padding + sequence_number.to_bytes(8, "big")

    nonce = xor_bytes(aead, iv)

    ciphertext = encrypt(new_message.encode(), key, nonce)

    client_socket.sendall(length + ciphertext)


    print(f"[INFO] message_to_send: {new_message}")
    print(f"[INFO] nonce_sending: {nonce.hex()}")


def start_server(port: int, secret: int):

    host = '127.0.0.1'

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    while True:

        print("[STATUS] waiting for a new connection")
        server.listen(1)
        client_socket, client_address = server.accept()
        print(f"[STATUS] accepted connection from {client_address}")

        # perform diffie hellmann key exchange
        secret_key = diffie_hellman_key_exchange(client_socket, secret)

        if secret_key != b'':

            # continue

            print("[STATUS] Deriving Keys and IVs")

            server_iv = hkdf(secret_key, generate_hkdflabel("server", "iv", 12), 12)
            server_key = hkdf(secret_key, generate_hkdflabel("server", "key", 32), 32)
            client_iv = hkdf(secret_key, generate_hkdflabel("client", "iv", 12), 12)
            client_key = hkdf(secret_key, generate_hkdflabel("client", "key", 32), 32)

            print(f"[INFO] client_key: {client_key.hex()}")
            print(f"[INFO] server_key: {server_key.hex()}")
            print(f"[INFO] client_iv: {client_iv.hex()}")
            print(f"[INFO] server_iv: {server_iv.hex()}")

            server_writing = 0
            client_reading = 0
            client_writing = 0
            server_reading = 0

            padding = b'\x00\x00\x00\x00'

            while True:

                try:

                    plain_text = receive_message(client_socket, client_key, client_reading, padding, client_iv)
                    client_writing += 1
                    client_reading += 1

                    send_message(client_socket, plain_text, server_iv, server_key, server_writing, padding)
                    server_writing += 1
                    server_reading += 1

                # in case client disconnects
                except Exception as e:
                    break


        else:
            client_socket.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--port", action="store", required=True, help="add server port")
    parser.add_argument("--y", action="store", required=False, help="servers secret int")
    args = parser.parse_args()

    port_number = int(args.port)
    secret_number = int(args.y) if args.y is not None else None

    start_server(port_number, secret_number)
