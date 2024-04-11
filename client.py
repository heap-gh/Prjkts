
import socket
import argparse
import random

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


n = pow(2, 256) - 189
g = 2


def diffie_hellman_key_exchange(client_socket: socket, secret: int) -> bytes:

    print("[STATUS] Establishing a shared secret with DH")

    try:

        if secret is None:
            secret = random.randint(1, pow(2, 10))

        # send g, n, g^x mod n

        message = n.to_bytes(32, "big") + g.to_bytes(1, "big") + pow(g, secret, n).to_bytes(32, "big")
        client_socket.sendall(message)

        # receive g^y mod n and calculate g^yx mod n
        gymodn = int.from_bytes(client_socket.recv(1024), "big")

        key = pow(gymodn, secret, n).to_bytes(32, "big")

        print(f"[INFO] established_secret: {key.hex()}")

        return key

    except Exception as e:

        print(f"Exception: {e}")
        return b''


def generate_hkdflabel(sender: str, purpose: str, length: int) -> bytes:

    length_bytes = length.to_bytes(2, "big")
    label = ("tls13 " + sender + " ap traffic " + purpose).encode()
    label_length = len(label).to_bytes(1, "big")
    context = "".encode()
    context_length = len(context).to_bytes(1, "big")

    return length_bytes + label_length + label + context_length + context


def hkdf(secret: bytes, hkdflabel: bytes, length: int) -> bytes:

    hkdf_ye = HKDFExpand(
        algorithm=hashes.SHA384(),
        length=length,
        info=hkdflabel,
    )
    key = hkdf_ye.derive(secret)

    return key


def xor_bytes(byte_str1, byte_str2):

    return bytes(x ^ y for x, y in zip(byte_str1, byte_str2))


# Chat-GPT -> "Encrypt a text message with AESGCM in python"
def encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:

    cipher = AESGCM(key)

    ciphertext = cipher.encrypt(nonce, plaintext, None)

    return ciphertext


def send_message(client_socket: socket, sequence_number: int, padding: bytes, iv: bytes, key: bytes):

    # get terminal input

    user_input = ""

    while len(user_input) < 1 or len(user_input) > 101:
        user_input = str(input("[STATUS] Please type in a message that should be sent. . .\n"))

    length = len(user_input).to_bytes(1, "big")

    # calculate nonce

    aead = padding + sequence_number.to_bytes(8, "big")

    nonce = xor_bytes(aead, iv)

    print(f"[INFO] message_to_send: {user_input}")
    print(f"[INFO] nonce_sending: {nonce.hex()}")

    # encrypt the message and send it with 1 byte field of length of the decrypted message (in bytes)
    # send the nonce

    ciphertext = encrypt(user_input.encode(), key, nonce)

    client_socket.sendall(length + ciphertext)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:

    # Create an AES-GCM cipher object with the provided key
    cipher = AESGCM(key)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    return plaintext


def receive_message(client_socket: socket, server_key: bytes, sequence_number: int, padding: bytes, server_iv: bytes):

    message_received = client_socket.recv(1024)

    length = int.from_bytes(message_received[:1], "big")

    aead = padding + sequence_number.to_bytes(8, "big")

    nonce = xor_bytes(aead, server_iv)

    ciphertext = message_received[1:]

    message_decrypted = decrypt(ciphertext, server_key, nonce).decode()

    print(f"[INFO] received_data: {message_received.hex()}")
    print(f"[INFO] nonce_receiving: {nonce.hex()}")
    print(f"[INFO] received_decrypted_message: {message_decrypted}")


def start_connection(addr: str, port: int, secret: int):

    # start the connection
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((addr, port))

    # start the key exchange protocol
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

        padding = b'\x00\x00\x00\x00'
        server_writing = 0
        client_reading = 0
        client_writing = 0
        server_reading = 0

        while True:

            send_message(client_socket, client_writing, padding, client_iv, client_key)
            client_writing += 1
            client_reading += 1


            receive_message(client_socket, server_key, server_reading, padding, server_iv)
            server_writing += 1
            server_reading += 1

    else:
        client_socket.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--serv", required=True, action="store", help="The IPv4 address of the server")
    parser.add_argument("--port", required=True, action="store", help="The port of the server")
    parser.add_argument("--x", required=False, action="store", help="the clients secret int")
    args = parser.parse_args()

    addr_number = str(args.serv)
    port_number = int(args.port)
    secret_number = int(args.x) if args.x is not None else None

    start_connection(addr_number, port_number, secret_number)
