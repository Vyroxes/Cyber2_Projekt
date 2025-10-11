from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QLabel, QMessageBox, QComboBox, QProgressBar, QGroupBox, QHBoxLayout
from PyQt5.QtWinExtras import QWinTaskbarButton
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from Crypto.Cipher import AES, DES3, PKCS1_OAEP, PKCS1_v1_5, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from skein import skein256, skein512, skein1024, threefish
import os
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

class EncryptDecryptThread(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(str)

    def __init__(self, file_path, key_path, algorithm, mode, padding, key_size, decrypt=False, save_path=None):
        super().__init__()
        self.file_path = file_path
        self.key_path = key_path
        self.algorithm = algorithm
        self.mode = mode
        self.padding = padding
        self.key_size = key_size
        self.decrypt = decrypt
        self.save_path = save_path

    def run(self):
        try:
            file_size = os.path.getsize(self.file_path)
            processed_size = 0
            chunk_size = 1 * 1024 * 1024

            with open(self.file_path, "rb") as f:
                data = f.read()

            if self.algorithm == "AES":
                with open(self.key_path, "rb") as f:
                    key = f.read()
                if len(key) != self.key_size//8 or len(key) not in (16, 24, 32):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz ma długość " + str(len(key) * 8) + "-bitów.")

                if self.decrypt:
                    if self.mode == "GCM-MAC":
                        nonce, tag, ciphertext = data[:12], data[-16:], data[12:-16]
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        try:
                            cipher.verify(tag)
                            operation_message = "Plik został deszyfrowany!"
                        except ValueError:
                            decrypted_data = b""
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")

                    elif self.mode == "EAX-MAC":
                        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
                        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        try:
                            cipher.verify(tag)
                            operation_message = "Plik został deszyfrowany!"
                        except ValueError:
                            decrypted_data = b""
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")

                    elif self.mode == "CBC":
                        iv, ciphertext = data[:16], data[16:]
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        padding_length = decrypted_data[-1]
                        decrypted_data = decrypted_data[:-padding_length]
                        operation_message = "Plik został deszyfrowany!"

                    elif self.mode == "ECB":
                        ciphertext = data
                        cipher = AES.new(key, AES.MODE_ECB)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        padding_length = decrypted_data[-1]
                        decrypted_data = decrypted_data[:-padding_length]
                        operation_message = "Plik został deszyfrowany!"
                else:
                    if self.mode == "GCM-MAC":
                        nonce = get_random_bytes(12)
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        encrypted_data = b""
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        encrypted_data = nonce + encrypted_data + cipher.digest()
                        operation_message = "Plik został zaszyfrowany!"

                    elif self.mode == "EAX-MAC":
                        cipher = AES.new(key, AES.MODE_EAX)
                        encrypted_data = b""
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        encrypted_data = cipher.nonce + cipher.digest() + encrypted_data
                        operation_message = "Plik został zaszyfrowany!"

                    elif self.mode == "CBC":
                        iv = get_random_bytes(16)
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        padding_length = 16 - (len(data) % 16)
                        data += bytes([padding_length]) * padding_length
                        encrypted_data = b""
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        encrypted_data = iv + encrypted_data
                        operation_message = "Plik został zaszyfrowany!"

                    elif self.mode == "ECB":
                        cipher = AES.new(key, AES.MODE_ECB)
                        padding_length = 16 - (len(data) % 16)
                        data += bytes([padding_length]) * padding_length
                        encrypted_data = b""
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        operation_message = "Plik został zaszyfrowany!"

            elif self.algorithm == "RSA-HMAC":
                with open(self.key_path, "rb") as f:
                    key = RSA.import_key(f.read())
                key_size_bits = key.size_in_bits()
                if key_size_bits != self.key_size or key_size_bits not in (1024, 2048, 3072, 4096):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz ma długość " + str(key_size_bits) + "-bitów.")
                if not self.decrypt and key.has_private():
                    key = key.publickey()

                if self.padding == "OAEP":
                    cipher = PKCS1_OAEP.new(key)
                    chunk_size = key.size_in_bytes() - 42
                elif self.padding == "PKCS1 v1.5":
                    cipher = PKCS1_v1_5.new(key)
                    chunk_size = key.size_in_bytes() - 11

                if self.decrypt:
                    if not key.has_private():
                        raise ValueError("Błąd: Wybrany klucz nie jest kluczem prywatnym!")

                    hmac_received = data[:32]
                    encrypted_data = data[32:]

                    hmac_key = key.publickey().export_key()
                    if hmac_received != HMAC.new(hmac_key, encrypted_data, SHA256).digest():
                        raise ValueError("Błąd: Nie udało się zweryfikować tagu HMAC!")

                    decrypted_data = b""
                    for i in range(0, len(encrypted_data), key.size_in_bytes()):
                        chunk = encrypted_data[i:i + key.size_in_bytes()]
                        if self.padding == "PKCS1 v1.5":
                            sentinel = b"ERROR"
                            decrypted_chunk = cipher.decrypt(chunk, sentinel)
                            if decrypted_chunk == sentinel:
                                raise ValueError("Błąd: Integralność pliku nie została zachowana!")
                            
                        elif self.padding == "OAEP":
                            try:
                                decrypted_chunk = cipher.decrypt(chunk)
                            except ValueError:
                                raise ValueError("Błąd: Integralność pliku nie została zachowana!")
                        decrypted_data += decrypted_chunk
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)

                    operation_message = "Plik został deszyfrowany!"
                else:


                    encrypted_data = b""
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        encrypted_data += cipher.encrypt(chunk)
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)

                    hmac_key = key.export_key()
                    hmac_tag = HMAC.new(hmac_key, encrypted_data, SHA256).digest()
                    encrypted_data = hmac_tag + encrypted_data
                    operation_message = "Plik został zaszyfrowany!"

            elif self.algorithm == "3DES":
                with open(self.key_path, "rb") as f:
                    key = f.read()
                if len(key) != 24:
                    raise ValueError("Błąd: Nieprawidłowa długość klucza 3DES! Użyj klucza 192-bitowego.")
                
                if self.decrypt:
                    if self.mode == "EAX-MAC":
                        nonce, tag, ciphertext = data[:16], data[16:24], data[24:]
                        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        try:
                            cipher.verify(tag)
                            operation_message = "Plik został deszyfrowany!"
                        except ValueError:
                            raise ValueError("Błąd: Nie udało się zweryfikować tagu MAC!")
                        
                    elif self.mode == "CFB":
                        iv, ciphertext = data[:8], data[8:]
                        cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        operation_message = "Plik został deszyfrowany!"
                    elif self.mode == "OFB":
                        iv, ciphertext = data[:8], data[8:]
                        cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
                        decrypted_data = b""
                        for i in range(0, len(ciphertext), chunk_size):
                            chunk = ciphertext[i:i + chunk_size]
                            decrypted_data += cipher.decrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        operation_message = "Plik został deszyfrowany!"
                else:
                    if self.mode == "EAX-MAC":
                        cipher = DES3.new(key, DES3.MODE_EAX)
                        encrypted_data = b""
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        encrypted_data = cipher.nonce + cipher.digest() + encrypted_data
                        operation_message = "Plik został zaszyfrowany!"
                    elif self.mode == "CFB":
                        iv = get_random_bytes(8)
                        cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
                        encrypted_data = iv
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        operation_message = "Plik został zaszyfrowany!"
                    elif self.mode == "OFB":
                        iv = get_random_bytes(8)
                        cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
                        encrypted_data = iv
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i + chunk_size]
                            encrypted_data += cipher.encrypt(chunk)
                            processed_size += len(chunk)
                            progress = int((processed_size / file_size) * 100)
                            self.progress_signal.emit(progress)
                        operation_message = "Plik został zaszyfrowany!"

            elif self.algorithm == "XChaCha20-Poly1305":
                with open(self.key_path, "rb") as f:
                    key = f.read()
                if len(key) != 32:
                    raise ValueError("Błąd: Nieprawidłowa długość klucza XChaCha20-Poly1305! Użyj klucza 256-bitowego.")
                if self.decrypt:
                    nonce, tag, ciphertext = data[:24], data[-16:], data[24:-16]
                    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                    decrypted_data = b""
                    for i in range(0, len(ciphertext), chunk_size):
                        decrypted_data += cipher.decrypt(ciphertext[i:i + chunk_size])
                        processed_size += len(ciphertext[i:i + chunk_size])
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)
                    try:
                        cipher.verify(tag)
                        operation_message = "Plik został deszyfrowany!"
                    except ValueError:
                        raise ValueError("Błąd: Nie udało się zweryfikować tagu Poly1305!")
                else:
                    nonce = get_random_bytes(24)
                    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                    encrypted_data = b""
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        encrypted_data += cipher.encrypt(chunk)
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)
                    tag = cipher.digest()
                    encrypted_data = nonce + encrypted_data + tag
                    operation_message = "Plik został zaszyfrowany!"
                    
            elif self.algorithm == "Threefish-Skein":
                with open(self.key_path, "rb") as f:
                    key = f.read()
                if len(key) != self.key_size//8 or len(key) not in (32, 64, 128):
                    raise ValueError("Błąd: Nieprawidłowa długość klucza! Wymagany klucz " + str(self.key_size) + "-bitowy, a podany klucz ma długość " + str(len(key) * 8) + "-bitów.")
                tweak = bytes(15) + b"\x3f"
                
                if self.decrypt:
                    if len(key) == 32:
                        hash_func = skein256
                        tag_size = 32
                    elif len(key) == 64:
                        hash_func = skein512
                        tag_size = 64
                    else:
                        hash_func = skein1024
                        tag_size = 128
                        
                    nonce, tag, ciphertext = data[:16], data[-tag_size:], data[16:-tag_size]
                    decrypted_data = b""
                    block_size = len(key)
                    
                    tf = threefish(key, tweak)

                    for i in range(0, len(ciphertext), block_size):
                        chunk = ciphertext[i:i + block_size]
                        if len(chunk) < block_size:
                            chunk = chunk.ljust(block_size, b'\x00')
                        decrypted_chunk = tf.decrypt_block(chunk)
                        decrypted_data += decrypted_chunk[:min(len(chunk), len(ciphertext) - i)]
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)
                    
                    if len(key) == 32:
                        hash_func = skein256
                    elif len(key) == 64:
                        hash_func = skein512
                    else:
                        hash_func = skein1024
                        
                    decrypted_data = decrypted_data.rstrip(b'\x00')
                    calculated_hash = hash_func(decrypted_data).digest()
                    if calculated_hash != tag:
                        raise ValueError("Błąd: Nie udało się zweryfikować tagu Skein!")
                    operation_message = "Plik został deszyfrowany!"
                else:
                    encrypted_data = b""
                    block_size = len(key)
                    nonce = get_random_bytes(16)
                    
                    tf = threefish(key, tweak)
                    
                    for i in range(0, len(data), block_size):
                        chunk = data[i:i + block_size]
                        if len(chunk) < block_size:
                            chunk = chunk.ljust(block_size, b'\x00')
                        encrypted_chunk = tf.encrypt_block(chunk)
                        encrypted_data += encrypted_chunk
                        processed_size += len(chunk)
                        progress = int((processed_size / file_size) * 100)
                        self.progress_signal.emit(progress)
                    
                    if len(key) == 32:
                        hash_func = skein256
                    elif len(key) == 64:
                        hash_func = skein512
                    else:
                        hash_func = skein1024
                        
                    tag = hash_func(data).digest()
                    encrypted_data = nonce + encrypted_data + tag
                    operation_message = "Plik został zaszyfrowany!"

            if self.decrypt:
                dec_path = self.save_path if self.save_path else self.file_path.replace(".enc", ".dec")
                with open(dec_path, "wb") as f:
                    f.write(decrypted_data)
            else:
                enc_path = self.save_path if self.save_path else self.file_path + ".enc"
                with open(enc_path, "wb") as f:
                    f.write(encrypted_data)

            self.progress_signal.emit(100)
            self.finished_signal.emit(operation_message)
        except Exception as e:
            self.finished_signal.emit(str(e))

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon("icon.png"))
        self.initUI()
        self.taskbar_button = None
        self.taskbar_progress = None

    def initUI(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2e2e2e;
                color: #ffffff;
                font-family: Arial, sans-serif;
                font-size: 14px;
                font-weight: bold;
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
            }
            QPushButton {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #4c5052;
            }
            QPushButton:pressed {
                background-color: #5c6062;
            }
            QComboBox {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 3px;
                font-size: 14px;
                padding-left: 6px;
            }
            QComboBox QAbstractItemView {
                background-color: #3c3f41;
                color: #ffffff;
                selection-background-color: #4c5052;
                padding: 3px;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                color: #ffffff;
            }
            QProgressBar {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                text-align: center;
                font-size: 14px;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        file_group = QGroupBox("Plik do szyfrowania/deszyfrowania")
        self.label = QLabel("Plik: nie wybrano")
        file_layout = QVBoxLayout()
        file_layout.addWidget(self.label)
        file_buttons_layout = QHBoxLayout()
        self.file_button = QPushButton("Wybierz plik")
        self.file_button.clicked.connect(self.select_file)
        file_buttons_layout.addWidget(self.file_button)
        self.clear_file_button = QPushButton("X")
        self.clear_file_button.setFixedWidth(30)
        self.clear_file_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
            }
            QPushButton:hover {
                background-color: #ff7777;
            }
        """)
        self.clear_file_button.clicked.connect(self.clear_file_path)
        self.clear_file_button.setVisible(False)
        file_buttons_layout.addWidget(self.clear_file_button)

        file_layout.addLayout(file_buttons_layout)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        algo_group = QGroupBox("Algorytm")
        algo_layout = QVBoxLayout()
        self.algorithm_label = QLabel("Wybierz algorytm:")
        algo_layout.addWidget(self.algorithm_label)
        self.algorithm_box = QComboBox()
        self.algorithm_box.addItems(["AES", "RSA-HMAC", "3DES", "XChaCha20-Poly1305", "Threefish-Skein"])
        self.algorithm_box.currentIndexChanged.connect(self.update_algorithm_settings)
        algo_layout.addWidget(self.algorithm_box)
        self.additional_options_button = QPushButton("Ustawienia algorytmu ▼")
        self.additional_options_button.clicked.connect(self.toggle_additional_options)
        algo_layout.addWidget(self.additional_options_button)

        self.additional_options_widget = QWidget()
        additional_options_layout = QVBoxLayout()

        # Opcje AES
        self.aes_options_widget = QWidget()
        aes_options_layout = QVBoxLayout()
        self.aes_key_size_label = QLabel("Wybierz długość klucza AES (bit):")
        aes_options_layout.addWidget(self.aes_key_size_label)
        self.aes_key_size_box = QComboBox()
        self.aes_key_size_box.addItems(["128", "192", "256"])
        self.aes_key_size_box.setCurrentIndex(2)
        aes_options_layout.addWidget(self.aes_key_size_box)
        self.aes_mode_label = QLabel("Wybierz tryb AES:")
        aes_options_layout.addWidget(self.aes_mode_label)
        self.aes_mode_box = QComboBox()
        self.aes_mode_box.addItems(["GCM-MAC", "EAX-MAC", "CBC", "ECB"])
        aes_options_layout.addWidget(self.aes_mode_box)
        self.aes_options_widget.setLayout(aes_options_layout)
        additional_options_layout.addWidget(self.aes_options_widget)

        # Opcje RSA-HMAC
        self.rsa_options_widget = QWidget()
        rsa_options_layout = QVBoxLayout()
        self.rsa_key_size_label = QLabel("Wybierz długość kluczy RSA-HMAC (bit):")
        rsa_options_layout.addWidget(self.rsa_key_size_label)
        self.rsa_key_size_box = QComboBox()
        self.rsa_key_size_box.addItems(["1024", "2048", "3072", "4096"])
        self.rsa_key_size_box.setCurrentIndex(1)
        rsa_options_layout.addWidget(self.rsa_key_size_box)
        self.rsa_padding_label = QLabel("Wybierz padding RSA-HMAC:")
        rsa_options_layout.addWidget(self.rsa_padding_label)
        self.rsa_padding_box = QComboBox()
        self.rsa_padding_box.addItems(["PKCS1 v1.5", "OAEP"])
        self.rsa_padding_box.setCurrentIndex(1)
        rsa_options_layout.addWidget(self.rsa_padding_box)
        self.rsa_options_widget.setLayout(rsa_options_layout)
        additional_options_layout.addWidget(self.rsa_options_widget)
        self.rsa_options_widget.setVisible(False)

        # Opcje 3DES
        self.des_options_widget = QWidget()
        des_options_layout = QVBoxLayout()
        self.des_mode_label = QLabel("Wybierz tryb 3DES:")
        des_options_layout.addWidget(self.des_mode_label)
        self.des_mode_box = QComboBox()
        self.des_mode_box.addItems(["EAX-MAC", "CFB", "OFB"])
        des_options_layout.addWidget(self.des_mode_box)
        self.des_options_widget.setLayout(des_options_layout)
        additional_options_layout.addWidget(self.des_options_widget)
        self.des_options_widget.setVisible(False)

        # Opcje Threefish-Skein
        self.threefish_options_widget = QWidget()
        threefish_options_layout = QVBoxLayout()
        self.threefish_key_size_label = QLabel("Wybierz długość klucza Threefish-Skein (bit):")
        threefish_options_layout.addWidget(self.threefish_key_size_label)
        self.threefish_key_size_box = QComboBox()
        self.threefish_key_size_box.addItems(["256", "512", "1024"])
        self.threefish_key_size_box.setCurrentIndex(2)
        threefish_options_layout.addWidget(self.threefish_key_size_box)
        self.threefish_options_widget.setLayout(threefish_options_layout)
        additional_options_layout.addWidget(self.threefish_options_widget)
        self.threefish_options_widget.setVisible(False)

        self.additional_options_widget.setLayout(additional_options_layout)
        self.additional_options_widget.setVisible(False)
        algo_layout.addWidget(self.additional_options_widget)
        algo_group.setLayout(algo_layout)
        main_layout.addWidget(algo_group)

        self.key_group = QGroupBox("Klucz")
        self.key_layout = QVBoxLayout()
        self.key_label = QLabel("Klucz: nie wybrano")
        self.key_layout.addWidget(self.key_label)
        key_buttons_layout = QHBoxLayout()
        self.key_button = QPushButton("Wybierz klucz")
        self.key_button.clicked.connect(self.select_key_file)
        key_buttons_layout.addWidget(self.key_button)
        self.clear_key_button = QPushButton("X")
        self.clear_key_button.setFixedWidth(30)
        self.clear_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
            }
            QPushButton:hover {
                background-color: #ff7777;
            }
        """)
        self.clear_key_button.clicked.connect(self.clear_key_path)
        self.clear_key_button.setVisible(False)
        key_buttons_layout.addWidget(self.clear_key_button)
        self.key_layout.addLayout(key_buttons_layout)
        self.key_group.setLayout(self.key_layout)
        self.generate_key_button = QPushButton("Generuj klucz")
        self.generate_key_button.clicked.connect(self.generate_key)
        self.key_layout.addWidget(self.generate_key_button)

        self.rsa_key_widget = QWidget()
        rsa_key_layout = QVBoxLayout()
        self.rsa_private_key_label = QLabel("Klucz prywatny: Nie wybrano")
        rsa_key_layout.addWidget(self.rsa_private_key_label)
        private_key_buttons_layout = QHBoxLayout()
        self.select_private_key_button = QPushButton("Wybierz klucz prywatny")
        self.select_private_key_button.clicked.connect(self.select_private_key_file)
        private_key_buttons_layout.addWidget(self.select_private_key_button)
        self.clear_private_key_button = QPushButton("X")
        self.clear_private_key_button.setFixedWidth(30)
        self.clear_private_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
            }
            QPushButton:hover {
                background-color: #ff7777;
            }
        """)
        self.clear_private_key_button.clicked.connect(self.clear_private_key_path)
        self.clear_private_key_button.setVisible(False)
        private_key_buttons_layout.addWidget(self.clear_private_key_button)
        rsa_key_layout.addLayout(private_key_buttons_layout)
        self.generate_private_key_button = QPushButton("Generuj klucz prywatny")
        self.generate_private_key_button.clicked.connect(self.generate_private_key)
        rsa_key_layout.addWidget(self.generate_private_key_button)
        self.rsa_public_key_label = QLabel("Klucz publiczny: Nie wybrano")
        rsa_key_layout.addWidget(self.rsa_public_key_label)
        public_key_buttons_layout = QHBoxLayout()
        self.select_public_key_button = QPushButton("Wybierz klucz publiczny")
        self.select_public_key_button.clicked.connect(self.select_public_key_file)
        public_key_buttons_layout.addWidget(self.select_public_key_button)
        self.clear_public_key_button = QPushButton("X")
        self.clear_public_key_button.setFixedWidth(30)
        self.clear_public_key_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
            }
            QPushButton:hover {
                background-color: #ff7777;
            }
        """)
        self.clear_public_key_button.clicked.connect(self.clear_public_key_path)
        self.clear_public_key_button.setVisible(False)
        public_key_buttons_layout.addWidget(self.clear_public_key_button)
        rsa_key_layout.addLayout(public_key_buttons_layout)
        self.generate_public_key_button = QPushButton("Generuj klucz publiczny")
        self.generate_public_key_button.clicked.connect(self.generate_public_key)
        rsa_key_layout.addWidget(self.generate_public_key_button)
        self.rsa_key_widget.setLayout(rsa_key_layout)
        self.rsa_key_widget.setVisible(False)
        self.key_layout.addWidget(self.rsa_key_widget)
        self.key_group.setLayout(self.key_layout)
        main_layout.addWidget(self.key_group)

        ops_group = QGroupBox("Operacje")
        ops_layout = QVBoxLayout()
        encrypt_decrypt_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Szyfruj")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        encrypt_decrypt_layout.addWidget(self.encrypt_button)
        self.decrypt_button = QPushButton("Deszyfruj")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        encrypt_decrypt_layout.addWidget(self.decrypt_button)
        ops_layout.addLayout(encrypt_decrypt_layout)
        self.cancel_button = QPushButton("Anuluj")
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setVisible(False)
        ops_layout.addWidget(self.cancel_button)
        ops_group.setLayout(ops_layout)
        main_layout.addWidget(ops_group)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.progress_bar)

        self.algorithm_widgets = {
            "AES": [self.aes_options_widget],
            "RSA-HMAC": [self.rsa_options_widget, self.rsa_key_widget],
            "3DES": [self.des_options_widget],
            "XChaCha20-Poly1305": [],
            "Threefish-Skein": [self.threefish_options_widget]
        }

        self.all_controls = [
            self.file_button,
            self.clear_file_button,
            self.key_button,
            self.clear_key_button,
            self.generate_key_button,
            self.select_private_key_button,
            self.clear_private_key_button,
            self.generate_private_key_button,
            self.select_public_key_button,
            self.clear_public_key_button,
            self.generate_public_key_button,
            self.encrypt_button,
            self.decrypt_button,
            self.algorithm_box,
            self.additional_options_button,
            self.aes_key_size_box,
            self.aes_mode_box,
            self.rsa_key_size_box,
            self.rsa_padding_box,
            self.des_mode_box,
            self.threefish_key_size_box
        ]

        self.setLayout(main_layout)
        self.setWindowTitle("Szyfrowanie i deszyfrowanie plików")
        self.setMinimumWidth(500)
        self.setMaximumSize(self.sizeHint().width(), self.sizeHint().height())
        self.file_path = ""
        self.key_path = ""
        self.private_key_path = ""
        self.public_key_path = ""
        self.save_path = ""

    def clear_file_path(self):
        self.file_path = "" 
        self.label.setText("Plik: nie wybrano")
        self.label.setToolTip("")
        self.clear_file_button.setVisible(False)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "All Files (*)", options=options)
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Plik: {self.file_path}")
            self.label.setToolTip(self.file_path)
            self.clear_file_button.setVisible(True)
        else:
            if self.file_path:
                self.label.setText(f"Plik: {self.file_path}")
                self.label.setToolTip(self.file_path)
            else:
                self.label.setText("Plik: nie wybrano")
                self.label.setToolTip("")
                self.clear_file_button.setVisible(False)

    def clear_key_path(self):
        self.key_path = ""
        self.key_label.setText("Klucz: nie wybrano")
        self.key_label.setToolTip("")
        self.clear_key_button.setVisible(False)

    def select_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.key_path = file_path
            self.key_label.setText(f"Klucz: {self.key_path}")
            self.key_label.setToolTip(self.key_path)
            self.clear_key_button.setVisible(True)
        else:
            if self.key_path:
                self.key_label.setText(f"Klucz: {self.key_path}")
                self.key_label.setToolTip(self.key_path)
            else:
                self.key_label.setText("Klucz: nie wybrano")
                self.key_label.setToolTip("")
                self.clear_key_button.setVisible(False)

    def clear_private_key_path(self):
        self.private_key_path = ""
        self.rsa_private_key_label.setText("Klucz prywatny: nie wybrano")
        self.rsa_private_key_label.setToolTip("")
        self.clear_private_key_button.setVisible(False)

    def select_private_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz prywatny", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.private_key_path = file_path
            self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
            self.rsa_private_key_label.setToolTip(self.private_key_path)
            self.clear_private_key_button.setVisible(True)
        else:
            if self.private_key_path:
                self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
                self.rsa_private_key_label.setToolTip(self.private_key_path)
            else:
                self.rsa_private_key_label.setText("Klucz prywatny: nie wybrano")
                self.rsa_private_key_label.setToolTip("")
                self.clear_private_key_button.setVisible(False)

    def clear_public_key_path(self):
        self.public_key_path = ""
        self.rsa_public_key_label.setText("Klucz publiczny: nie wybrano")
        self.rsa_public_key_label.setToolTip("")
        self.clear_public_key_button.setVisible(False)

    def select_public_key_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz publiczny", "", "Key Files (*.key);;All Files (*)", options=options)
        if file_path:
            self.public_key_path = file_path
            self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
            self.rsa_public_key_label.setToolTip(self.public_key_path)
            self.clear_public_key_button.setVisible(True)
        else:
            if self.public_key_path:
                self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
                self.rsa_public_key_label.setToolTip(self.public_key_path)
            else:
                self.rsa_public_key_label.setText("Klucz publiczny: nie wybrano")
                self.rsa_public_key_label.setToolTip("")
                self.clear_public_key_button.setVisible(False)

    def generate_key(self):
        algorithm = self.algorithm_box.currentText()
        options = QFileDialog.Options()
        default_save_name = "Klucz.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        if key_path:
            if algorithm == "AES":
                key_size = int(self.aes_key_size_box.currentText()) // 8
                key = get_random_bytes(key_size)
                with open(key_path, "wb") as key_file:
                    key_file.write(key)
                self.key_path = key_path
                self.key_label.setText(f"Wybrano klucz: {self.key_path}")
                QMessageBox.information(self, "Sukces", "Klucz AES został wygenerowany!")
            elif algorithm == "3DES":
                key = get_random_bytes(24)
                with open(key_path, "wb") as key_file:
                    key_file.write(key)
                self.key_path = key_path
                self.key_label.setText(f"Wybrano klucz: {self.key_path}")
                QMessageBox.information(self, "Sukces", "Klucz 3DES został wygenerowany!")
            elif algorithm == "XChaCha20-Poly1305":
                key = get_random_bytes(32)
                with open(key_path, "wb") as key_file:
                    key_file.write(key)
                self.key_path = key_path
                self.key_label.setText(f"Wybrano klucz: {self.key_path}")
                QMessageBox.information(self, "Sukces", "Klucz XChaCha20-Poly1305 został wygenerowany!")
            elif algorithm == "Threefish-Skein":
                key_size = int(self.threefish_key_size_box.currentText()) // 8
                key = get_random_bytes(key_size)
                with open(key_path, "wb") as key_file:
                    key_file.write(key)
                self.key_path = key_path
                self.key_label.setText(f"Wybrano klucz: {self.key_path}")
                QMessageBox.information(self, "Sukces", "Klucz Threefish-Skein został wygenerowany!")

    def generate_private_key(self):
        options = QFileDialog.Options()
        default_save_name = "Klucz prywatny.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz prywatny", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        if key_path:
            rsa_key_size = int(self.rsa_key_size_box.currentText())
            rsa_key = RSA.generate(rsa_key_size)
            private_key = rsa_key.export_key()
            with open(key_path, "wb") as key_file:
                key_file.write(private_key)
            self.private_key_path = key_path
            self.rsa_private_key_label.setText(f"Klucz prywatny: {self.private_key_path}")
            QMessageBox.information(self, "Sukces", "Klucz prywatny RSA-HMAC został wygenerowany!")

    def generate_public_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "Błąd", "Najpierw wygeneruj klucz prywatny!")
            return
        options = QFileDialog.Options()
        default_save_name = "Klucz publiczny.key"
        key_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz publiczny", default_save_name, "Key Files (*.key);;All Files (*)", options=options)
        if key_path:
            with open(self.private_key_path, "rb") as f:
                rsa_key = RSA.import_key(f.read())
            public_key = rsa_key.publickey().export_key()
            with open(key_path, "wb") as key_file:
                key_file.write(public_key)
            self.public_key_path = key_path
            self.rsa_public_key_label.setText(f"Klucz publiczny: {self.public_key_path}")
            QMessageBox.information(self, "Sukces", "Klucz publiczny RSA-HMAC został wygenerowany!")

    def encrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            return
        algorithm = self.algorithm_box.currentText()
        MAX_AES_FILE_SIZE = 1024 * 1024 * 1024 * 64 # 64GB
        MAX_RSA_FILE_SIZE = 1024 * 1024 # 1MB
        MAX_3DES_FILE_SIZE = 1024 * 1024 * 1024 * 32 # 32GB
        file_size = os.path.getsize(self.file_path)
        if algorithm == "RSA-HMAC":
            if not self.public_key_path:
                QMessageBox.warning(self, "Błąd", "Wybierz klucz publiczny!")
                return
            if file_size > MAX_RSA_FILE_SIZE:
                QMessageBox.warning(self, "Błąd", f"RSA-HMAC nie nadaje się do plików większych niż {MAX_RSA_FILE_SIZE // (1024*1024)} MB!")
                return
            key_path = self.public_key_path
            mode = None
            key_size = int(self.rsa_key_size_box.currentText())
            padding = self.rsa_padding_box.currentText()
        else:
            if not self.key_path:
                QMessageBox.warning(self, "Błąd", "Wybierz klucz!")
                return
            key_path = self.key_path
            if algorithm == "AES":
                if file_size > MAX_AES_FILE_SIZE:
                    QMessageBox.warning(self, "Błąd", f"AES nie nadaje się do plików większych niż {MAX_AES_FILE_SIZE // (1024*1024*1024)} GB!")
                    return
                mode = self.aes_mode_box.currentText()
                key_size = int(self.aes_key_size_box.currentText())
                padding = None
            elif algorithm == "3DES":
                if file_size > MAX_3DES_FILE_SIZE:
                    QMessageBox.warning(self, "Błąd", f"3DES nie nadaje się do plików większych niż {MAX_3DES_FILE_SIZE // (1024*1024*1024)} GB!")
                    return
                mode = self.des_mode_box.currentText()
                key_size = 0
                padding = None
            elif algorithm == "Threefish-Skein":
                mode = None
                key_size = int(self.threefish_key_size_box.currentText())
                padding = None
            else:
                mode = None
                key_size = 0
                padding = None

        if os.path.splitext(os.path.basename(self.file_path))[1] == '.enc':
            QMessageBox.warning(self, "Błąd", "Plik już jest zaszyfrowany!")
            return
        
        options = QFileDialog.Options()
        base = os.path.splitext(os.path.basename(self.file_path))
        default_save_name = base[0] + " - zaszyfrowany" + base[1] + ".enc"
        self.save_path, _ = QFileDialog.getSaveFileName(self, "Zapisz zaszyfrowany plik", default_save_name, "Encrypted Files (*.enc);;All Files (*)", options=options)
        if not self.save_path:
            return

        self.toggle_ui(False)
        self.cancel_button.setVisible(True)
        self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(0)
        self.thread = EncryptDecryptThread(self.file_path, key_path, algorithm, mode, padding, key_size, save_path=self.save_path)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.operation_finished)
        self.thread.start()

    def decrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            return
        algorithm = self.algorithm_box.currentText()
        if algorithm == "RSA-HMAC":
            if not self.private_key_path:
                QMessageBox.warning(self, "Błąd", "Wybierz klucz prywatny!")
                return
            key_path = self.private_key_path
            mode = None
            key_size = int(self.rsa_key_size_box.currentText())
            padding = self.rsa_padding_box.currentText()
        else:
            if not self.key_path:
                QMessageBox.warning(self, "Błąd", "Wybierz klucz!")
                return
            key_path = self.key_path
            if algorithm == "AES":
                mode = self.aes_mode_box.currentText()
                key_size = int(self.aes_key_size_box.currentText())
                padding = None
            elif algorithm == "3DES":
                mode = self.des_mode_box.currentText()
                key_size = 0
                padding = None
            elif algorithm == "Threefish-Skein":
                mode = None
                key_size = int(self.threefish_key_size_box.currentText())
                padding = None
            else:
                mode = None
                key_size = 0
                padding = None

        if os.path.splitext(os.path.basename(self.file_path))[1] != '.enc':
            QMessageBox.warning(self, "Błąd", "Plik nie jest zaszyfrowany!")
            return
        
        options = QFileDialog.Options()
        base = os.path.splitext(os.path.basename(self.file_path))[0]
        base2 = os.path.splitext(base)
        if "- zaszyfrowany" in base:
            default_save_name = base.replace("- zaszyfrowany", "- deszyfrowany")
        else:
            default_save_name = base2[0] + ' - deszyfrowany' + base2[1]
        self.save_path, _ = QFileDialog.getSaveFileName(self, "Zapisz deszyfrowany plik", default_save_name, "All Files (*)", options=options)
        if not self.save_path:
            return
        
        self.toggle_ui(False)
        self.cancel_button.setVisible(True)
        QTimer.singleShot(0, self.adjustSize)
        self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(0)
        self.thread = EncryptDecryptThread(self.file_path, key_path, algorithm, mode, padding, key_size, decrypt=True, save_path=self.save_path)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.operation_finished)
        self.thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        if value > 0:
            self.taskbar_progress.setVisible(True)
        self.taskbar_progress.setValue(value)

    def cancel_operation(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            self.thread.terminate()
            self.thread.wait()
            self.cancel_button.setVisible(False)
            self.taskbar_progress.setVisible(False)
            self.toggle_ui(True)
            QMessageBox.information(self, "Informacja", "Operacja została anulowana.")
            if self.progress_bar.value != 0:
                self.progress_bar.setValue(0)
            QTimer.singleShot(0, self.adjustSize)

    def operation_finished(self, message):
        if self.progress_bar.value != 0:
            self.progress_bar.setValue(0)
        self.cancel_button.setVisible(False)
        self.taskbar_progress.setVisible(False)
        self.toggle_ui(True)
        QTimer.singleShot(0, self.adjustSize)
        if "Błąd" in message:
            QMessageBox.critical(self, "Błąd", message.replace("Błąd: ", ""))
        elif "Info" in message:
            QMessageBox.information(self, "Informacja", message.replace("Info: ", ""))
        else:
            QMessageBox.information(self, "Sukces", message)

        if "zaszyfrowany" in message:
            dialog = QMessageBox(self)
            dialog.setWindowTitle("Usuwanie pliku")
            dialog.setText("Czy chcesz usunąć oryginalny plik?")
            dialog.setIcon(QMessageBox.Question)
            tak_button = dialog.addButton("Tak", QMessageBox.YesRole)
            nie_button = dialog.addButton("Nie", QMessageBox.NoRole)
            dialog.exec_()

            if dialog.clickedButton() == tak_button:
                try:
                    os.remove(self.file_path)
                    QMessageBox.information(self, "Sukces", "Oryginalny plik został usunięty.")
                    self.file_path = ""
                    self.label.setText("Wybierz plik")
                    self.label.setToolTip("")
                except Exception as e:
                    QMessageBox.warning(self, "Błąd", f"Nie udało się usunąć pliku: {str(e)}")

        elif "deszyfrowany" in message:
            dialog = QMessageBox(self)
            dialog.setWindowTitle("Usuwanie pliku")
            dialog.setText("Czy chcesz usunąć zaszyfrowany plik?")
            dialog.setIcon(QMessageBox.Question)
            tak_button = dialog.addButton("Tak", QMessageBox.YesRole)
            nie_button = dialog.addButton("Nie", QMessageBox.NoRole)
            dialog.exec_()

            if dialog.clickedButton() == tak_button:
                try:
                    os.remove(self.file_path)
                    QMessageBox.information(self, "Sukces", "Zaszyfrowany plik został usunięty.")
                    self.file_path = ""
                    self.label.setText("Wybierz plik")
                    self.label.setToolTip("")
                except Exception as e:
                    QMessageBox.warning(self, "Błąd", f"Nie udało się usunąć pliku: {str(e)}")

    def init_taskbar_progress(self):
        self.taskbar_button = QWinTaskbarButton(self)
        self.taskbar_button.setWindow(self.windowHandle())
        self.taskbar_progress = self.taskbar_button.progress()
        self.taskbar_progress.setVisible(False)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self.init_taskbar_progress)

    def toggle_ui(self, enabled):
        for ctrl in self.all_controls:
            ctrl.setEnabled(enabled)

    def toggle_additional_options(self):
        if self.additional_options_widget.isVisible():
            self.additional_options_widget.setVisible(False)
            self.additional_options_button.setText("Ustawienia algorytmu ▼")
        else:
            self.additional_options_widget.setVisible(True)
            self.additional_options_button.setText("Ustawienia algorytmu ▲")

        QTimer.singleShot(0, self.adjustSize)

    def update_algorithm_settings(self):
        algorithm = self.algorithm_box.currentText()

        for widgets_list in self.algorithm_widgets.values():
            for widget in widgets_list:
                widget.setVisible(False)

        for widget in self.algorithm_widgets.get(algorithm, []):
            widget.setVisible(True)

        if algorithm == "RSA-HMAC":
            self.key_button.setVisible(False)
            self.generate_key_button.setVisible(False)
            self.key_label.setText("Wybierz lub wygeneruj klucze:")
            self.key_group.setTitle("Klucze")
        else:
            self.key_button.setVisible(True)
            self.generate_key_button.setVisible(True)
            self.key_label.setText("Wybierz lub wygeneruj klucz:")
            self.key_group.setTitle("Klucz")
            self.clear_private_key_path()
            self.clear_public_key_path()
            self.clear_key_path()

        self.additional_options_button.setVisible(bool(self.algorithm_widgets.get(algorithm)))

        QTimer.singleShot(0, self.adjustSize)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if getattr(sys, 'frozen', False):
        applicationPath = sys._MEIPASS
    elif __file__:
        applicationPath = os.path.dirname(__file__)
    icon_path = os.path.join(applicationPath, "icon.ico")
    app.setWindowIcon(QIcon(icon_path))
    window = FileEncryptor()
    window.setWindowIcon(QIcon(icon_path))
    window.show()
    app.exec_()