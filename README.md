# 🔐 Projekt z przedmiotu Cyberbezpieczeństwo 2

## 🛠 Aplikacja do szyfrowania i deszyfrowania plików

Aplikacja umożliwia szyfrowanie i deszyfrowanie plików tekstowych, graficznych, dźwiękowych, wideo itp. za pomocą różnych algorytmów symetrycznych i asymetrycznych. Dodatkowo implementuje mechanizm sprawdzania integralności danych.

---

## 🎨 GUI aplikacji

![GUI](https://github.com/user-attachments/assets/a0e696d4-9646-447c-8c6c-06f4e906de3b)

---

## 🔑 Klucze

### Symetryczne
- Klucz generowany i zapisywany w pliku `.key`
- Przykładowy plik z kluczem symetrycznym:

![klucz](https://github.com/user-attachments/assets/03c99485-6229-4b68-b61a-a9663e879722)


### Asymetryczne (RSA)
- Klucze generowane i zapisywane w osobnych plikach `.key`
- Klucz publiczny generowany na podstawie klucza prywatnego
- Przykładowe pliki z kluczami prywatnym i publicznym:

![klucze](https://github.com/user-attachments/assets/709d0929-bada-4982-961f-aec14899e5a8)

---

## 🔢 Zaimplementowane algorytmy

![Algorytmy](https://github.com/user-attachments/assets/5b04e1a5-d0ae-4c62-89e0-d8f56da48dd3)

### 🔹 **AES (Advanced Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Sieć Feistela z operacjami w polu GF(2⁸)
- **Długość klucza w bitach:** 128, 192, 256
- **Tryby:** EAX (Encrypt-then-Authenticate-then-Translate), CBC Cipher Block Chaining), ECB (Electronic Codebook)
- **Sprawdzanie integralności plików**: tryb EAS - tag MAC (Message Authentication Code), tryby CBC oraz ECB - padding PKCS7

![AES 1](https://github.com/user-attachments/assets/e886e708-3506-4e16-b7c6-256dd724c763)

![AES 2](https://github.com/user-attachments/assets/423ba5e0-4a6b-47a5-8b63-ab8d7e97babc)

![AES 3](https://github.com/user-attachments/assets/4885a943-6e9c-4c38-ae9b-03635532fa0d)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Rodzaj:** Asymetryczny
- **Struktura:** Oparty na trudności faktoryzacji dużych liczb pierwszych
- **Długość klucza w bitach:** 1024, 2048, 3072, 4096
- **Padding:** PKCS1 v1.5 (Public-Key Cryptography Standards), OAEP (Optimal Asymmetric Encryption Padding)
- **Sprawdzanie integralności plików**: tag HMAC (Hash-based Message Authentication Code)

![RSA 1](https://github.com/user-attachments/assets/c325fa2c-37d9-45f7-91a4-b41c30c13a28)

![RSA 2](https://github.com/user-attachments/assets/b206d97e-384d-4a46-acb8-515e39b01c3f)

![RSA 3](https://github.com/user-attachments/assets/5aa8efe8-f5fb-4827-8112-101f36380190)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Sieć Feistela
- **Długość klucza w bitach:** 192
- **Tryby:** EAX (Encrypt-then-Authenticate-then-Translate), CFB (Cipher Feedback), OFB (Output Feedback)
- **Sprawdzanie integralności plików**: tryb EAX - tag MAC (Message Authentication Code)

![3DES 1](https://github.com/user-attachments/assets/af48a252-52f1-4f31-8e93-870b5ebc7d9d)

![3DES 2](https://github.com/user-attachments/assets/c12f4715-42ce-4d88-997d-63e62cc89393)

### 🔹 **XChaCha20-Poly1305**
- **Rodzaj:** Symetryczny, strumieniowy
- **Struktura:** Macierze i operacje XOR
- **Długość klucza w bitach:** 256
- **Sprawdzanie integralności plików**: tag Poly1305

![XChaCha20 1](https://github.com/user-attachments/assets/506f0114-eda8-4273-8c11-c8408a6771ac)


### 🔹 **Threefish**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Transformacje modularne i bitowe
- **Długość klucza w bitach:** 256, 512, 1024
- **Sprawdzanie integralności plików**: funkcja skrótu Skein

![Threefish 1](https://github.com/user-attachments/assets/3e42f900-9449-45fa-89d4-31f072dbaef5)

![Threefish 2](https://github.com/user-attachments/assets/95ab525a-91a2-4b25-99df-c0881e2089e1)

---

## 📂 Podgląd ścieżki pliku oraz możliwość usunięcia pliku oraz klucza/kluczy

![Podgląd](https://github.com/user-attachments/assets/2d44b4db-6f1f-409f-b72d-72eb4d6e5d41)

![image](https://github.com/user-attachments/assets/89bd5752-d40e-4750-81e9-0e579e5ae402)

![image](https://github.com/user-attachments/assets/8643733a-6ad4-48b9-acb9-ac0f86dfd980)

## 🔏 Zaszyfrowany plik w rozszerzeniu `.enc`

![Zaszyfrowany plik](https://github.com/user-attachments/assets/016528f5-c610-40fa-bb58-e320fa2cbead)

---

## ⏳ Funkcjonalny **progress bar** oraz możliwość anulowania operacji szyfrowania/deszyfrowania

![Progress bar](https://github.com/user-attachments/assets/132bae2a-6cad-4667-ae75-bdb9a457ffdd)

---

## 🧰 Wymagania i instalacja zależności

### Aplikacja wymaga następujących bibliotek

- `PyQt5` - biblioteka GUI dla Pythona.
- `pycryptodome` - zestaw narzędzi kryptograficznych.
- `skein` - implementacja algorytmów Skein.


### Instalacja zależności
  ```bash
  pip install PyQt5 pycryptodome skein
  ```

---

📌 **Autor:** *Michał Rusek / Vyroxes*
