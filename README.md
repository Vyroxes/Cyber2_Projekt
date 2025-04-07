# 🔐 Projekt z przedmiotu Cyberbezpieczeństwo 2

## 🛠 Aplikacja do szyfrowania i deszyfrowania plików

Aplikacja umożliwia szyfrowanie i deszyfrowanie plików tekstowych, graficznych, dźwiękowych, wideo itp. za pomocą różnych algorytmów symetrycznych i asymetrycznych. Dodatkowo implementuje mechanizm sprawdzania integralności danych.

---

## 🎨 GUI aplikacji

![GUI](https://github.com/user-attachments/assets/a0e696d4-9646-447c-8c6c-06f4e906de3b)

---

## 🔑 Klucze

### Symetryczne
- Klucz zapisywany w pliku `.key`
- Przykładowy klucz symetryczny:

![Klucz symetryczny](https://github.com/user-attachments/assets/19bb7fa7-9a64-4313-a5de-3aac51feb9a2)

### Asymetryczne (RSA)
- Klucz publiczny i prywatny

![Klucz prywatny](https://github.com/user-attachments/assets/2878717b-fce9-4e8a-b876-1a8c93462dd7)
![Klucz publiczny](https://github.com/user-attachments/assets/63195745-329a-424c-8157-f2039de5b813)

---

## 🔢 Zaimplementowane algorytmy

![Algorytmy](https://github.com/user-attachments/assets/5b04e1a5-d0ae-4c62-89e0-d8f56da48dd3)

### 🔹 **AES (Advanced Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Sieć Feistela z operacjami w polu GF(2⁸)
- **Długość klucza:** 128, 192, 256-bit
- **Tryby:** EAX, CBC, ECB
- **Sprawdzanie integralności plików**:

![AES 1](https://github.com/user-attachments/assets/e886e708-3506-4e16-b7c6-256dd724c763)
![AES 2](https://github.com/user-attachments/assets/423ba5e0-4a6b-47a5-8b63-ab8d7e97babc)
![AES 3](https://github.com/user-attachments/assets/4885a943-6e9c-4c38-ae9b-03635532fa0d)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Rodzaj:** Asymetryczny
- **Struktura:** Oparty na trudności faktoryzacji dużych liczb pierwszych
- **Długość klucza:** 1024, 2048, 3072, 4096-bit
- **Padding:** PKCS1 v1.5, OAEP
- **Sprawdzanie integralności plików**:

![RSA 1](https://github.com/user-attachments/assets/c325fa2c-37d9-45f7-91a4-b41c30c13a28)
![RSA 2](https://github.com/user-attachments/assets/b206d97e-384d-4a46-acb8-515e39b01c3f)
![RSA 3](https://github.com/user-attachments/assets/5aa8efe8-f5fb-4827-8112-101f36380190)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Sieć Feistela
- **Długość klucza:** 192-bit
- **Tryby:** EAX, CFB, OFB
- **Sprawdzanie integralności plików**:

![3DES 1](https://github.com/user-attachments/assets/af48a252-52f1-4f31-8e93-870b5ebc7d9d)
![3DES 2](https://github.com/user-attachments/assets/c12f4715-42ce-4d88-997d-63e62cc89393)

### 🔹 **XChaCha20-Poly1305**
- **Rodzaj:** Symetryczny, strumieniowy
- **Struktura:** Macierze i operacje XOR
- **Długość klucza:** 256-bit
- **Sprawdzanie integralności plików**:

### 🔹 **Threefish**
- **Rodzaj:** Symetryczny, blokowy
- **Struktura:** Transformacje modularne i bitowe
- **Długość klucza:** 256, 512, 1024-bit
- **Sprawdzanie integralności plików**:

![Threefish 1](https://github.com/user-attachments/assets/3e42f900-9449-45fa-89d4-31f072dbaef5)
![Threefish 2](https://github.com/user-attachments/assets/95ab525a-91a2-4b25-99df-c0881e2089e1)

---

## 📂 Podgląd ścieżki pliku

![Podgląd](https://github.com/user-attachments/assets/2d44b4db-6f1f-409f-b72d-72eb4d6e5d41)

## 🔏 Zaszyfrowany plik w rozszerzeniu `.enc`

![Zaszyfrowany plik](https://github.com/user-attachments/assets/016528f5-c610-40fa-bb58-e320fa2cbead)

---

## ⏳ Funkcjonalny **progress bar** oraz możliwość anulowania operacji szyfrowania/deszyfrowania

![Progress Bar](https://github.com/user-attachments/assets/Uploading image.png…)

---

📌 **Autor:** *Michał Rusek / Vyroxes*
