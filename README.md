# 📋 Praca inżynierska

## 🔐 System informatyczny do szyfrowania i deszyfrowania plików z weryfikacją integralności danych

System umożliwia szyfrowanie i deszyfrowanie plików różnego typu (tekstowych, graficznych, audio, wideo itd.) z wykorzystaniem wybranych algorytmów symetrycznych i asymetrycznych. Dodatkowo implementuje mechanizm weryfikacji integralności danych.

---

## 🎨 GUI aplikacji

System pozwala na ręczną zmianę motywu (jasny/ciemny). Dostępna jest też opcja "Automatyczny motyw" — po włączeniu aplikacja będzie automatycznie dopasowywać motyw do ustawień systemowych (Windows). Wybrany tryb jest zapisywany i zachowywany między uruchomieniami.  

### 🔹 **Motyw jasny**

![GUI](https://github.com/user-attachments/assets/46a52655-3a0b-4e35-b979-f0874f4898bf)

### 🔹 **Motyw ciemny**

![GUI 2](https://github.com/user-attachments/assets/5ba3e581-c9e4-4e07-8920-0f12a9d5a41d)

---

## 🔑 Klucze

### 🔹 **Symetryczne**
- Klucz generowany i zapisywany w pliku `.key`.
- Przykładowy plik z kluczem symetrycznym:

![Klucz](https://github.com/user-attachments/assets/03c99485-6229-4b68-b61a-a9663e879722)


### 🔹 **Asymetryczne (RSA)**
- Klucze generowane i zapisywane w osobnych plikach `.key`.
- Klucz publiczny generowany na podstawie klucza prywatnego.
- Przykładowe pliki z kluczami prywatnym i publicznym:

![Klucze](https://github.com/user-attachments/assets/709d0929-bada-4982-961f-aec14899e5a8)

---

## 🔢 Zaimplementowane algorytmy

![Algorytmy](https://github.com/user-attachments/assets/01467c60-b404-4d2e-98ed-3cfcc89bfb6f)

### 🔹 **AES (Advanced Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Sieć Feistela z operacjami w polu GF(2⁸).
- **Długość klucza w bitach:** 128, 192, 256.
- **Tryby:** GCM (Galois/Counter Mode), EAX (Encrypt-then-Authenticate-then-Translate), CBC (Cipher Block Chaining), ECB (Electronic Codebook).
- **Sprawdzanie integralności plików**: tryby  GCM oraz EAS - tag MAC (Message Authentication Code), tryby CBC oraz ECB - padding PKCS7.
- **Maksymalny rozmiar pliku**: 64 GB.

![AES](https://github.com/user-attachments/assets/e29ded45-be4d-4019-8139-d7976b2b1c31)

![AES 2](https://github.com/user-attachments/assets/423ba5e0-4a6b-47a5-8b63-ab8d7e97babc)

![AES 3](https://github.com/user-attachments/assets/72c7b224-8bcf-43dd-9f26-ad79065ae6ba)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Rodzaj:** Asymetryczny.
- **Struktura:** Oparty na trudności faktoryzacji dużych liczb pierwszych.
- **Długość klucza w bitach:** 1024, 2048, 3072, 4096.
- **Padding:** PKCS1 v1.5 (Public-Key Cryptography Standards), OAEP (Optimal Asymmetric Encryption Padding).
- **Sprawdzanie integralności plików**: tag HMAC (Hash-based Message Authentication Code).
- **Maksymalny rozmiar pliku**: 1 MB.

![RSA](https://github.com/user-attachments/assets/c325fa2c-37d9-45f7-91a4-b41c30c13a28)

![RSA 2](https://github.com/user-attachments/assets/b206d97e-384d-4a46-acb8-515e39b01c3f)

![RSA 3](https://github.com/user-attachments/assets/5aa8efe8-f5fb-4827-8112-101f36380190)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Sieć Feistela.
- **Długość klucza w bitach:** 192.
- **Tryby:** EAX (Encrypt-then-Authenticate-then-Translate), CFB (Cipher Feedback), OFB (Output Feedback).
- **Sprawdzanie integralności plików**: tryb EAX - tag MAC (Message Authentication Code).
- **Maksymalny rozmiar pliku**: 32 GB.

![3DES](https://github.com/user-attachments/assets/af48a252-52f1-4f31-8e93-870b5ebc7d9d)

![3DES 2](https://github.com/user-attachments/assets/c12f4715-42ce-4d88-997d-63e62cc89393)

### 🔹 **XChaCha20-Poly1305**
- **Rodzaj:** Symetryczny, strumieniowy.
- **Struktura:** Macierze i operacje XOR.
- **Długość klucza w bitach:** 256.
- **Sprawdzanie integralności plików**: tag Poly1305.
- **Maksymalny rozmiar pliku**: praktycznie nieograniczony (setki TB do PB).

![XChaCha20](https://github.com/user-attachments/assets/506f0114-eda8-4273-8c11-c8408a6771ac)


### 🔹 **Threefish**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Transformacje modularne i bitowe.
- **Długość klucza w bitach:** 256, 512, 1024.
- **Sprawdzanie integralności plików**: funkcja skrótu Skein.
- **Maksymalny rozmiar pliku**: praktycznie nieograniczony (setki TB do PB).

![Threefish](https://github.com/user-attachments/assets/3e42f900-9449-45fa-89d4-31f072dbaef5)

![Threefish 2](https://github.com/user-attachments/assets/95ab525a-91a2-4b25-99df-c0881e2089e1)

---

## 🗑️ Bezpiecznie usuwanie pliku

System zawiera zaimplementowany mechanizm bezpiecznego usuwania pliku niezaszyfrowanego po jego zaszyfrowaniu, dostosowany do rodzaju dysku - automatyczne wykrywanie nośnika (Windows). Bezpieczne usuwanie jest opcjonalne i kontrolowane z poziomu GUI.

![Usuwanie](https://github.com/user-attachments/assets/a5e11866-935d-4423-b323-399a1ce23d8b)

### 🔹 **HDD (dyski talerzowe)**
- Dwukrotne nadpisywanie pliku losowymi danymi, wykonywane blokami ~4 MiB. Po każdym zapisie wykonywane są flush() oraz os.fsync() w celu wymuszenia zapisu na nośniku.
- Stosowany jest mechanizm "crypto‑erase": tworzony jest tymczasowy plik w tym samym katalogu, do którego oryginał jest strumieniowo szyfrowany losowym kluczem (AES‑GCM, klucz 256-bitowy, nonce 96-bitowy) w blokach ~1 MiB. Dla każdego bloku wykonywane są flush() oraz os.fsync(). Po zakończeniu szyfrowania klucz jest bezpiecznie wyzerowany z pamięci. Tymczasowy plik zastępuje oryginał (os.replace), a następnie zaszyfrowany plik zostaje usunięty.

### 🔹 **SSD (dyski półprzewodnikowe)**
- Ze względu na wear‑leveling nadpisywanie nie gwarantuje fizycznego usunięcia. Stosowany jest głównie tryb "crypto‑erase" (opisany wyżej).
- Jeśli dostępne i włączone, aplikacja próbuje wywołać TRIM / Optimize‑Volume (PowerShell), aby zwolnić bloki (Windows).

---

## 📂 Dodatkowe funkcje

Podgląd ścieżki pliku oraz klucza/kluczy.

![Podgląd](https://github.com/user-attachments/assets/8ee59dd5-c9a7-47fa-9e55-cdf4e2dcd86b)

Możliwość usunięcia wybranego pliku oraz klucza/kluczy.

![Podgląd 2](https://github.com/user-attachments/assets/ac8f28d3-3769-4f0c-9330-d4e70405677d)

![Podgląd 3](https://github.com/user-attachments/assets/da0897e8-b38b-4ff8-ad85-717fad505e2e)

Historia ostatnich plików oraz klucza/kluczy.

![Podgląd 4](https://github.com/user-attachments/assets/ed4cba93-654f-4060-8520-b928dbab65d7)

Możliwość przeciągania i upuszczania pliku oraz klucza/kluczy bezpośrednio na odpowiednie pola w GUI.

![Podgląd 5](https://github.com/user-attachments/assets/c1028026-34cd-4589-b1fe-27d0b1bb4a30)

---

## ⚙️ Szyfrowanie/deszyfrowanie

Zaszyfrowany plik w rozszerzeniu `.enc`.

![Szyfrowanie](https://github.com/user-attachments/assets/016528f5-c610-40fa-bb58-e320fa2cbead)

Błąd weryfikacji integralności danych podczas operacji deszyfrowania spowodowany modyfikacją pliku zaszyfrowanego.

![Szyfrowanie 2](https://github.com/user-attachments/assets/15a0d35f-1e28-437e-b2e4-24b5d2ebd013)

---

## ⏳ Funkcjonalny pasek postępu

Możliwość anulowania operacji szyfrowania/deszyfrowania w dowolnym momencie.

![Pasek](https://github.com/user-attachments/assets/b844c800-656c-471c-86d6-a294c0ff86f5)

Funkcjonalny pasek postępu wyświetla graficzny i procentowy postęp operacji oraz ETA (Estimated Time of Arrival) - szacowany czas do zakończenia operacji szyfrowania/deszyfrowania.

![Pasek 2](https://github.com/user-attachments/assets/042cd932-cafa-445a-935b-58d618f007c1)

Integracja paska postępu z paskiem zadań (Windows).

![Pasek 3](https://github.com/user-attachments/assets/4cfb24a2-45d5-4de5-9933-58d4be05b996)

---

## 🧰 Wymagania i instalacja zależności

### 🔹 **Aplikacja wymaga następujących bibliotek**

- `PyQt5` - biblioteka GUI.
- `pycryptodome` - zestaw narzędzi kryptograficznych.
- `skein` - implementacja algorytmów Skein.


### 🔹 **Instalacja zależności**
  ```bash
  pip install PyQt5 pycryptodome skein
  ```

  ```bash
  pip install -r requirements.txt
  ```

---

📌 **Autor:** *Michał Rusek / Vyroxes*
