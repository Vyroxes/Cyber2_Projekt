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

![Algorytmy](https://github.com/user-attachments/assets/051ef0d3-b792-4796-a95b-a96ac052528d)

### 🔹 **AES (Advanced Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Sieć Feistela z operacjami w polu GF(2⁸).
- **Długość klucza w bitach:** 128, 192, 256.
- **Tryby:** GCM (Galois/Counter Mode), EAX, CBC (Cipher Block Chaining), ECB (Electronic Codebook).
- **Padding:** tryby CBC i ECB - PKCS7.
- **Sprawdzanie integralności plików**: tryby  AEAD (GCM, EAX) - tag MAC (Message Authentication Code).
- **Maksymalny rozmiar pliku**: 64 GB.

![AES](https://github.com/user-attachments/assets/b8fd7516-7a75-4717-b524-266819cd0663)

![AES 2](https://github.com/user-attachments/assets/423ba5e0-4a6b-47a5-8b63-ab8d7e97babc)

![AES 3](https://github.com/user-attachments/assets/72c7b224-8bcf-43dd-9f26-ad79065ae6ba)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Rodzaj:** Asymetryczny.
- **Struktura:** Oparty na trudności faktoryzacji dużych liczb pierwszych.
- **Długość klucza w bitach:** 1024, 2048, 3072, 4096.
- **Padding:** PKCS#1 v1.5 (Public-Key Cryptography Standards), OAEP (Optimal Asymmetric Encryption Padding).
- **Sprawdzanie integralności plików**: podpis PSS (Probabilistic Signature Scheme) z hashem SHA-256 (Secure Hash Alhorithm 256-bit).
- **Maksymalny rozmiar pliku**: 1 MB.

![RSA](https://github.com/user-attachments/assets/9d49e960-9b0b-4cf5-b15c-06146506566f)

![RSA 2](https://github.com/user-attachments/assets/c9647f63-e38d-4ff6-8a1c-908d9e913f9e)

![RSA 3](https://github.com/user-attachments/assets/a0b5d13f-d677-4a71-937f-cfed82b59ace)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Sieć Feistela (DES zastosowany 3x w schemacie EDE - encrypt-decrypt-encrypt).
- **Długość klucza w bitach:** 192.
- **Tryby:** EAX - AEAD, CFB (Cipher Feedback), OFB (Output Feedback).
- **Sprawdzanie integralności plików**: tryb AEAD (EAX) - tag MAC (Message Authentication Code).
- **Maksymalny rozmiar pliku**: tryb EAX - 10 MB, tryby CFB oraz OFB - 32 GB.

![3DES](https://github.com/user-attachments/assets/31533d27-ea4c-44fb-9318-d4a8f61081a0)

![3DES 2](https://github.com/user-attachments/assets/c12f4715-42ce-4d88-997d-63e62cc89393)

### 🔹 **XChaCha20**
- **Rodzaj:** Symetryczny, strumieniowy.
- **Struktura:** Operacje XOR na macierzach i wektorach.
- **Długość klucza w bitach:** 256.
- **Sprawdzanie integralności plików**: tag Poly1305.
- **Maksymalny rozmiar pliku**: praktycznie nieograniczony (setki TB do PB).

![XChaCha20](https://github.com/user-attachments/assets/cef22c90-5fcb-47ba-9531-128a6cd08bf8)


### 🔹 **Threefish**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Transformacje modularne i bitowe.
- **Długość klucza w bitach:** 256, 512, 1024.
- **Tryby:** strumieniowy - XOR z keystream, podobny do CTR (Counter).
- **Sprawdzanie integralności plików**: tag Skein-MAC, klucze wyprowadzane przez HKDF (HMAC-based Key Derivation Function) z hashem SHA-256 (Secure Hash Alhorithm 256-bit), schemat EtM (Encrypt-then-MAC).
- **Maksymalny rozmiar pliku**: praktycznie nieograniczony (setki TB do PB).

![Threefish](https://github.com/user-attachments/assets/c0200b10-3d68-4ebd-b35d-df98438eb8f6)

![Threefish 2](https://github.com/user-attachments/assets/398243d7-0291-4954-a625-6653621e7b2c)

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
- `psutil` - zarządzanie zasobami systemu.


### 🔹 **Instalacja zależności**
  ```bash
  pip install PyQt5 pycryptodome skein psutil
  ```

  ```bash
  pip install -r requirements.txt
  ```

---

📌 **Autor:** *Michał Rusek / Vyroxes*
