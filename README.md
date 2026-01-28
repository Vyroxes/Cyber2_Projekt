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

![AES](https://github.com/user-attachments/assets/d471c5da-253a-4017-aa52-801d49394546)

![AES 2](https://github.com/user-attachments/assets/4e2b6967-8f2d-4a4d-ac7a-c20eabd622ba)

![AES 3](https://github.com/user-attachments/assets/21f2882f-b421-4f76-a6df-4f9781620bab)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Rodzaj:** Asymetryczny.
- **Struktura:** Oparty na trudności faktoryzacji dużych liczb pierwszych.
- **Długość klucza w bitach:** 1024, 2048, 3072, 4096.
- **Padding:** PKCS#1 v1.5 (Public-Key Cryptography Standards), OAEP (Optimal Asymmetric Encryption Padding).
- **Sprawdzanie integralności plików**: podpis PSS (Probabilistic Signature Scheme) z hashem SHA-256 (Secure Hash Alhorithm 256-bit).
- **Maksymalny rozmiar pliku**: 1 MB.

![RSA](https://github.com/user-attachments/assets/873cd11a-37b3-4ba4-9af4-b867220ef0f5)

![RSA 2](https://github.com/user-attachments/assets/58e16bcc-928b-4c4f-a1c1-e38241a4f554)

![RSA 3](https://github.com/user-attachments/assets/b88c18db-b8bd-441f-b97b-0900ce8bca3f)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Rodzaj:** Symetryczny, blokowy.
- **Struktura:** Sieć Feistela (DES zastosowany 3x w schemacie EDE - encrypt-decrypt-encrypt).
- **Długość klucza w bitach:** 192.
- **Tryby:** EAX - AEAD, CFB (Cipher Feedback), OFB (Output Feedback).
- **Sprawdzanie integralności plików**: tryb AEAD (EAX) - tag MAC (Message Authentication Code).
- **Maksymalny rozmiar pliku**: tryb EAX - 10 MB, tryby CFB oraz OFB - 32 GB.

![3DES](https://github.com/user-attachments/assets/f27a811b-6881-4608-bbc4-6e7f2cd2407b)

![3DES 2](https://github.com/user-attachments/assets/e9f85a8a-e83a-4210-9f40-142394316903)

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

![Threefish](https://github.com/user-attachments/assets/8ebe010e-92e5-4e83-b48a-d8b4574447e3)

![Threefish 2](https://github.com/user-attachments/assets/c9634ca0-ce75-4e2e-810c-345443ad4bb5)

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

Podgląd ścieżki i rozmiaru pliku oraz klucza/kluczy, z możliwością otwarcia lokalizacji pliku oraz klucza/kluczy poprzez dwukrotne kliknięcie.

![Podgląd](https://github.com/user-attachments/assets/3498f8d0-9ea5-4b63-a977-5228fa6f7836)

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

- `PyQt5` - graficzny interfejs użytkownika.
- `PyCryptodome` - implementacja algorytmów kryptograficznych.
- `PySkein` - implementacja prymitywu kryptograficznego Skein.
- `psutil` - monitorowanie wykorzystania zasobów systemowych.

### 🔹 **Do zbudowania pliku wykonywalnego wymagane**

  - `PyInstaller` - narzędzie do tworzenia plików wykonywalnych `.exe`.

  Komenda do zbudowania aplikacji:
  ``` bash
  pyinstaller --onefile --windowed --icon=icon.ico --name="Szyfrowanie i deszyfrowanie plików" --add-data="icon.ico;." "main.py"
  ```
  
  Instalacja narzędzia PyInstaller:
  ```bash
  pip install PyInstaller==6.18.0
  ```

### 🔹 **Instalacja zależności**
  Można je zainstalować pojedynczo z określoną wersją:
  ```bash
  pip install PyQt5==5.15.11 PyCryptodome==3.23.0 PySkein==1.0 psutil==7.2.2
  ```

  Lub za pomocą pliku `requirements.txt`:
  ```bash
  pip install -r requirements.txt
  ```

---

📌 **Autor:** *Michał Rusek / Vyroxes*
