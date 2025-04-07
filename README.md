# Projekt z przedmiotu cyberbezpieczeństwo 2 - aplikacja do szyfrowania i deszyfrowania plików tekstowych, graficznych, dźwiękowych, wideo, itd. za pomocą różnych algorytmów symetrycznych i asymetrycznych ze sprawdzaniem integralności danych

GUI aplikacji:

![image](https://github.com/user-attachments/assets/a0e696d4-9646-447c-8c6c-06f4e906de3b)

Klucz
Dla algorytmów symetrycznych pojedynczy klucz z rozszerzeniem .key.
![image](https://github.com/user-attachments/assets/19bb7fa7-9a64-4313-a5de-3aac51feb9a2)

Klucze pryawtny i publiczny dla algorytmu asymetrycznego - RSA.
![image](https://github.com/user-attachments/assets/2878717b-fce9-4e8a-b876-1a8c93462dd7)
![image](https://github.com/user-attachments/assets/63195745-329a-424c-8157-f2039de5b813)

Zaimplementowane algorytmy:
![image](https://github.com/user-attachments/assets/5b04e1a5-d0ae-4c62-89e0-d8f56da48dd3)

AES (Advanced Encryption Standard):
symetryczny,
blokowy,
struktura: sieć Feistela z operacjami w polu GF(2⁸),
długość klucza: 128, 192, 256-bit,
tryby: EAX, CBC, ECB,
sprawdzanie integralności plików:


![image](https://github.com/user-attachments/assets/e886e708-3506-4e16-b7c6-256dd724c763)
![image](https://github.com/user-attachments/assets/423ba5e0-4a6b-47a5-8b63-ab8d7e97babc)
![image](https://github.com/user-attachments/assets/4885a943-6e9c-4c38-ae9b-03635532fa0d)

RSA (Rivest–Shamir–Adleman):
asymetryczny,
kryptografia klucza publicznego
struktura: trudność faktoryzacji dużych liczb pierwszych,
długość klucza: 1024, 2048, 3072, 4096-bit,
padding: PKCS1 v1.5, OAEP
sprawdzanie integralności plików:

![image](https://github.com/user-attachments/assets/c325fa2c-37d9-45f7-91a4-b41c30c13a28)
![image](https://github.com/user-attachments/assets/b206d97e-384d-4a46-acb8-515e39b01c3f)
![image](https://github.com/user-attachments/assets/5aa8efe8-f5fb-4827-8112-101f36380190)

3DES (Triple Data Encryption Standard):
symetryczny,
szyfr blokowy,
struktura: sieć Feistela,
długość klucza: 192-bit,
tryby: EAX, CFB, OFB
sprawdzanie integralności plików:

![image](https://github.com/user-attachments/assets/af48a252-52f1-4f31-8e93-870b5ebc7d9d)
![image](https://github.com/user-attachments/assets/c12f4715-42ce-4d88-997d-63e62cc89393)

XChaCha20-Poly1305
symetryczny,
szyfr strumieniowy,
struktura: macierze i operacje XOR,
długość klucza: 256-bit,
sprawdzanie integralności plików: 

Threefish
symetryczny,
szyfr blokowy,
struktura: transformacje modularne i bitowe,
długość klucza: 256, 512, 1024-bit,
sprawdzanie integralności plików: 

![image](https://github.com/user-attachments/assets/3e42f900-9449-45fa-89d4-31f072dbaef5)
![image](https://github.com/user-attachments/assets/95ab525a-91a2-4b25-99df-c0881e2089e1)

Podgląd ścieżki pliku
![image](https://github.com/user-attachments/assets/2d44b4db-6f1f-409f-b72d-72eb4d6e5d41)

Zaszyfrowany plik w rozszerzeniu .enc
![image](https://github.com/user-attachments/assets/016528f5-c610-40fa-bb58-e320fa2cbead)


Funkcjonalny progress bar oraz anulowanie operacji szyfrowania/deszyfrowania
![Uploading image.png…]()


