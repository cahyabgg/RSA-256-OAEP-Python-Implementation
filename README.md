# Pembuka

Selamat datang di proyek implementasi RSA! Proyek ini mencakup beberapa variasi RSA dan skema padding OAEP.

## Struktur RSA

Ada tiga versi RSA yang diimplementasikan dalam proyek ini:

1.  **RSA Textbook (`rsa_textbook.py`)**: Implementasi standar RSA dasar. Cocok untuk pembelajaran dasar cara kerja algoritma RSA.
2.  **RSA CRT (`rsa_crt.py`)**: Implementasi RSA yang menggunakan *Chinese Remainder Theorem* (CRT) untuk mempercepat proses dekripsi.
3.  **RSA Precalculated (`rsa_precalc.py`)**: Implementasi RSA yang menggunakan precalculated values di cipher text agar mempercepat proses dekripsi, dengan kekurangan memperbesar ukuran ct dan mengharuskan mengubah stream dekrip menjadi 512

## Entry Point Utama

Titik masuk utama (*main entry point*) untuk menjalankan program adalah:
**`rsa_oaep.py`**

File ini menggabungkan RSA (saat ini menggunakan versi CRT) dengan padding **OAEP (Optimal Asymmetric Encryption Padding)** untuk enkripsi dan dekripsi file yang lebih aman.

## Cara Menggunakan

Untuk menggunakan program ini, Anda dapat menjalankan file `gui.py`

##### **Direkomendasikan anda mengenerate key di tab generate key diatas, lalu pilih tempat anda ingin menempatkan public dan private key**

### Untuk enkripsi 
- Klik tab encrypt
- Pilih file encrypt (kami rekomendasikan menggunakan tombol upload file)
- Pilih file public key (kami merekomendasikan dengan tombol upload key)
- Terakhir klik encrypt file di bawah kanan

### Untuk dekripsi
- Klik tab decrypt
- Pilih file ciphertext (kami rekomendasikan menggunakan tombol upload file)
- Pilih file private key (kami merekomendasikan dengan tombol upload key)
- Terakhir klik decrypt file di bawah kanan
