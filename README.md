# Pembuka

Selamat datang di proyek implementasi RSA! Proyek ini mencakup beberapa variasi RSA dan skema padding OAEP.

## Struktur RSA

Ada dua versi RSA yang diimplementasikan dalam proyek ini:

1.  **RSA Textbook (`rsa_textbook.py`)**: Implementasi standar RSA dasar. Cocok untuk pembelajaran dasar cara kerja algoritma RSA.
2.  **RSA CRT (`rsa_crt.py`)**: Implementasi RSA yang menggunakan *Chinese Remainder Theorem* (CRT) untuk mempercepat proses dekripsi.

## Entry Point Utama

Titik masuk utama (*main entry point*) untuk menjalankan program adalah:
**`rsa_oaep.py`**

File ini menggabungkan RSA (saat ini menggunakan versi CRT) dengan padding **OAEP (Optimal Asymmetric Encryption Padding)** untuk enkripsi dan dekripsi file yang lebih aman.

## Cara Menggunakan

Untuk menggunakan program ini, Anda dapat menjalankan file `rsa_oaep.py`. Sayangnya untuk saat ini masih hardcode untuk file apa yang akan di enkripsi, jadi masih butuh GUI nya

Selain itu versi RSA yang digunakan diatur di file ini, tanpa mengubah banyak tinggal mengganti from import rsanya saja

