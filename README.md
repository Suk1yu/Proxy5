# SOCKS5 Proxy Advanced 
[![Awesome](/awesome.png)](https://github.com/sindresorhus/awesome) [![](https://img.shields.io/liberapay/goal/awesome-selfhosted?logo=liberapay)](https://liberapay.com/awesome-selfhosted/)

Proxy SOCKS5 ini adalah versi lanjutan dengan fitur enterprise-grade: autentikasi (RFC 1929), kontrol rate limit dua arah, control port untuk shutdown, UDP ASSOCIATE & BIND, logging yang dapat dikonfigurasi dan rotasi log, serta mode anonymous untuk privasi.

---

## Ringkasan Fitur
- Dukungan `CONNECT` untuk IPv4/IPv6 dan domain (RFC 1928)
- Autentikasi USERNAME/PASSWORD (RFC 1929) + ACL berbasis CIDR
- Rate limiting dua arah dengan `TokenBucket` dan limiter global/per-IP
- Control port HTTP (`127.0.0.1:1081`) untuk `shutdown` dan `status`
- UDP ASSOCIATE (relay UDP; berguna untuk DNS/QUIC) dan `BIND`
- Logging dengan `RotatingFileHandler`, level dapat diatur, dan mode anonymous
- Thread pool untuk concurrency; opsi `--async-mode` untuk profil async

---
---

## Cara Menjalankan

- Python 3.8+ (disarankan)
- Instal dependensi minimal: `colorama`

```powershell
pip install colorama
```
```powershell
# Bantuan
python pororo.py --help

# Menjalankan server default (listen di 0.0.0.0:1080)
python pororo.py start

# Menentukan port
python pororo.py start --port 8080

# Menonaktifkan autentikasi (open proxy; gunakan hati-hati)
python pororo.py start --no-auth

# Mode anonymous (alamat/host dimasking di log)
python pororo.py start --anonymous

# Mode async (eksperimental; siap untuk pengembangan lebih lanjut)
python pororo.py start --async-mode

# Menghentikan server
python pororo.py stop
```

Konfigurasi proxy di aplikasi/OS Anda sebagai SOCKS5:
- Host: `127.0.0.1` (atau IP mesin)
- Port: `1080` (atau yang Anda atur)

---

## Control Port
Control server berjalan di `127.0.0.1:1081`.

```powershell
# Shutdown server
curl -X POST http://127.0.0.1:1081/shutdown

# Status server
curl -X POST http://127.0.0.1:1081/status
```

---

## File & Konfigurasi
- `socks5_users.json` – database pengguna (username/password) dan allowlist IP per user
- `socks5_acl.json` – ACL global (CIDR) untuk memfilter IP klien
- `socks5_proxy.log` – log dengan rotasi otomatis
- `socks5_proxy.pid` – PID file untuk manajemen proses

Contoh isi `socks5_users.json`:
```json
[
  {"username": "user1", "password": "pass1", "allow": ["0.0.0.0/0"]},
  {"username": "user2", "password": "pass2", "allow": ["192.168.1.0/24"]}
]
```

Contoh isi `socks5_acl.json`:
```json
[
  "0.0.0.0/0",
  "::/0"
]
```

---

## Perbedaan dengan Versi Sebelumnya
- Handshake SOCKS5 lebih lengkap dan robust; dukungan IPv6 & domain lebih baik
- Autentikasi RFC 1929 + ACL (sebelumnya tidak ada autentikasi/ACL)
- Rate limiting dua arah (uplink & downlink), global dan per-IP (sebelumnya terbatas/sederhana)
- Control port untuk shutdown/status (sebelumnya hanya PID kill)
- Log rotation dan level logging yang tepat (sebelumnya log dasar tanpa rotasi)
- Koordinasi penutupan socket dan peningkatan stabilitas transfer
- `sendall()` dan helper `recv_exact()` untuk keandalan I/O
- Backlog dan thread pool yang disesuaikan untuk beban tinggi

---

## Kelebihan Versi Sebelumnya (Legacy)
- Sederhana dan mudah dipahami; cocok untuk belajar dasar SOCKS5
- Overhead lebih kecil untuk skenario ringan
- Dependensi minim
- Cepat diinisialisasi karena fitur lebih terbatas

---

## Kelebihan Proxy Ini dibanding Proxy Lain
- Dibanding HTTP proxy: SOCKS5 lebih generik (bukan hanya HTTP), mendukung berbagai protokol di layer transport
- Dibanding "proxy gratisan": keamanan lebih baik (opsi autentikasi), kontrol akses (ACL), dan privasi (anonymous mode)
- Dibanding implementasi SOCKS5 sederhana: fitur lengkap (UDP, BIND, rate limit, control port, rotasi log), stabil dan siap produksi kecil

Catatan: Proxy ini bukan alat anonimitas penuh (bukan Tor/mix-net). Untuk kebutuhan anonimitas kuat, gunakan chain proxy atau solusi khusus.

---

## Troubleshooting
- "Unexpected token" saat mengetik `--anonymous` di PowerShell: pastikan menjalankan `python pororo.py start --anonymous` (param harus mengikuti perintah `start`).
- Error modul `colorama`: jalankan `pip install colorama`.
- Port sudah digunakan: ganti dengan `--port <angka>` atau hentikan proses lain yang memakai port tersebut.

---

## Creator & Credits
- Creator: **Far&** / Suk1yu

<p>
  <img src="trae.jpg" alt="Trae AI Logo" width="24" />
  Terima kasih kepada TraeAI yang membantu proses pengembangan.
</p>

---

## Lisensi 

Proyek ini dilisensikan di bawah [GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.en.html).

```
Copyright (C) 2023 Far&

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
Selamat menggunakan SOCKS5 Proxy Advanced! Jika Anda memiliki masukan atau ingin menambah fitur, silakan ajukan issue atau diskusi.

**[ Alert ]** Script Ini masih di tahap pengembangan [developer](https://github.com/suk1yu/)
