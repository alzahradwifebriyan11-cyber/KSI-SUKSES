# Portal Kampus FIKTI

Aplikasi latihan kampus fiksyen menggunakan Node.js, Express dan SQLite. Semua akaun dan data contoh adalah sintetik. Aplikasi ini sengaja mengajar **cara mencegah** SQL injection dan muat naik fail berbahaya; ia tidak memasukkan kelemahan yang boleh dieksploitasi.

## Keperluan

- Node.js 22.5 atau lebih baharu (untuk modul SQLite terbina dalam `node:sqlite`)
- npm

## Jalankan di localhost

```powershell
npm install
npm start
```

Buka http://localhost:3000. Pangkalan data SQLite dan fail tugasan dicipta secara automatik dalam folder `data/` dan `uploads/`. Untuk persekitaran selain localhost, tetapkan `SESSION_SECRET` yang rawak dan panjang serta `NODE_ENV=production` sebelum memulakan pelayan.
Portal ini disediakan untuk latihan localhost sahaja. Jangan dedahkan terus ke Internet; penggunaan production memerlukan HTTPS dan session store yang sesuai selain konfigurasi di atas.

## Deploy ke Render

Backend Express menyajikan frontend daripada `public/`, jadi deploy sebagai **satu Web Service Node.js** (bukan Static Site berasingan).

1. Pastikan seluruh folder projek—termasuk `package.json`, `package-lock.json`, `server.js`, `README.md` dan `public/`—ada dalam repository GitHub. Jangan masukkan `node_modules/`, `.env`, `data/` atau `uploads/`; semuanya dikecualikan oleh `.gitignore`.
2. Push repository ke GitHub dan di Render pilih **New → Web Service**, kemudian sambungkan repository itu.
3. Tetapkan konfigurasi service:
   - **Root Directory:** kosong jika projek di akar repository; jika berada di subfolder, isi laluan subfolder projek.
   - **Runtime:** Node.
   - **Build Command:** `npm install` (boleh guna `npm ci` jika lockfile tersedia).
   - **Start Command:** `npm start`.
4. Tambahkan environment variables:
   - `NODE_ENV` = `production`
   - `SESSION_SECRET` = nilai rahsia panjang dan rawak. Jana secara lokal dengan `node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"` dan masukkan hasilnya di Render; jangan commit atau kongsi nilai ini.
   - `DATA_DIR` = `/var/data`
   - `UPLOAD_DIR` = `/var/data/uploads`
5. Tambahkan **Persistent Disk** ke service, dengan mount path `/var/data` dan saiz yang sesuai. Semak syarat/availability disk untuk jenis plan Render yang dipilih. Tanpa persistent disk, SQLite dan fail upload pada filesystem service boleh hilang apabila service redeploy atau dimulakan semula.
6. Cipta service dan tunggu deploy selesai. Buka URL `onrender.com` yang diberikan. `server.js` menggunakan `process.env.PORT` (fallback `3000`) dan melayani frontend melalui `express.static(public)`.

`express-session` saat ini memakai MemoryStore bawaan, yang tidak persisten dan tidak disarankan untuk production. Sesi pengguna boleh hilang ketika instance restart/deploy; untuk penggunaan nyata, ganti dengan session store eksternal yang persisten. Persistent Disk menjaga SQLite dan upload, tetapi tidak menjadikan session MemoryStore persisten. Akun bawaan adalah akun demo dengan kata laluan publik di dokumentasi—jangan gunakan untuk data sebenar atau deployment publik; siapkan akun dan kredensial khusus sebelum membukanya.

## Akaun latihan

| Peranan | E-mel | Kata laluan |
|---|---|---|
| Mahasiswa | `alya@fikti.test` | `MhsFikti2026!` |
| Mahasiswa | `bima@fikti.test` | `MhsFikti2026!` |
| Dosen | `dina@fikti.test` | `DosenFikti2026!` |
| Admin | `raka@fikti.test` | `AdminFikti2026!` |

Tukar kata laluan contoh sebelum menggunakan aplikasi dalam persekitaran yang dikongsi.

## Ciri

- **Mahasiswa:** log masuk, lihat nilai sendiri, muat naik tugasan dan berforum.
- **Dosen:** lihat kiriman tugasan serta merekod nilai mahasiswa.
- **Admin:** cipta dan padam akaun pengguna.
- Password disimpan sebagai hash scrypt; sesi menggunakan cookie `HttpOnly`/`SameSite=Strict` dan operasi perubahan memerlukan token CSRF.

## Latihan keselamatan yang selamat

### SQL injection

Log masuk menggunakan pertanyaan berparameter (`WHERE email = ?`), bukannya membina SQL daripada teks input. Cuba masukkan payload seperti `' OR 1=1--` pada medan e-mel dan kata laluan. Hasil yang dijangka: log masuk gagal dengan mesej generik, dan data tidak terdedah. Carian dan operasi pangkalan data lain juga tidak menyambung input pengguna ke dalam SQL.

### Validasi fail

Muat naik mengehadkan sambungan dan MIME kepada PDF/DOCX/TXT, saiz fail kepada 5 MB, memeriksa tandatangan asas kandungan, menggunakan nama fail rawak di luar direktori awam, dan memerlukan sesi mahasiswa. Cuba pilih fail bernama `.php` atau fail PDF palsu yang tidak bermula dengan `%PDF-`. Hasil yang dijangka: HTTP 400 dan fail tidak disimpan.

Ini ialah demonstrasi kawalan keselamatan dalam aplikasi localhost, bukan arahan untuk menguji sistem pihak ketiga.
