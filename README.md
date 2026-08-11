# 📄 PDF Attachment Manager with 2FA Admin Auth

A lightweight, modern single-page web application to attach, name, preview, download, and manage PDF documents with role-based access control and **2-Factor Authentication (2FA) Email OTP** for Admin login.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Auth](https://img.shields.io/badge/auth-Admin%202FA%20%2F%20Member-purple)
![Storage](https://img.shields.io/badge/storage-MySQL-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

---

## 🔐 Authentication & Security

### 🛡️ Admin Role (2FA Enabled)
- **Ultra-Secure Access**:
  1. **Username & Password**: Configured via `.env` file (never hardcoded)
  2. **2-Factor Email OTP Verification**: After providing valid credentials, a secure 6-digit OTP code is dispatched via Gmail SMTP.
  3. Enter the 6-digit OTP code to complete Admin login.
- **Admin Permissions**: Upload PDF attachments, set custom display names, rename files, delete attachments, preview, and download.

### 👤 Member Role
- **Read-Only Access**:
  - **Default Credentials**: Configured via `.env` file
  - **Self-Registration**: Members can register their own accounts (stored in MySQL)
  - Search, Preview in full-screen modal, and Download PDFs to local storage.
  - Upload, Rename, and Delete tools are securely hidden.

### 🛡️ Security Features
- **bcrypt** password hashing (server-side)
- **Cryptographic session tokens** (64-byte hex) stored in `httpOnly` cookies
- **Server-side OTP** generation, storage & validation with timing-safe comparison
- **OTP expiration** (5 minutes) & attempt lockout
- **Rate limiting** on login (5/15min) and OTP (5/5min)
- **Account lockout** after 10 failed attempts (30min cooldown)
- **Helmet** security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Restricted CORS** policy
- **Request body size limits** (DoS protection)
- **SameSite=Strict** cookies (CSRF protection)
- **Input sanitization** on all auth endpoints
- **Automatic cleanup** of expired sessions, OTPs, and rate limits every 15min

---

## 💾 Database

This app uses **MySQL** for persistent storage with connection pooling via `mysql2`.

### Tables
| Table | Purpose |
|---|---|
| `sessions` | Active user sessions (httpOnly cookie tokens) |
| `members` | Registered member accounts (username, bcrypt hash, name) |
| `pending_otps` | Admin 2FA OTP codes (with expiry & attempt tracking) |
| `rate_limits` | Per-IP rate limiting counters |
| `account_lockouts` | Failed login tracking & temporary account locks |
| `pdf_attachments` | Uploaded PDF files stored as `LONGBLOB` (up to ~4GB each) |

All tables are **auto-created** on first server startup. No manual SQL setup required.

---

## 🛠️ Project Structure

```text
my workbench/
├── .env                # 🔒 Credentials & secrets (git-ignored, NEVER commit)
├── .gitignore          # Excludes .env, node_modules, logs, etc.
├── server.js           # Hardened Express server (auth, 2FA, sessions, PDF API)
├── database.js         # MySQL database module (async pool, prepared queries)
├── index.html          # Main layout, 2FA OTP Modal, PDF Grid & Viewer
├── style.css           # CSS design system, 2FA OTP styles, background
├── app.js              # Secure frontend (zero credentials, cookie-based auth)
├── bg_iit_dholakpur.png# Futuristic background image
├── package.json        # Dependencies & scripts
└── README.md           # This file
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** (v18 or higher)
- **MySQL** server (standalone, XAMPP, or any MySQL-compatible server)

### 1. Create MySQL Database

Create a database in MySQL (via phpMyAdmin, MySQL CLI, or any client):

```sql
CREATE DATABASE pdfs;
```

> Tables are auto-created when the server starts — no additional SQL needed.

### 2. Configure Environment

Copy the example below into a `.env` file in the project root and fill in your values:

```env
PORT=3000

# Admin credentials
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_secure_password
ADMIN_EMAIL=your_admin_email@example.com

# Member credentials (default account)
MEMBER_USERNAME=your_member_username
MEMBER_PASSWORD=your_member_password

# Gmail SMTP (for OTP emails)
GMAIL_USER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password

# Session secret
SESSION_SECRET=generate_a_random_64_char_hex_string

# MySQL Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=pdfs
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Then open `http://localhost:3000` in your browser.

---

## ⚠️ Security Notes

- **NEVER** commit the `.env` file to version control
- Use a [Gmail App Password](https://myaccount.google.com/apppasswords) (not your main password) for SMTP
- In production, use HTTPS (the server enforces secure headers)
- Session tokens are stored in `httpOnly` cookies — they cannot be stolen via XSS
- PDF files are stored as BLOBs in MySQL — no file system exposure

---

## 📄 License

This project is open-source and free to use under the [MIT License](LICENSE).
