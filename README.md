# 📄 PDF Attachment Manager with 2FA Admin Auth

<div align="center">

![PDF Manager Banner](./pdf_manager_banner.png)

### *Enterprise-Grade, Cloud-Ready PDF Management System with 2FA Admin Security & MySQL Storage*

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Auth](https://img.shields.io/badge/auth-Admin%202FA%20%2F%20Member-purple.svg)](#-authentication--security)
[![Storage](https://img.shields.io/badge/storage-MySQL-blue.svg)](#-database)
[![Node](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org/)
[![Cloud Ready](https://img.shields.io/badge/cloud-Render%20%2F%20Cloudflare-orange.svg)](#-cloud--render-deployment)
[![Health Check](https://img.shields.io/badge/health-Active-brightgreen.svg)](#-api-endpoints)

</div>

---

## ✨ Overview

**PDF Attachment Manager** is a hardened, single-page web application designed to store, manage, preview, and serve PDF documents with zero client-side credential exposure. Built with a Node.js/Express backend and persistent MySQL connection pooling, it features **2-Factor Email OTP verification** for Admin operations, self-registration for Members, and seamless resilience for cloud deployments like **Render.com**.

---

## 🌟 Key Attractions & Features

### 🔑 2-Factor Authentication (2FA) Admin Security
- **Gmail SMTP Integration**: Admin login generates a cryptographically random 6-digit OTP code sent directly to the Admin's email.
- **Timing-Safe Validation**: Server-side OTP comparison prevents timing attacks with 5-minute code expiration and 5-attempt brute-force protection.
- **Session Single-Device Enforcement**: Admin login automatically invalidates prior sessions for maximum account security.

### 👤 Role-Based Access Control (RBAC)
- **Admin Role**: Full access to upload PDFs, assign custom display names, rename files, delete attachments, preview, and download.
- **Member Role**: Read-only access with self-registration capability. Members can search, preview in a full-screen modal, and download attachments.

### ☁️ Cloud & Render Production Resilience
- **Zero-Crash Server Startup**: Server binds port immediately on startup so cloud health checks pass without waiting on database wake-ups.
- **Async Auto-Reconnect Engine**: Automatically retries DB connections in the background if cloud databases (e.g., Aiven free tier) undergo inactivity power-offs.
- **Proxy Trust (`trust proxy`)**: Seamlessly handles reverse proxies (Render, Heroku, Cloudflare, Nginx) preventing 301 infinite redirect loops (`ERR_TOO_MANY_REDIRECTS`).
- **Dedicated Health Endpoint (`/health`)**: Real-time status probe reporting system uptime and DB connectivity status.

### 🛡️ Enterprise Security Stack
- **`httpOnly` & `SameSite` Cookies**: Session tokens (64-byte hex) are stored securely in browser cookies inaccessible to JavaScript (XSS protection).
- **Helmet Security Headers**: Enforces strict Content Security Policy (CSP), HSTS, frame restriction, and MIME type sniffing protection.
- **Rate Limiting & Lockout**: MySQL-backed rate limiters on login endpoints and automatic 30-minute lockout after 10 failed login attempts.
- **MySQL LONGBLOB Storage**: PDF files are stored directly in MySQL as binary data — no exposed server file paths or static file vulnerabilities.

---

## 💾 Database Schema

Powered by **MySQL** (`mysql2` connection pool with SSL support):

| Table Name | Description |
|---|---|
| 🔐 `sessions` | Active session tokens with 24-hour expiration |
| 👤 `members` | Registered member credentials with bcrypt password hashes |
| 🔑 `pending_otps` | Active 2FA OTP codes with expiration & attempt counters |
| 🛡️ `rate_limits` | Per-IP request counters for brute-force protection |
| 🔒 `account_lockouts` | Failed login attempt counters and temporary lockouts |
| 📄 `pdf_attachments` | Uploaded PDF documents stored as `LONGBLOB` binary data |

> 💡 **Auto-Migration**: All database tables are created automatically on server startup.

---

## 🔌 API Endpoints

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/health` | Public | Real-time health check (uptime & DB status) |
| `POST` | `/api/login` | Public | Validate credentials (triggers 2FA for Admin) |
| `POST` | `/api/verify-otp` | Public | Validate 6-digit 2FA OTP code |
| `POST` | `/api/resend-otp` | Public | Dispatch a new OTP code via email |
| `POST` | `/api/register` | Public | Self-register a new Member account |
| `GET` | `/api/session` | Authenticated | Verify active user session |
| `POST` | `/api/logout` | Authenticated | Destroy session token and clear cookies |
| `GET` | `/api/pdfs` | Authenticated | List all PDF metadata |
| `POST` | `/api/pdfs` | Admin Only | Upload PDF attachment (`multipart/form-data`) |
| `GET` | `/api/pdfs/:id/file` | Authenticated | Stream PDF file for preview or download |
| `PATCH` | `/api/pdfs/:id` | Admin Only | Rename PDF display name |
| `DELETE` | `/api/pdfs/:id` | Admin Only | Delete PDF attachment |

---

## 🛠️ Project Structure

```text
my workbench/
├── pdf_manager_banner.png  # 🖼️ High-resolution project header banner
├── .env                    # 🔒 Environment variables (git-ignored)
├── .gitignore              # Excludes .env, node_modules, temp files
├── server.js               # Express server (Auth, 2FA, Helmet, Health Check)
├── database.js             # MySQL module (Async Pool, Retries, Tables)
├── index.html              # Frontend layout, 2FA Modal, PDF Grid & Viewer
├── style.css               # Kinetic CSS design system & dynamic styling
├── app.js                  # Frontend client (Cookie auth, API consumer)
├── bg_iit_dholakpur.png    # Futuristic background graphic
├── package.json            # Project dependencies & start scripts
└── README.md               # Project documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Node.js**: v18.0.0 or higher
- **MySQL Database**: Local MySQL instance or Cloud provider (Aiven, PlanetScale, Railway, AWS RDS)

### 2. Configure Environment (`.env`)
Create a `.env` file in the project root:

```env
PORT=3000

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_admin_password
ADMIN_EMAIL=your_admin_email@gmail.com

# Member Credentials (default account)
MEMBER_USERNAME=member
MEMBER_PASSWORD=your_member_password

# Gmail SMTP for 2FA OTP Email
GMAIL_USER=your_admin_email@gmail.com
GMAIL_APP_PASSWORD=your_16_char_gmail_app_password

# Cryptographic Session Secret
SESSION_SECRET=a_random_64_character_hex_secret_key

# MySQL Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=pdfs
DB_SSL=false
```

### 3. Install & Run Locally

```bash
# Install dependencies
npm install

# Start server
npm start
```
Visit `http://localhost:3000` in your browser.

---

## 🌐 Cloud & Render Deployment

1. Push your repository to **GitHub**.
2. Connect your repo to **Render.com** (Web Service).
3. Set **Build Command**: `npm install`
4. Set **Start Command**: `node server.js`
5. In Render's **Environment** settings, add all key-value pairs from your `.env` file (`DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`, etc.).
6. Render's health check path automatically points to `/health`.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
