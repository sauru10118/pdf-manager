/**
 * PDF Manager - MySQL Database Module
 * =====================================
 * Persistent storage for sessions, OTPs, rate limits,
 * account lockouts, and PDF attachments using mysql2.
 * 
 * All data survives server restarts. Connection pooling enabled.
 */

const mysql = require('mysql2/promise');

class PdfManagerDB {
    constructor() {
        this.pool = null;
    }

    /**
     * Initialize the connection pool and create tables.
     * Must be called (and awaited) before using any other methods.
     */
    async initialize() {
        const poolConfig = {
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT) || 3306,
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'pdfs',
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            charset: 'utf8mb4',
        };

        // Enable SSL for cloud databases (Aiven, PlanetScale, etc.)
        if (process.env.DB_SSL === 'true') {
            poolConfig.ssl = { rejectUnauthorized: false };
        }

        this.pool = mysql.createPool(poolConfig);

        // Verify connectivity
        const conn = await this.pool.getConnection();
        conn.release();

        await this._createTables();
    }

    // ========================================
    // Schema
    // ========================================
    async _createTables() {
        const queries = [
            `CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(255) PRIMARY KEY,
                username VARCHAR(128) NOT NULL,
                role VARCHAR(32) NOT NULL,
                name VARCHAR(256) NOT NULL,
                created_at BIGINT NOT NULL,
                INDEX idx_sessions_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

            `CREATE TABLE IF NOT EXISTS pending_otps (
                username VARCHAR(128) PRIMARY KEY,
                code VARCHAR(16) NOT NULL,
                email VARCHAR(256) NOT NULL,
                expires_at BIGINT NOT NULL,
                attempts INT DEFAULT 0
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

            `CREATE TABLE IF NOT EXISTS rate_limits (
                \`key\` VARCHAR(255) PRIMARY KEY,
                count INT DEFAULT 0,
                reset_at BIGINT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

            `CREATE TABLE IF NOT EXISTS account_lockouts (
                username VARCHAR(128) PRIMARY KEY,
                failed_count INT DEFAULT 0,
                locked_until BIGINT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

            `CREATE TABLE IF NOT EXISTS pdf_attachments (
                id VARCHAR(128) PRIMARY KEY,
                custom_name VARCHAR(512) NOT NULL,
                original_filename VARCHAR(512) NOT NULL,
                file_data LONGBLOB NOT NULL,
                file_size BIGINT NOT NULL,
                uploaded_by VARCHAR(128) NOT NULL,
                created_at BIGINT NOT NULL,
                INDEX idx_pdf_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

            `CREATE TABLE IF NOT EXISTS members (
                username VARCHAR(128) PRIMARY KEY,
                password_hash VARCHAR(256) NOT NULL,
                name VARCHAR(256) NOT NULL,
                created_at BIGINT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
        ];

        for (const query of queries) {
            await this.pool.execute(query);
        }
    }

    // ========================================
    // SESSIONS
    // ========================================
    async createSession(token, username, role, name) {
        await this.pool.execute(
            'INSERT INTO sessions (token, username, role, name, created_at) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE username=VALUES(username), role=VALUES(role), name=VALUES(name), created_at=VALUES(created_at)',
            [token, username, role, name, Date.now()]
        );
    }

    async getSession(token) {
        const [rows] = await this.pool.execute('SELECT * FROM sessions WHERE token = ?', [token]);
        return rows[0] || null;
    }

    async deleteSession(token) {
        const [result] = await this.pool.execute('DELETE FROM sessions WHERE token = ?', [token]);
        return { changes: result.affectedRows };
    }

    async deleteUserSessions(username) {
        const [result] = await this.pool.execute('DELETE FROM sessions WHERE username = ?', [username]);
        return { changes: result.affectedRows };
    }

    async cleanExpiredSessions(maxAgeMs = 24 * 60 * 60 * 1000) {
        const [result] = await this.pool.execute('DELETE FROM sessions WHERE created_at < ?', [Date.now() - maxAgeMs]);
        return { changes: result.affectedRows };
    }

    // ========================================
    // MEMBERS
    // ========================================
    async createMember(username, passwordHash, name) {
        await this.pool.execute(
            'INSERT INTO members (username, password_hash, name, created_at) VALUES (?, ?, ?, ?)',
            [username, passwordHash, name, Date.now()]
        );
    }

    async getMember(username) {
        const [rows] = await this.pool.execute('SELECT * FROM members WHERE username = ?', [username]);
        return rows[0] || null;
    }

    // ========================================
    // OTPs
    // ========================================
    async setPendingOtp(username, code, email, expiresAt) {
        await this.pool.execute(
            'INSERT INTO pending_otps (username, code, email, expires_at, attempts) VALUES (?, ?, ?, ?, 0) ON DUPLICATE KEY UPDATE code=VALUES(code), email=VALUES(email), expires_at=VALUES(expires_at), attempts=0',
            [username, code, email, expiresAt]
        );
    }

    async getPendingOtp(username) {
        const [rows] = await this.pool.execute('SELECT * FROM pending_otps WHERE username = ?', [username]);
        return rows[0] || null;
    }

    async deletePendingOtp(username) {
        const [result] = await this.pool.execute('DELETE FROM pending_otps WHERE username = ?', [username]);
        return { changes: result.affectedRows };
    }

    async incrementOtpAttempts(username) {
        await this.pool.execute('UPDATE pending_otps SET attempts = attempts + 1 WHERE username = ?', [username]);
    }

    async updateOtpCode(username, code, expiresAt) {
        await this.pool.execute(
            'UPDATE pending_otps SET code = ?, expires_at = ?, attempts = 0 WHERE username = ?',
            [code, expiresAt, username]
        );
    }

    async cleanExpiredOtps() {
        const [result] = await this.pool.execute('DELETE FROM pending_otps WHERE expires_at < ?', [Date.now()]);
        return { changes: result.affectedRows };
    }

    // ========================================
    // RATE LIMITS
    // ========================================
    async checkRateLimit(key, maxAttempts, windowMs) {
        const now = Date.now();
        const [rows] = await this.pool.execute('SELECT * FROM rate_limits WHERE `key` = ?', [key]);
        const record = rows[0];

        if (!record || now > record.reset_at) {
            await this.pool.execute(
                'INSERT INTO rate_limits (`key`, count, reset_at) VALUES (?, 1, ?) ON DUPLICATE KEY UPDATE count=1, reset_at=VALUES(reset_at)',
                [key, now + windowMs]
            );
            return { allowed: true, count: 1 };
        }

        const newCount = record.count + 1;
        await this.pool.execute(
            'UPDATE rate_limits SET count = ? WHERE `key` = ?',
            [newCount, key]
        );

        if (newCount > maxAttempts) {
            const waitSec = Math.ceil((record.reset_at - now) / 1000);
            return { allowed: false, count: newCount, waitSec };
        }

        return { allowed: true, count: newCount };
    }

    async cleanExpiredRateLimits() {
        const [result] = await this.pool.execute('DELETE FROM rate_limits WHERE reset_at < ?', [Date.now()]);
        return { changes: result.affectedRows };
    }

    // ========================================
    // ACCOUNT LOCKOUTS
    // ========================================
    async checkAccountLockout(username) {
        const [rows] = await this.pool.execute('SELECT * FROM account_lockouts WHERE username = ?', [username]);
        const lockout = rows[0];
        if (!lockout) return { locked: false };

        if (lockout.locked_until && Date.now() < lockout.locked_until) {
            const waitMin = Math.ceil((lockout.locked_until - Date.now()) / 60000);
            return { locked: true, waitMin };
        }

        // Lockout expired — reset
        if (lockout.locked_until && Date.now() >= lockout.locked_until) {
            await this.pool.execute('DELETE FROM account_lockouts WHERE username = ?', [username]);
        }

        return { locked: false };
    }

    async recordFailedLogin(username, maxFailures = 10, lockoutMs = 30 * 60 * 1000) {
        const [rows] = await this.pool.execute('SELECT * FROM account_lockouts WHERE username = ?', [username]);
        const lockout = rows[0];
        const failedCount = lockout ? lockout.failed_count + 1 : 1;
        const lockedUntil = failedCount >= maxFailures ? Date.now() + lockoutMs : null;

        await this.pool.execute(
            'INSERT INTO account_lockouts (username, failed_count, locked_until) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE failed_count=VALUES(failed_count), locked_until=VALUES(locked_until)',
            [username, failedCount, lockedUntil]
        );

        if (lockedUntil) {
            console.warn(`🔒 Account "${username}" locked for ${lockoutMs / 60000}min after ${maxFailures} failed attempts.`);
        }
    }

    async resetFailedLogin(username) {
        const [result] = await this.pool.execute('DELETE FROM account_lockouts WHERE username = ?', [username]);
        return { changes: result.affectedRows };
    }

    async cleanExpiredLockouts() {
        const [result] = await this.pool.execute(
            'DELETE FROM account_lockouts WHERE locked_until IS NOT NULL AND locked_until < ?',
            [Date.now()]
        );
        return { changes: result.affectedRows };
    }

    // ========================================
    // PDF ATTACHMENTS
    // ========================================
    async savePdf(id, customName, originalFilename, fileData, fileSize, uploadedBy) {
        await this.pool.execute(
            'INSERT INTO pdf_attachments (id, custom_name, original_filename, file_data, file_size, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, customName, originalFilename, fileData, fileSize, uploadedBy, Date.now()]
        );
    }

    async getAllPdfs() {
        const [rows] = await this.pool.execute(
            'SELECT id, custom_name, original_filename, file_size, uploaded_by, created_at FROM pdf_attachments ORDER BY created_at DESC'
        );
        return rows;
    }

    async getPdfFile(id) {
        const [rows] = await this.pool.execute(
            'SELECT id, custom_name, original_filename, file_data, file_size FROM pdf_attachments WHERE id = ?',
            [id]
        );
        return rows[0] || null;
    }

    async getPdfMeta(id) {
        const [rows] = await this.pool.execute(
            'SELECT id, custom_name, original_filename, file_size, uploaded_by, created_at FROM pdf_attachments WHERE id = ?',
            [id]
        );
        return rows[0] || null;
    }

    async deletePdf(id) {
        const [result] = await this.pool.execute('DELETE FROM pdf_attachments WHERE id = ?', [id]);
        return { changes: result.affectedRows };
    }

    async renamePdf(id, newName) {
        await this.pool.execute('UPDATE pdf_attachments SET custom_name = ? WHERE id = ?', [newName, id]);
    }

    async getPdfStats() {
        const [rows] = await this.pool.execute(
            'SELECT COUNT(*) as count, COALESCE(SUM(file_size), 0) as total_size FROM pdf_attachments'
        );
        return rows[0];
    }

    // ========================================
    // PERIODIC CLEANUP
    // ========================================
    async runCleanup() {
        const results = {
            sessions: (await this.cleanExpiredSessions()).changes,
            otps: (await this.cleanExpiredOtps()).changes,
            rateLimits: (await this.cleanExpiredRateLimits()).changes,
            lockouts: (await this.cleanExpiredLockouts()).changes,
        };
        const total = Object.values(results).reduce((a, b) => a + b, 0);
        if (total > 0) {
            console.log(`🧹 DB Cleanup: ${results.sessions} sessions, ${results.otps} OTPs, ${results.rateLimits} rate-limits, ${results.lockouts} lockouts purged.`);
        }
        return results;
    }

    // ========================================
    // SHUTDOWN
    // ========================================
    async close() {
        if (this.pool) {
            await this.pool.end();
        }
    }
}

module.exports = PdfManagerDB;
