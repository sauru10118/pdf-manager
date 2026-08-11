/**
 * PDF Attachment Manager - Secure Frontend (Server API Edition)
 * ==============================================================
 * ZERO credentials, ZERO OTP codes, ZERO passwords, ZERO tokens in this file.
 * All authentication handled via httpOnly cookies (automatic).
 * All PDF storage handled via server API (SQLite-backed).
 * No IndexedDB, no localStorage — everything persists on the server.
 */

// Global App State
let currentUser = null;     // { username, role, name } — received from server
let activeRoleTab = 'admin';
let currentSelectedFile = null;
let pdfItems = [];
let renamingId = null;

// DOM Element References
const loginModal = document.getElementById('login-modal');
const loginStepCredentials = document.getElementById('login-step-credentials');
const loginStepOtp = document.getElementById('login-step-otp');
const loginStepRegister = document.getElementById('login-step-register');

const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const loginError = document.getElementById('login-error');
const loginSubmitBtn = document.getElementById('login-submit-btn');
const tabAdmin = document.getElementById('tab-admin');
const tabMember = document.getElementById('tab-member');

const registerHint = document.getElementById('register-hint');
const showRegisterBtn = document.getElementById('show-register-btn');
const registerForm = document.getElementById('register-form');
const regNameInput = document.getElementById('reg-name-input');
const regUsernameInput = document.getElementById('reg-username-input');
const regPasswordInput = document.getElementById('reg-password-input');
const regError = document.getElementById('reg-error');
const regSubmitBtn = document.getElementById('reg-submit-btn');
const backToLoginFromRegBtn = document.getElementById('back-to-login-from-reg-btn');

const otpForm = document.getElementById('otp-form');
const otpSentEmail = document.getElementById('otp-sent-email');
const otpError = document.getElementById('otp-error');
const resendOtpBtn = document.getElementById('resend-otp-btn');
const resendTimer = document.getElementById('resend-timer');
const backToLoginBtn = document.getElementById('back-to-login-btn');
const otpInputs = [
    document.getElementById('otp-1'),
    document.getElementById('otp-2'),
    document.getElementById('otp-3'),
    document.getElementById('otp-4'),
    document.getElementById('otp-5'),
    document.getElementById('otp-6')
];

const userSessionBar = document.getElementById('user-session-bar');
const userNameDisplay = document.getElementById('user-name-display');
const roleIcon = document.getElementById('role-icon');
const roleTag = document.getElementById('role-tag');
const logoutBtn = document.getElementById('logout-btn');

const uploadSection = document.getElementById('upload-section');
const memberInfoBanner = document.getElementById('member-info-banner');
const stepNumList = document.getElementById('step-num-list');
const emptyStateText = document.getElementById('empty-state-text');

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('pdf-file-input');
const customNameInput = document.getElementById('pdf-name-input');
const selectedFileNameEl = document.getElementById('selected-file-name');
const attachBtn = document.getElementById('attach-btn');
const uploadForm = document.getElementById('upload-form');

const pdfGrid = document.getElementById('pdf-grid');
const emptyState = document.getElementById('empty-state');
const searchInput = document.getElementById('search-input');

const statCount = document.getElementById('stat-count');
const statSize = document.getElementById('stat-size');

const previewModal = document.getElementById('preview-modal');
const modalPdfTitle = document.getElementById('modal-pdf-title');
const modalDownloadBtn = document.getElementById('modal-download-btn');
const modalCloseBtn = document.getElementById('modal-close-btn');
const pdfViewer = document.getElementById('pdf-viewer');

const renameModal = document.getElementById('rename-modal');
const renameForm = document.getElementById('rename-form');
const renameInput = document.getElementById('rename-input');
const renameCloseBtn = document.getElementById('rename-close-btn');
const renameCancelBtn = document.getElementById('rename-cancel-btn');

const toastContainer = document.getElementById('toast-container');

let resendTimerInterval = null;

// ============================================================
// 1. SERVER API FUNCTIONS (replaces IndexedDB)
// ============================================================

async function fetchPdfsFromServer() {
    const response = await fetch('/api/pdfs', { credentials: 'include' });
    if (!response.ok) {
        if (response.status === 401) return [];
        throw new Error('Failed to fetch PDFs');
    }
    const data = await response.json();
    // Map snake_case DB fields to camelCase for frontend consistency
    return data.pdfs.map(p => ({
        id: p.id,
        customName: p.custom_name,
        originalFileName: p.original_filename,
        fileSize: p.file_size,
        uploadedBy: p.uploaded_by,
        timestamp: p.created_at
    }));
}

async function uploadPdfToServer(file, customName) {
    const formData = new FormData();
    formData.append('pdf', file);
    formData.append('customName', customName);

    const response = await fetch('/api/pdfs', {
        method: 'POST',
        credentials: 'include',
        body: formData  // no Content-Type — browser sets multipart boundary
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Upload failed');

    // Map to frontend format
    return {
        id: data.pdf.id,
        customName: data.pdf.custom_name,
        originalFileName: data.pdf.original_filename,
        fileSize: data.pdf.file_size,
        uploadedBy: data.pdf.uploaded_by,
        timestamp: data.pdf.created_at
    };
}

async function deletePdfFromServer(id) {
    const response = await fetch(`/api/pdfs/${id}`, {
        method: 'DELETE',
        credentials: 'include'
    });
    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Delete failed');
    }
}

async function renamePdfOnServer(id, newName) {
    const response = await fetch(`/api/pdfs/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ customName: newName })
    });
    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Rename failed');
    }
}

// ============================================================
// 2. APP STARTUP
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
    try {
        initKineticTypography();
        setupAuthListeners();
        setupEventListeners();

        // Check existing session with server (cookie sent automatically)
        const valid = await verifySessionWithServer();
        if (!valid) {
            openLoginModal();
        }

        await loadPdfAttachments();
    } catch (err) {
        console.error('App init failed:', err);
    }
});

function initKineticTypography() {
    const titleEl = document.getElementById('app-title');
    if (!titleEl) return;

    const text = titleEl.textContent.trim();
    titleEl.innerHTML = '';
    titleEl.classList.add('kinetic-heading');

    [...text].forEach((char, index) => {
        const span = document.createElement('span');
        span.className = 'kinetic-char';
        span.textContent = char === ' ' ? '\u00A0' : char;
        span.style.animationDelay = `${(index * 0.15).toFixed(2)}s`;
        titleEl.appendChild(span);
    });
}

// ============================================================
// 3. SERVER-SIDE AUTH FLOW
// ============================================================
async function verifySessionWithServer() {
    try {
        const response = await fetch('/api/session', {
            credentials: 'include'
        });
        const data = await response.json();
        if (response.ok && data.success) {
            currentUser = data.user;
            applyUserRole(currentUser);
            loginModal.classList.remove('active');
            return true;
        }
    } catch (err) {
        console.error('Session check failed:', err);
    }
    return false;
}

function setupAuthListeners() {
    tabAdmin.addEventListener('click', () => switchRoleTab('admin'));
    tabMember.addEventListener('click', () => switchRoleTab('member'));

    // STEP 1: Login form — sends credentials to server
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.style.display = 'none';
        loginSubmitBtn.disabled = true;
        loginSubmitBtn.textContent = 'Signing In...';

        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username, password, role: activeRoleTab })
            });

            const data = await response.json();

            if (response.status === 429 || response.status === 423) {
                showLoginError(`🚫 ${data.error}`);
            } else if (!response.ok) {
                showLoginError(data.error || 'Login failed.');
            } else if (data.requires2FA) {
                showOtpStep(data.message);
            } else {
                // Member — direct login (cookie set by server)
                currentUser = data.user;
                loginModal.classList.remove('active');
                applyUserRole(currentUser);
                await loadPdfAttachments();
                showToast(`Welcome, ${currentUser.name}!`);
            }
        } catch (err) {
            showLoginError('Could not reach the server. Is it running?');
        }

        loginSubmitBtn.disabled = false;
        loginSubmitBtn.textContent = 'Sign In';
    });

    // OTP Input Auto-advance
    otpInputs.forEach((input, idx) => {
        input.addEventListener('input', (e) => {
            const val = e.target.value.replace(/[^0-9]/g, '');
            e.target.value = val;
            if (val && idx < otpInputs.length - 1) otpInputs[idx + 1].focus();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && idx > 0) otpInputs[idx - 1].focus();
        });
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text').trim();
            if (/^\d{6}$/.test(paste)) {
                paste.split('').forEach((ch, i) => { if (otpInputs[i]) otpInputs[i].value = ch; });
                otpInputs[5].focus();
            }
        });
    });

    // STEP 2: OTP form — sends code to server for validation
    otpForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        otpError.style.display = 'none';

        const enteredOtp = otpInputs.map(i => i.value).join('');
        if (enteredOtp.length < 6) {
            showOtpError('Please enter all 6 digits.');
            return;
        }

        try {
            const response = await fetch('/api/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ otpCode: enteredOtp })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                currentUser = data.user;
                loginModal.classList.remove('active');
                applyUserRole(currentUser);
                await loadPdfAttachments();
                showToast('🛡️ 2FA Verification Successful! Welcome, Admin.');
            } else {
                showOtpError(data.error || 'Invalid OTP code.');
                otpInputs.forEach(i => i.value = '');
                otpInputs[0].focus();
            }
        } catch (err) {
            showOtpError('Server error. Is the server running?');
        }
    });

    // Resend OTP
    resendOtpBtn.addEventListener('click', async () => {
        if (resendOtpBtn.disabled) return;
        try {
            const response = await fetch('/api/resend-otp', {
                method: 'POST',
                credentials: 'include'
            });
            const data = await response.json();
            if (response.ok) {
                showToast(`📩 ${data.message}`);
                startResendTimer(60);
            } else {
                showToast(`⚠️ ${data.error}`, 'error');
            }
        } catch (err) {
            showToast('⚠️ Could not resend OTP.', 'error');
        }
    });

    backToLoginBtn.addEventListener('click', () => showCredentialsStep());
    if (showRegisterBtn) showRegisterBtn.addEventListener('click', () => showRegisterStep());
    if (backToLoginFromRegBtn) backToLoginFromRegBtn.addEventListener('click', () => showCredentialsStep());

    // Member Registration form
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            showRegError('');
            regSubmitBtn.disabled = true;
            regSubmitBtn.textContent = 'Creating Account...';

            const name = regNameInput.value.trim();
            const username = regUsernameInput.value.trim();
            const password = regPasswordInput.value.trim();

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ username, password, name })
                });

                const data = await response.json();

                if (!response.ok) {
                    showRegError(data.error || 'Registration failed.');
                } else {
                    currentUser = data.user;
                    loginModal.classList.remove('active');
                    applyUserRole(currentUser);
                    await loadPdfAttachments();
                    showToast(`Welcome, ${currentUser.name}! Member account created.`);
                }
            } catch (err) {
                showRegError('Could not reach the server. Is it running?');
            }

            regSubmitBtn.disabled = false;
            regSubmitBtn.textContent = 'Create Member Account';
        });
    }

    // Logout — server invalidation + cookie cleared by server
    logoutBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/logout', {
                method: 'POST',
                credentials: 'include'
            });
        } catch (e) { /* ignore */ }
        currentUser = null;
        pdfItems = [];
        document.body.classList.remove('is-member', 'is-admin');
        renderPdfGrid();
        updateStats();
        showToast('Logged out successfully.');
        openLoginModal();
    });
}

// --- UI Helpers ---
function switchRoleTab(role) {
    activeRoleTab = role;
    tabAdmin.classList.toggle('active', role === 'admin');
    tabMember.classList.toggle('active', role === 'member');
    usernameInput.placeholder = role === 'admin' ? 'Enter admin username' : 'Enter member username';
    loginError.style.display = 'none';
    if (registerHint) registerHint.style.display = role === 'member' ? 'block' : 'none';
}

function showLoginError(msg) { loginError.textContent = msg; loginError.style.display = 'block'; }
function showOtpError(msg) { otpError.textContent = msg; otpError.style.display = 'block'; }
function showRegError(msg) {
    if (!regError) return;
    if (msg) { regError.textContent = msg; regError.style.display = 'block'; }
    else { regError.style.display = 'none'; }
}

function openLoginModal() {
    loginModal.classList.add('active');
    showCredentialsStep();
}

function showCredentialsStep() {
    loginStepCredentials.style.display = 'block';
    loginStepOtp.style.display = 'none';
    if (loginStepRegister) loginStepRegister.style.display = 'none';
    usernameInput.value = '';
    passwordInput.value = '';
    loginError.style.display = 'none';
    if (registerHint) registerHint.style.display = activeRoleTab === 'member' ? 'block' : 'none';
}

function showRegisterStep() {
    loginStepCredentials.style.display = 'none';
    loginStepOtp.style.display = 'none';
    if (loginStepRegister) loginStepRegister.style.display = 'block';
    regNameInput.value = '';
    regUsernameInput.value = '';
    regPasswordInput.value = '';
    if (regError) regError.style.display = 'none';
}

function showOtpStep(message) {
    loginStepCredentials.style.display = 'none';
    loginStepOtp.style.display = 'block';
    otpSentEmail.textContent = message || 'Check your email';
    otpError.style.display = 'none';
    otpInputs.forEach(i => i.value = '');
    startResendTimer(60);
    setTimeout(() => otpInputs[0].focus(), 100);
}

function startResendTimer(seconds) {
    resendOtpBtn.disabled = true;
    let remaining = seconds;
    resendTimer.textContent = `(Resend in ${remaining}s)`;
    if (resendTimerInterval) clearInterval(resendTimerInterval);
    resendTimerInterval = setInterval(() => {
        remaining--;
        if (remaining <= 0) {
            clearInterval(resendTimerInterval);
            resendOtpBtn.disabled = false;
            resendTimer.textContent = '';
        } else {
            resendTimer.textContent = `(Resend in ${remaining}s)`;
        }
    }, 1000);
}

function applyUserRole(user) {
    if (!user) return;
    userNameDisplay.textContent = user.username;
    roleTag.textContent = user.role.toUpperCase();

    if (user.role === 'admin') {
        roleIcon.textContent = '🛡️';
        roleTag.className = 'role-tag admin';
        document.body.classList.remove('is-member');
        document.body.classList.add('is-admin');
        memberInfoBanner.style.display = 'none';
        uploadSection.style.display = 'block';
        stepNumList.textContent = '2';
        emptyStateText.textContent = 'Upload your first PDF file using the attachment section on the left.';
    } else {
        roleIcon.textContent = '👤';
        roleTag.className = 'role-tag member';
        document.body.classList.remove('is-admin');
        document.body.classList.add('is-member');
        memberInfoBanner.style.display = 'flex';
        uploadSection.style.display = 'none';
        stepNumList.textContent = '1';
        emptyStateText.textContent = 'No PDF documents have been attached by an Admin yet.';
    }
    renderPdfGrid();
}

// ============================================================
// 4. PDF ATTACHMENTS (Server API)
// ============================================================
async function loadPdfAttachments() {
    try {
        pdfItems = await fetchPdfsFromServer();
    } catch (err) {
        console.error('Failed to load PDFs:', err);
        pdfItems = [];
    }
    renderPdfGrid();
    updateStats();
}

function updateStats() {
    statCount.textContent = pdfItems.length;
    const totalBytes = pdfItems.reduce((sum, item) => sum + (item.fileSize || 0), 0);
    statSize.textContent = formatBytes(totalBytes);
}

function renderPdfGrid() {
    const searchTerm = searchInput.value.toLowerCase().trim();
    const filteredItems = pdfItems.filter(item =>
        item.customName.toLowerCase().includes(searchTerm) ||
        item.originalFileName.toLowerCase().includes(searchTerm)
    );

    pdfGrid.innerHTML = '';
    if (filteredItems.length === 0) {
        emptyState.style.display = 'block';
        pdfGrid.style.display = 'none';
        return;
    }

    emptyState.style.display = 'none';
    pdfGrid.style.display = 'grid';
    filteredItems.forEach(item => pdfGrid.appendChild(createPdfCardElement(item)));
}

function createPdfCardElement(item) {
    const card = document.createElement('div');
    card.className = 'pdf-card';
    card.dataset.id = item.id;

    const formattedDate = new Date(item.timestamp).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric'
    });

    const isAdmin = currentUser && currentUser.role === 'admin';

    card.innerHTML = `
        <div>
            <div class="card-top">
                <span class="pdf-badge">PDF</span>
                ${isAdmin ? `
                <button class="btn-icon delete-btn" title="Delete" data-id="${item.id}">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                </button>` : ''}
            </div>
            <h3 class="card-title" title="${escapeHtml(item.customName)}">${escapeHtml(item.customName)}</h3>
            <p class="card-filename" title="${escapeHtml(item.originalFileName)}">📄 ${escapeHtml(item.originalFileName)}</p>
            <div class="card-meta">
                <span>💾 ${formatBytes(item.fileSize)}</span>
                <span>•</span>
                <span>📅 ${formattedDate}</span>
            </div>
        </div>
        <div class="card-actions">
            <button class="btn btn-secondary btn-sm preview-btn" data-id="${item.id}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>
                Preview
            </button>
            ${isAdmin ? `
            <button class="btn btn-secondary btn-sm rename-btn" data-id="${item.id}" title="Rename">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                </svg>
            </button>` : ''}
            <button class="btn btn-secondary btn-sm download-btn" data-id="${item.id}" title="Download">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
            </button>
        </div>
    `;
    return card;
}

// ============================================================
// 5. EVENT LISTENERS
// ============================================================
function setupEventListeners() {
    ['dragenter', 'dragover'].forEach(ev => {
        dropzone.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('drag-over'); });
    });
    ['dragleave', 'drop'].forEach(ev => {
        dropzone.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('drag-over'); });
    });

    dropzone.addEventListener('drop', (e) => {
        if (!currentUser || currentUser.role !== 'admin') { showToast('Admin only.', 'error'); return; }
        if (e.dataTransfer.files.length > 0) handleSelectedFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleSelectedFile(e.target.files[0]);
    });

    // Upload form — sends file to server API
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!currentUser || currentUser.role !== 'admin') { showToast('Admin permission required.', 'error'); return; }
        if (!currentSelectedFile) return;

        const customName = customNameInput.value.trim() || currentSelectedFile.name.replace(/\.pdf$/i, '');

        try {
            attachBtn.disabled = true;
            attachBtn.textContent = 'Uploading...';

            const newItem = await uploadPdfToServer(currentSelectedFile, customName);
            pdfItems.unshift(newItem);
            renderPdfGrid();
            updateStats();
            resetUploadForm();
            showToast(`Attached "${newItem.customName}" successfully!`);
        } catch (err) {
            showToast(err.message || 'Error uploading PDF.', 'error');
        } finally {
            attachBtn.disabled = false;
            attachBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="12" y1="5" x2="12" y2="19"></line>
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
                Attach PDF File`;
        }
    });

    // PDF Grid actions
    pdfGrid.addEventListener('click', async (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        const id = target.dataset.id;
        const pdfItem = pdfItems.find(item => item.id === id);
        if (!pdfItem) return;

        if (target.classList.contains('preview-btn')) openPreviewModal(pdfItem);
        else if (target.classList.contains('download-btn')) downloadPdf(pdfItem);
        else if (target.classList.contains('rename-btn')) {
            if (currentUser?.role === 'admin') openRenameModal(pdfItem);
            else showToast('Admin only.', 'error');
        } else if (target.classList.contains('delete-btn')) {
            if (currentUser?.role === 'admin') confirmAndDeletePdf(pdfItem);
            else showToast('Admin only.', 'error');
        }
    });

    searchInput.addEventListener('input', () => renderPdfGrid());

    modalCloseBtn.addEventListener('click', closePreviewModal);
    previewModal.addEventListener('click', (e) => { if (e.target === previewModal) closePreviewModal(); });

    renameCloseBtn.addEventListener('click', closeRenameModal);
    renameCancelBtn.addEventListener('click', closeRenameModal);

    // Rename form — sends to server API
    renameForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!currentUser || currentUser.role !== 'admin') { showToast('Admin only.', 'error'); return; }
        if (!renamingId) return;
        const pdfItem = pdfItems.find(item => item.id === renamingId);
        if (pdfItem) {
            const newName = renameInput.value.trim() || pdfItem.originalFileName;
            try {
                await renamePdfOnServer(pdfItem.id, newName);
                pdfItem.customName = newName;
                renderPdfGrid(); closeRenameModal();
                showToast('Name updated!');
            } catch (err) {
                showToast('Rename failed.', 'error');
            }
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { closePreviewModal(); closeRenameModal(); }
    });
}

// ============================================================
// 6. HELPER FUNCTIONS
// ============================================================
function handleSelectedFile(file) {
    if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
        showToast('Please select a valid PDF file.', 'error'); return;
    }
    currentSelectedFile = file;
    selectedFileNameEl.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
    attachBtn.disabled = false;
    if (!customNameInput.value.trim()) customNameInput.value = file.name.replace(/\.pdf$/i, '');
}

function resetUploadForm() {
    currentSelectedFile = null; fileInput.value = ''; customNameInput.value = '';
    selectedFileNameEl.textContent = ''; attachBtn.disabled = true;
}

// Preview — uses server URL (cookie sent automatically for auth)
function openPreviewModal(pdfItem) {
    const fileUrl = `/api/pdfs/${pdfItem.id}/file`;
    pdfViewer.src = fileUrl;
    modalPdfTitle.textContent = pdfItem.customName;
    const fn = pdfItem.customName.endsWith('.pdf') ? pdfItem.customName : `${pdfItem.customName}.pdf`;
    modalDownloadBtn.href = `${fileUrl}?download=1`;
    modalDownloadBtn.download = fn;
    previewModal.classList.add('active');
}

function closePreviewModal() {
    previewModal.classList.remove('active');
    pdfViewer.src = 'about:blank';
}

function openRenameModal(pdfItem) {
    renamingId = pdfItem.id; renameInput.value = pdfItem.customName;
    renameModal.classList.add('active'); renameInput.focus();
}

function closeRenameModal() { renamingId = null; renameModal.classList.remove('active'); }

// Download — uses server URL (cookie sent automatically)
function downloadPdf(pdfItem) {
    const fn = pdfItem.customName.endsWith('.pdf') ? pdfItem.customName : `${pdfItem.customName}.pdf`;
    const a = document.createElement('a');
    a.href = `/api/pdfs/${pdfItem.id}/file?download=1`;
    a.download = fn;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

async function confirmAndDeletePdf(pdfItem) {
    if (confirm(`Delete "${pdfItem.customName}"?`)) {
        try {
            await deletePdfFromServer(pdfItem.id);
            pdfItems = pdfItems.filter(i => i.id !== pdfItem.id);
            renderPdfGrid(); updateStats();
            showToast('Attachment deleted.');
        } catch (err) { showToast('Delete failed.', 'error'); }
    }
}

function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024, dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'error') toast.style.borderLeftColor = '#EF4444';
    toast.innerHTML = `<span>${type === 'error' ? '⚠️' : '✅'}</span> ${escapeHtml(message)}`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0'; toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}
