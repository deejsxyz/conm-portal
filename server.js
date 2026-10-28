require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const BCRYPT_COST = 12;

// Trust Render's reverse proxy for secure cookies and rate limiting
app.set('trust proxy', 1);
app.set('view engine', 'ejs');

// Helmet security headers (configured to allow Tailwind script & inline styles)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"]
        }
    }
}));

app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' || (process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost'))
        ? { rejectUnauthorized: false }
        : false
});

// Multer configured with 2MB limit and CSV filter
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'text/csv' || file.originalname.toLowerCase().endsWith('.csv')) {
            cb(null, true);
        } else {
            cb(new Error('Only .csv files are allowed.'));
        }
    }
});

// Production PostgreSQL Session Store
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'user_sessions',
        createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000 // 8 hours
    }
}));

// Rate limiter for login route (max 10 attempts per 15 minutes)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('login', {
            error: 'Too many login attempts. Please wait 15 minutes before trying again.',
            popupMessage: null
        });
    }
});

// Cryptographically secure random password generator using crypto.randomInt
function generateSecurePassword() {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const num = '0123456789';
    const special = '!@#$%^&*';
    const all = upper + lower + num + special;

    const chars = [
        upper[crypto.randomInt(0, upper.length)],
        lower[crypto.randomInt(0, lower.length)],
        num[crypto.randomInt(0, num.length)],
        special[crypto.randomInt(0, special.length)]
    ];

    for (let i = 0; i < 6; i++) {
        chars.push(all[crypto.randomInt(0, all.length)]);
    }

    // Unbiased Fisher-Yates shuffle
    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

// Server-side grade validation & auto-remark computation
const ALLOWED_GRADES = ['1.00', '1.25', '1.50', '1.75', '2.00', '2.25', '2.50', '2.75', '3.00', '4.00', '5.00', 'X', 'INC', 'W', 'NG', ''];

function computeServerRemark(grade) {
    const passed = ['1.00', '1.25', '1.50', '1.75', '2.00', '2.25', '2.50', '2.75', '3.00'];
    if (passed.includes(grade)) return 'PASSED';
    if (grade === '4.00') return 'CONDITIONAL';
    if (grade === '5.00') return 'FAILED';
    if (grade === 'X') return 'DROPPED';
    if (grade === 'INC') return 'INCOMPLETE';
    if (grade === 'W') return 'ABSENT FROM EXAMINATION';
    if (grade === 'NG') return 'NO GRADE';
    return '';
}

function normalizeGrade(rawGrade) {
    let g = rawGrade ? String(rawGrade).trim().toUpperCase() : '';
    if (/^[1-5]$/.test(g)) g = `${g}.00`;
    return ALLOWED_GRADES.includes(g) ? g : '';
}

function formatFullName(first, middle, last, fallback) {
    const parts = [first, middle, last].map(p => (p || '').trim()).filter(Boolean);
    return parts.length > 0 ? parts.join(' ') : fallback;
}

function formatFormalFacultyName(fac) {
    if (!fac) return '';
    return [fac.last_name, [fac.first_name, fac.middle_name].filter(Boolean).join(' ')].filter(Boolean).join(', ');
}

// Escape CSV cells to prevent Excel Formula Injection (=, +, -, @) and quote issues
function sanitizeCsvCell(val) {
    let str = String(val ?? '').replace(/"/g, '""');
    if (/^[=+\-@\t\r]/.test(str)) {
        str = "'" + str;
    }
    return `"${str}"`;
}

// Flash message helper (prevents URL spoofing of success/error banners)
function setFlash(req, type, text) {
    req.session.flash = { type, text };
}

// Global Middleware: CSRF token generation & Flash message extraction
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken;
    res.locals.generateSecurePassword = generateSecurePassword;

    const flash = req.session.flash;
    delete req.session.flash;
    res.locals.message = flash && flash.type === 'msg' ? flash.text : null;
    res.locals.error = flash && flash.type === 'err' ? flash.text : null;
    next();
});

function verifyCsrf(req, res, next) {
    const token = (req.body && req.body._csrf) || req.query._csrf || req.headers['x-csrf-token'];
    if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
        return res.status(403).send('Invalid or expired security token (CSRF). Please go back, refresh the page, and try again.');
    }
    next();
}

// Apply CSRF verification to all standard POST routes (multipart routes verify after multer parses)
app.use((req, res, next) => {
    if (req.method === 'POST' && !req.is('multipart/form-data')) {
        return verifyCsrf(req, res, next);
    }
    next();
});

// Authentication & Forced Password Change Enforcement
function isAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/');
    }
    if (req.session.user.mustChangePassword && req.path !== '/change-password' && req.path !== '/logout') {
        return res.redirect('/change-password');
    }
    next();
}

async function seedDatabase() {
    try {
        // 1. Create Base Tables (Fresh DB safe)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(100) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL,
                first_name VARCHAR(100),
                middle_name VARCHAR(100),
                last_name VARCHAR(100),
                must_change_password BOOLEAN DEFAULT TRUE,
                is_archived BOOLEAN DEFAULT FALSE
            );
        `);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;`);
        await pool.query(`ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'faculty', 'student', 'registrar'));`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS students (
                student_id VARCHAR(100) PRIMARY KEY,
                student_number VARCHAR(100),
                first_name VARCHAR(100) NOT NULL,
                middle_name VARCHAR(100),
                last_name VARCHAR(100) NOT NULL,
                program VARCHAR(150) DEFAULT 'Bachelor of Science in Nursing (BSN)',
                year_level INT DEFAULT 1,
                section VARCHAR(10) DEFAULT 'A',
                is_archived BOOLEAN DEFAULT FALSE
            );
        `);
        await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS section VARCHAR(10) DEFAULT 'A';`);
        await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE;`);
        await pool.query(`UPDATE students SET section = 'A' WHERE section IS NULL OR TRIM(section) = '';`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS courses (
                course_code VARCHAR(50) PRIMARY KEY,
                descriptive_title VARCHAR(255) NOT NULL,
                lec_units INT DEFAULT 0,
                rle_units INT DEFAULT 0,
                total_units INT DEFAULT 0,
                term_id INT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            );
        `);
        await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS faculty_courses (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                course_code VARCHAR(50) NOT NULL,
                UNIQUE (username, course_code)
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS grades (
                id SERIAL PRIMARY KEY,
                student_id VARCHAR(100) NOT NULL,
                student_number VARCHAR(100),
                course_code VARCHAR(50) NOT NULL,
                final_grade VARCHAR(50) DEFAULT '',
                instructor VARCHAR(150) DEFAULT '',
                instructor_username VARCHAR(100) DEFAULT '',
                remarks VARCHAR(50) DEFAULT '',
                enrolled_term VARCHAR(10) NOT NULL,
                academic_year VARCHAR(20) DEFAULT '2026-2027'
            );
        `);

        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS course_code VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS final_grade VARCHAR(50) DEFAULT '';`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS instructor VARCHAR(150) DEFAULT '';`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS instructor_username VARCHAR(100) DEFAULT '';`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS remarks VARCHAR(50) DEFAULT '';`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS student_id VARCHAR(100);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS enrolled_term VARCHAR(10);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS academic_year VARCHAR(20) DEFAULT '2026-2027';`);

        // Migrate uniqueness on grades to (student_id, course_code, academic_year, enrolled_term)
        await pool.query(`ALTER TABLE grades DROP CONSTRAINT IF EXISTS grades_student_id_course_code_key;`);
        await pool.query(`
            DELETE FROM grades a USING grades b
            WHERE a.id < b.id
              AND a.student_id = b.student_id
              AND a.course_code = b.course_code
              AND COALESCE(a.academic_year, '') = COALESCE(b.academic_year, '')
              AND COALESCE(a.enrolled_term, '') = COALESCE(b.enrolled_term, '');
        `);
        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS grades_stu_course_ay_term_idx 
            ON grades (student_id, course_code, academic_year, enrolled_term);
        `);

        // Audit Log Table for RA 10173 compliance & grade tracking
        await pool.query(`
            CREATE TABLE IF NOT EXISTS grade_audit_logs (
                id SERIAL PRIMARY KEY,
                changed_by VARCHAR(100) NOT NULL,
                changed_by_role VARCHAR(30) NOT NULL,
                student_id VARCHAR(100) NOT NULL,
                course_code VARCHAR(50) NOT NULL,
                academic_year VARCHAR(20),
                enrolled_term VARCHAR(10),
                old_grade VARCHAR(50),
                new_grade VARCHAR(50),
                changed_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);

        // Helpful performance indexes
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_students_year_sec ON students (year_level, section) WHERE is_archived = FALSE;`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_grades_student_term ON grades (student_id, enrolled_term, academic_year);`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                id INT PRIMARY KEY,
                current_ay VARCHAR(20),
                current_semester INT,
                faculty_portal_locked BOOLEAN DEFAULT FALSE
            );
        `);
        await pool.query(`ALTER TABLE settings ADD COLUMN IF NOT EXISTS faculty_portal_locked BOOLEAN DEFAULT FALSE;`);
        await pool.query(`
            INSERT INTO settings (id, current_ay, current_semester, faculty_portal_locked) 
            VALUES (1, '2026-2027', 1, FALSE) 
            ON CONFLICT (id) DO NOTHING;
        `);

        // Seed Admin & Registrar ONLY if missing, using ENV vars or random passwords, forcing password change
        const existingAdmin = await pool.query(`SELECT username FROM users WHERE username = 'admin'`);
        if (existingAdmin.rows.length === 0) {
            const initAdminPass = process.env.INITIAL_ADMIN_PASSWORD || generateSecurePassword();
            const adminHash = await bcrypt.hash(initAdminPass, BCRYPT_COST);
            await pool.query(`
                INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
                VALUES ('admin', $1, 'admin', 'System', 'Administrator', TRUE)
                ON CONFLICT (username) DO NOTHING;
            `, [adminHash]);
            if (!process.env.INITIAL_ADMIN_PASSWORD) {
                console.log(`[INITIAL SEED] Created 'admin' account. Temporary password: ${initAdminPass}`);
            }
        }

        const existingRegistrar = await pool.query(`SELECT username FROM users WHERE username = 'registrar'`);
        if (existingRegistrar.rows.length === 0) {
            const initRegPass = process.env.INITIAL_REGISTRAR_PASSWORD || generateSecurePassword();
            const regHash = await bcrypt.hash(initRegPass, BCRYPT_COST);
            await pool.query(`
                INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
                VALUES ('registrar', $1, 'registrar', 'CONM', 'Registrar', TRUE)
                ON CONFLICT (username) DO NOTHING;
            `, [regHash]);
            if (!process.env.INITIAL_REGISTRAR_PASSWORD) {
                console.log(`[INITIAL SEED] Created 'registrar' account. Temporary password: ${initRegPass}`);
            }
        }

        // EXACT 24 OFFICIAL CONM SUBJECTS CATALOG (Soft-deactivating old courses instead of deleting)
        const conmCourses = [
            ['CA 1', 'Course Audit 1', 3, 0, 3, 7],
            ['CA 2', 'Course Audit 2', 3, 0, 3, 8],
            ['GEC E3', 'Elective 3 - Nursing Personality Enhancement Program (NPEP)', 3, 0, 3, 6],
            ['NCM 100', 'Theoretical Foundation of Nursing', 3, 0, 3, 1],
            ['NCM 101', 'Health Assessment', 3, 2, 5, 2],
            ['NCM 102', 'Health Education', 3, 0, 3, 2],
            ['NCM 103', 'Fundamentals of Nursing Practice', 3, 2, 5, 2],
            ['NCM 104', 'Community Health Nursing 1', 3, 1, 4, 3],
            ['NCM 105', 'Nutrition and Diet Therapy', 3, 0, 3, 3],
            ['NCM 106', 'Pharmacology', 3, 0, 3, 3],
            ['NCM 107', 'Care of Mother, Child Adolescent (Well Clients)', 5, 4, 9, 3],
            ['NCM 108', 'Health Care Ethics (Bioethics)', 3, 0, 3, 3],
            ['NCM 110', 'Care of Mother, Child Adolescent (Acute and Chronic)', 6, 6, 12, 4],
            ['NCM 111', 'Nursing Research 1', 3, 0, 3, 5],
            ['NCM 112', 'Care of Clients with Problems in Oxygenation, Fluid & Electrolytes, Infectious, Inflammatory, & Immunologic Response, Cellular Aberrations; Acute and Chronic', 8, 6, 14, 5],
            ['NCM 113', 'Community Health Nursing 2 (Population Group and Community Guide Clients)', 2, 1, 3, 5],
            ['NCM 114', 'Care of Older Adult', 2, 1, 3, 5],
            ['NCM 115', 'Nursing Research 2', 3, 0, 3, 6],
            ['NCM 116', 'Care of Clients with Problems in Nutrition & Gastro-Intestinal, Metabolism and Endocrine Perception & Coordination (Acute & Chronic)', 5, 4, 9, 6],
            ['NCM 117', 'Care of Clients with Maladaptive Patterns of Behavior (Acute & Chronic)', 4, 4, 8, 6],
            ['NCM 118', 'Nursing Care of Clients with Life Threatening Conditions, Acutely III/Multi-organs Problems, High Acuity & Emergency Situation, Acute & Chronic', 5, 4, 9, 7],
            ['NCM 119', 'Nursing Leadership & Management', 4, 3, 7, 7],
            ['NCM 121', 'Disaster Nursing', 2, 1, 3, 8],
            ['NCM 122', 'Intensive Nursing Practicum (Hospital and Community Settings)', 0, 8, 8, 8]
        ];

        const validCodes = conmCourses.map(c => c[0]);
        await pool.query(`UPDATE courses SET is_active = FALSE WHERE course_code <> ALL($1::text[])`, [validCodes]);

        for (let c of conmCourses) {
            await pool.query(`
                INSERT INTO courses (course_code, descriptive_title, lec_units, rle_units, total_units, term_id, is_active) 
                VALUES ($1, $2, $3, $4, $5, $6, TRUE)
                ON CONFLICT (course_code) 
                DO UPDATE SET descriptive_title = $2, lec_units = $3, rle_units = $4, total_units = $5, term_id = $6, is_active = TRUE;
            `, c);
        }

        console.log("Database schema verified and 24 official CONM subjects active.");
    } catch (err) {
        console.error("Critical database seeding error:", err);
    }
}

// ==================== AUTH ROUTES ====================
app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/portal');
    const lockedPopup = req.query.locked === '1' 
        ? 'Encoding of Grades is Not Yet Officially Open. Please wait for the College Registrar to unlock the Faculty Portal.' 
        : null;
    res.render('login', { error: res.locals.error, popupMessage: lockedPopup });
});

app.post('/login', loginLimiter, async (req, res) => {
    const username = req.body.username ? req.body.username.trim() : '';
    const password = req.body.password || '';
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1 AND COALESCE(is_archived, FALSE) = FALSE', [username]);
        if (userQuery.rows.length === 0) {
            return res.render('login', { error: 'Invalid username or password.', popupMessage: null });
        }

        const user = userQuery.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.render('login', { error: 'Invalid username or password.', popupMessage: null });
        }

        if (user.role === 'faculty') {
            const settingsRes = await pool.query('SELECT faculty_portal_locked FROM settings WHERE id = 1');
            if (settingsRes.rows.length > 0 && settingsRes.rows[0].faculty_portal_locked) {
                return res.render('login', { 
                    error: null, 
                    popupMessage: 'Encoding of Grades is Not Yet Officially Open. Please wait for the College Registrar to unlock the Faculty Portal.' 
                });
            }
        }

        let fullName = formatFullName(user.first_name, user.middle_name, user.last_name, null);
        if (!fullName && user.role === 'student') {
            const stuRes = await pool.query('SELECT first_name, middle_name, last_name FROM students WHERE student_id = $1', [user.username]);
            if (stuRes.rows.length > 0) {
                const s = stuRes.rows[0];
                fullName = formatFullName(s.first_name, s.middle_name, s.last_name, user.username);
            }
        }
        if (!fullName) fullName = user.username;

        const sessionUser = { 
            username: user.username, 
            role: user.role, 
            fullName: fullName,
            mustChangePassword: user.must_change_password 
        };

        // Regenerate session ID on login to prevent session fixation
        req.session.regenerate((regenErr) => {
            if (regenErr) {
                console.error(regenErr);
                return res.render('login', { error: 'Session error occurred.', popupMessage: null });
            }
            req.session.user = sessionUser;
            req.session.csrfToken = crypto.randomBytes(32).toString('hex');

            if (user.must_change_password) {
                return res.redirect('/change-password');
            }
            if (user.role === 'admin') return res.redirect('/admin');
            if (user.role === 'registrar') return res.redirect('/registrar');
            if (user.role === 'faculty') return res.redirect('/faculty/edit-grades');
            return res.redirect('/portal');
        });
    } catch (err) {
        console.error('Login error:', err);
        res.render('login', { error: 'An unexpected error occurred. Please try again.', popupMessage: null });
    }
});

app.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change_password', { error: res.locals.error });
});

app.post('/change-password', isAuthenticated, async (req, res) => {
    const { new_password } = req.body;
    
    const isValid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(new_password || '');
    if (!isValid) {
        return res.render('change_password', { 
            error: 'Password must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters.' 
        });
    }

    try {
        const hashedNewPassword = await bcrypt.hash(new_password, BCRYPT_COST);
        await pool.query(`
            UPDATE users 
            SET password_hash = $1, must_change_password = FALSE 
            WHERE username = $2
        `, [hashedNewPassword, req.session.user.username]);

        req.session.user.mustChangePassword = false;

        if (req.session.user.role === 'admin') return res.redirect('/admin');
        if (req.session.user.role === 'registrar') return res.redirect('/registrar');
        if (req.session.user.role === 'faculty') return res.redirect('/faculty/edit-grades');
        return res.redirect('/portal');
    } catch (err) {
        console.error('Password change error:', err);
        res.render('change_password', { error: 'Could not update password. Please try again.' });
    }
});

app.post('/logout', isAuthenticated, (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ==================== ADMIN ROUTES ====================
app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.redirect('/portal');

    const selectedStaffUsername = req.query.staff_user ? req.query.staff_user.trim() : '';
    const searchStudentId = req.query.search_student_id ? req.query.search_student_id.trim() : '';

    try {
        const staffRes = await pool.query(`
            SELECT username, role, must_change_password, first_name, middle_name, last_name 
            FROM users 
            WHERE role IN ('faculty', 'registrar') AND COALESCE(is_archived, FALSE) = FALSE
            ORDER BY role DESC, last_name ASC, username ASC
        `);

        let selectedStaff = null;
        if (selectedStaffUsername) {
            selectedStaff = staffRes.rows.find(f => f.username === selectedStaffUsername) || null;
        }

        const countsRes = await pool.query(`
            SELECT year_level, COUNT(*) AS total 
            FROM students 
            WHERE COALESCE(is_archived, FALSE) = FALSE
            GROUP BY year_level
        `);
        const yearCounts = { 1: 0, 2: 0, 3: 0, 4: 0 };
        countsRes.rows.forEach(r => {
            yearCounts[r.year_level] = parseInt(r.total, 10);
        });

        let searchedStudents = [];
        if (searchStudentId) {
            const stuSearchRes = await pool.query(`
                SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.program, s.year_level, COALESCE(s.section, 'A') AS section,
                       s.is_archived, u.must_change_password
                FROM students s
                LEFT JOIN users u ON s.student_id = u.username
                WHERE s.student_id ILIKE $1
                ORDER BY s.is_archived ASC, s.student_id ASC
            `, [`%${searchStudentId}%`]);
            searchedStudents = stuSearchRes.rows;
        }

        res.render('admin', {
            currentUser: req.session.user,
            staffList: staffRes.rows,
            selectedStaff: selectedStaff,
            yearCounts: yearCounts,
            searchStudentId: searchStudentId,
            searchedStudents: searchedStudents
        });
    } catch (err) {
        console.error('Admin load error:', err);
        res.status(500).send('Unable to load administrator dashboard.');
    }
});

app.post('/admin/add-staff', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, role, first_name, middle_name, last_name, temp_password } = req.body;
    const cleanUser = username ? username.trim() : '';
    const staffRole = role === 'registrar' ? 'registrar' : 'faculty';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const pass = temp_password && temp_password.trim() ? temp_password.trim() : generateSecurePassword();

    if (!cleanUser || !fName || !lName) {
        setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
        return res.redirect('/admin');
    }

    try {
        const existing = await pool.query('SELECT username FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            setFlash(req, 'err', `The username '${cleanUser}' is already registered.`);
            return res.redirect('/admin');
        }

        const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name, is_archived) 
            VALUES ($1, $2, $3, TRUE, $4, $5, $6, FALSE)
        `, [cleanUser, hashedPassword, staffRole, fName, mName, lName]);

        setFlash(req, 'msg', `Staff account '${cleanUser}' created successfully.`);
        res.redirect(`/admin?staff_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        console.error('Add staff error:', err);
        setFlash(req, 'err', 'Database error while creating staff account.');
        res.redirect('/admin');
    }
});

app.post('/admin/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, section, temp_password } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const yr = Math.min(4, Math.max(1, parseInt(year_level, 10) || 1));
    const sec = ['A', 'B', 'C'].includes((section || '').trim().toUpperCase()) ? section.trim().toUpperCase() : 'A';
    const pass = temp_password && temp_password.trim() ? temp_password.trim() : generateSecurePassword();

    if (!cleanId || !fName || !lName) {
        setFlash(req, 'err', 'Student ID, First Name, and Last Name are required.');
        return res.redirect('/admin');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const existing = await client.query('SELECT username FROM users WHERE username = $1', [cleanId]);
        if (existing.rows.length > 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', `Student ID '${cleanId}' is already registered.`);
            return res.redirect('/admin');
        }

        const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);

        await client.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name, is_archived) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5, FALSE)
        `, [cleanId, hashedPassword, fName, mName, lName]);

        await client.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, is_archived) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, FALSE)
        `, [cleanId, fName, mName, lName, yr, sec]);

        await client.query('COMMIT');
        setFlash(req, 'msg', `Student account '${cleanId}' (BSN${yr} - ${sec}) created successfully.`);
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Admin add student error:', err);
        setFlash(req, 'err', 'Error creating student account.');
        res.redirect('/admin');
    } finally {
        client.release();
    }
});

// Soft-archive or restore user (reads role from DB instead of trusting form input, preserves academic grades)
app.post('/admin/delete-user', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const username = req.body.username ? req.body.username.trim() : '';
    const action = req.body.action === 'restore' ? 'restore' : 'archive';
    if (!username || username === 'admin') {
        setFlash(req, 'err', 'Cannot archive the primary system administrator.');
        return res.redirect('/admin');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT role FROM users WHERE username = $1', [username]);
        if (userRes.rows.length === 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'User account not found.');
            return res.redirect('/admin');
        }

        const dbRole = userRes.rows[0].role;
        const archiveFlag = action === 'archive';

        await client.query('UPDATE users SET is_archived = $1 WHERE username = $2', [archiveFlag, username]);

        if (dbRole === 'student') {
            await client.query('UPDATE students SET is_archived = $1 WHERE student_id = $2', [archiveFlag, username]);
        } else if (dbRole === 'faculty' && archiveFlag) {
            await client.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', `Account '${username}' has been ${archiveFlag ? 'archived (grades preserved)' : 'restored'}.`);
        res.redirect('/admin');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Archive user error:', err);
        setFlash(req, 'err', 'Failed to update account archive status.');
        res.redirect('/admin');
    } finally {
        client.release();
    }
});

app.post('/admin/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { original_username, username, first_name, middle_name, last_name, temp_password } = req.body;
    const origUser = original_username ? original_username.trim() : '';
    const cleanUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    if (!origUser || !cleanUser || !fName || !lName) {
        setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
        return res.redirect('/admin');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const updateRes = await client.query(`
            UPDATE users 
            SET username = $1, first_name = $2, middle_name = $3, last_name = $4
            WHERE username = $5 AND role IN ('faculty', 'registrar')
        `, [cleanUser, fName, mName, lName, origUser]);

        if (updateRes.rowCount === 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'Staff member not found.');
            return res.redirect('/admin');
        }

        const newFormalName = formatFormalFacultyName({ first_name: fName, middle_name: mName, last_name: lName });
        await client.query(`UPDATE faculty_courses SET username = $1 WHERE username = $2`, [cleanUser, origUser]);
        await client.query(`UPDATE grades SET instructor_username = $1, instructor = $2 WHERE instructor_username = $3`, [cleanUser, newFormalName, origUser]);

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE 
                WHERE username = $2
            `, [hashedPassword, cleanUser]);
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Staff profile updated successfully.');
        res.redirect(`/admin?staff_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Admin edit staff error:', err);
        setFlash(req, 'err', 'Failed to update staff profile.');
        res.redirect(`/admin?staff_user=${encodeURIComponent(origUser)}`);
    } finally {
        client.release();
    }
});

app.post('/admin/edit-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, section, temp_password } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const yr = Math.min(4, Math.max(1, parseInt(year_level, 10) || 1));
    const sec = ['A', 'B', 'C'].includes((section || '').trim().toUpperCase()) ? section.trim().toUpperCase() : 'A';
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`
            UPDATE students 
            SET first_name = $1, middle_name = $2, last_name = $3, year_level = $4, section = $5
            WHERE student_id = $6
        `, [first_name.trim(), (middle_name || '').trim(), last_name.trim(), yr, sec, cleanId]);

        await client.query(`
            UPDATE users 
            SET first_name = $1, middle_name = $2, last_name = $3
            WHERE username = $4 AND role = 'student'
        `, [first_name.trim(), (middle_name || '').trim(), last_name.trim(), cleanId]);

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE 
                WHERE username = $2 AND role = 'student'
            `, [hashedPassword, cleanId]);
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Student profile updated successfully.');
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Admin edit student error:', err);
        setFlash(req, 'err', 'Failed to update student profile.');
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}`);
    } finally {
        client.release();
    }
});

// ==================== REGISTRAR PORTAL ROUTES ====================
app.get('/registrar', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }

    const targetStudentId = req.query.student_id ? req.query.student_id.trim() : '';
    const selectedFacultyUser = req.query.faculty_user ? req.query.faculty_user.trim() : '';

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        let student = null;
        let grades = [];
        let selectedTerm = '1';
        let selectedAy = req.query.view_ay ? req.query.view_ay.trim() : systemSettings.current_ay;

        const allCoursesRes = await pool.query('SELECT * FROM courses WHERE COALESCE(is_active, TRUE) = TRUE ORDER BY term_id, course_code');
        const allCoursesRaw = allCoursesRes.rows;

        const facultyListRes = await pool.query(`
            SELECT username, first_name, middle_name, last_name 
            FROM users 
            WHERE role = 'faculty' AND COALESCE(is_archived, FALSE) = FALSE
            ORDER BY last_name ASC, username ASC
        `);
        const facultyList = facultyListRes.rows;

        let selectedFaculty = null;
        let facultyAssignedCourses = [];

        if (selectedFacultyUser) {
            selectedFaculty = facultyList.find(f => f.username === selectedFacultyUser) || null;
            if (selectedFaculty) {
                const facCoursesRes = await pool.query(`
                    SELECT course_code FROM faculty_courses WHERE username = $1
                `, [selectedFacultyUser]);
                facultyAssignedCourses = facCoursesRes.rows.map(fc => fc.course_code);
            }
        }

        if (targetStudentId) {
            const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1 AND COALESCE(is_archived, FALSE) = FALSE', [targetStudentId]);
            student = studentRes.rows[0] || null;

            if (student) {
                const defaultTerm = ((parseInt(student.year_level) - 1) * 2 + parseInt(systemSettings.current_semester)).toString();
                selectedTerm = req.query.view_term && /^[1-8]$/.test(req.query.view_term) ? req.query.view_term : defaultTerm;

                const gradesRes = await pool.query(`
                    SELECT g.id, g.course_code, g.final_grade, g.instructor, g.instructor_username, g.remarks, g.enrolled_term, g.academic_year,
                           c.descriptive_title, c.lec_units, c.rle_units, c.total_units
                    FROM grades g
                    JOIN courses c ON g.course_code = c.course_code
                    WHERE g.student_id = $1 AND g.enrolled_term = $2 AND g.academic_year = $3
                    ORDER BY g.course_code ASC
                `, [targetStudentId, selectedTerm, selectedAy]);
                grades = gradesRes.rows;
            }
        }

        res.render('registrar', {
            currentUser: req.session.user,
            systemSettings: systemSettings,
            selectedStudent: student,
            grades: grades,
            availableCourses: allCoursesRaw,
            allCoursesRaw: allCoursesRaw,
            currentTerm: selectedTerm,
            currentViewAy: selectedAy,
            facultyList: facultyList,
            selectedFaculty: selectedFaculty,
            facultyAssignedCourses: facultyAssignedCourses,
            hasBatchCredentials: Array.isArray(req.session.lastBatchCredentials) && req.session.lastBatchCredentials.length > 0
        });
    } catch (err) {
        console.error('Registrar load error:', err);
        res.status(500).send('Error loading registrar dashboard.');
    }
});

app.post('/registrar/update-settings', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    const { current_ay, current_semester } = req.body;
    const sem = parseInt(current_semester, 10) === 2 ? 2 : 1;
    const ay = /^\d{4}-\d{4}$/.test(current_ay || '') ? current_ay : '2026-2027';
    try {
        await pool.query('UPDATE settings SET current_ay = $1, current_semester = $2 WHERE id = 1', [ay, sem]);
        setFlash(req, 'msg', 'Active Academic Year and Semester updated system-wide.');
        res.redirect('/registrar');
    } catch (err) {
        console.error('Update settings error:', err);
        setFlash(req, 'err', 'Failed to update system settings.');
        res.redirect('/registrar');
    }
});

app.post('/registrar/toggle-faculty-lock', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    try {
        const currentRes = await pool.query('SELECT faculty_portal_locked FROM settings WHERE id = 1');
        const currentState = currentRes.rows[0] ? currentRes.rows[0].faculty_portal_locked : false;
        const newState = !currentState;

        await pool.query('UPDATE settings SET faculty_portal_locked = $1 WHERE id = 1', [newState]);
        const statusMsg = newState 
            ? '🔒 Faculty Portal is now LOCKED. Instructors cannot log in or encode grades.' 
            : '🔓 Faculty Portal is now UNLOCKED. Instructors may now log in and encode grades.';
        setFlash(req, 'msg', statusMsg);
        res.redirect('/registrar');
    } catch (err) {
        console.error('Toggle lock error:', err);
        setFlash(req, 'err', 'Failed to toggle Faculty Portal lock.');
        res.redirect('/registrar');
    }
});

// Hardened, Transactional Batch Upload Route
app.post('/registrar/batch-upload', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    upload.single('file')(req, res, (uploadErr) => {
        if (uploadErr) {
            setFlash(req, 'err', uploadErr.message || 'Invalid file upload.');
            return res.redirect('/registrar');
        }

        // Verify CSRF token after multer parses multipart body/query
        const token = (req.body && req.body._csrf) || req.query._csrf;
        if (!token || token !== req.session.csrfToken) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            return res.status(403).send('Invalid security token (CSRF).');
        }

        if (!req.file) {
            setFlash(req, 'err', 'Please select a valid .csv file before uploading.');
            return res.redirect('/registrar');
        }

        const rows = [];
        const stream = fs.createReadStream(req.file.path).pipe(csv());

        stream.on('data', (row) => rows.push(row));
        stream.on('error', (streamErr) => {
            console.error('CSV stream error:', streamErr);
            if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            setFlash(req, 'err', 'Could not read CSV file.');
            return res.redirect('/registrar');
        });

        stream.on('end', async () => {
            if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

            if (rows.length === 0) {
                setFlash(req, 'err', 'The uploaded CSV file is empty.');
                return res.redirect('/registrar');
            }
            if (rows.length > 300) {
                setFlash(req, 'err', 'Batch limit is 300 students per CSV upload to prevent server timeouts.');
                return res.redirect('/registrar');
            }

            const client = await pool.connect();
            const generatedCredentials = [];
            let enrolledCount = 0;

            try {
                // Pre-load faculty map to resolve instructor usernames accurately
                const facRes = await client.query(`SELECT username, first_name, middle_name, last_name FROM users WHERE role = 'faculty'`);
                const facultyMap = new Map();
                facRes.rows.forEach(f => {
                    facultyMap.set(f.username.toLowerCase(), { username: f.username, formalName: formatFormalFacultyName(f) });
                    facultyMap.set(formatFormalFacultyName(f).toLowerCase(), { username: f.username, formalName: formatFormalFacultyName(f) });
                });

                await client.query('BEGIN');

                for (let idx = 0; idx < rows.length; idx++) {
                    const row = rows[idx];
                    const cleanId = row.student_id ? String(row.student_id).trim() : '';
                    const fName = row.first_name ? String(row.first_name).trim() : '';
                    const mName = row.middle_name ? String(row.middle_name).trim() : '';
                    const lName = row.last_name ? String(row.last_name).trim() : '';

                    if (!cleanId || !fName || !lName) {
                        throw new Error(`Row ${idx + 2} is missing student_id, first_name, or last_name.`);
                    }

                    const rawYear = String(row.year_level || '1').replace(/[^0-9]/g, '');
                    const cleanYear = parseInt(rawYear, 10);
                    if (![1, 2, 3, 4].includes(cleanYear)) {
                        throw new Error(`Row ${idx + 2} (${cleanId}) has an invalid year_level.`);
                    }

                    const rawSec = row.section ? String(row.section).trim().toUpperCase() : 'A';
                    const cleanSection = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';

                    // Check if user already exists before hashing to save CPU and avoid bogus exported passwords
                    const userExists = await client.query('SELECT username FROM users WHERE username = $1', [cleanId]);
                    if (userExists.rows.length === 0) {
                        const tempPassword = generateSecurePassword();
                        const hashedPassword = await bcrypt.hash(tempPassword, 10);

                        const insertUser = await client.query(
                            `INSERT INTO users (username, password_hash, role, first_name, middle_name, last_name, must_change_password, is_archived) 
                             VALUES ($1, $2, 'student', $3, $4, $5, TRUE, FALSE) 
                             ON CONFLICT (username) DO NOTHING
                             RETURNING username`,
                            [cleanId, hashedPassword, fName, mName, lName]
                        );

                        if (insertUser.rowCount > 0) {
                            generatedCredentials.push({
                                student_id: cleanId,
                                name: `${lName}, ${fName} ${mName}`.trim(),
                                year_section: `BSN${cleanYear} - ${cleanSection}`,
                                temp_password: tempPassword
                            });
                        }
                    }

                    await client.query(
                        `INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, is_archived) 
                         VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, FALSE)
                         ON CONFLICT (student_id) DO UPDATE SET first_name = $2, middle_name = $3, last_name = $4, year_level = $5, section = $6, is_archived = FALSE`,
                        [cleanId, fName, mName, lName, cleanYear, cleanSection]
                    );

                    if (row.semester && row.subjects && row.academic_year) {
                        const cleanSem = parseInt(String(row.semester).trim(), 10);
                        if (![1, 2].includes(cleanSem)) {
                            throw new Error(`Row ${idx + 2} (${cleanId}) has an invalid semester (must be 1 or 2).`);
                        }
                        const cleanAy = String(row.academic_year).trim();
                        const termId = ((cleanYear - 1) * 2 + cleanSem).toString();
                        const courseCodes = String(row.subjects).split(',').map(s => s.trim()).filter(Boolean);

                        for (const code of courseCodes) {
                            const instructorKey = `instructor_${code.replace(/\s+/g, '_')}`;
                            const rawInst = String(row[instructorKey] || row.instructor || '').trim();
                            const matchedFac = facultyMap.get(rawInst.toLowerCase());
                            const instName = matchedFac ? matchedFac.formalName : rawInst;
                            const instUser = matchedFac ? matchedFac.username : '';

                            await client.query(
                                `INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year) 
                                 VALUES ($1, $2, '', $3, $4, '', $5, $6)
                                 ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
                                 DO UPDATE SET 
                                    instructor = COALESCE(NULLIF($3, ''), grades.instructor),
                                    instructor_username = COALESCE(NULLIF($4, ''), grades.instructor_username);`,
                                [cleanId, code, instName, instUser, termId, cleanAy]
                            );
                        }
                    }
                    enrolledCount++;
                }

                await client.query('COMMIT');
                req.session.lastBatchCredentials = generatedCredentials;
                setFlash(req, 'msg', `${enrolledCount} students processed (${generatedCredentials.length} new accounts generated).`);
                res.redirect('/registrar');
            } catch (err) {
                await client.query('ROLLBACK');
                console.error('Batch upload transaction rolled back:', err);
                setFlash(req, 'err', err.message || 'Batch upload failed. No changes were saved.');
                res.redirect('/registrar');
            } finally {
                client.release();
            }
        });
    });
});

// Safe CSV Export (clears plaintext passwords from session after download)
app.get('/registrar/export-batch-credentials', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    
    const credentials = req.session.lastBatchCredentials;
    if (!credentials || credentials.length === 0) {
        setFlash(req, 'err', 'No new student credentials available to download.');
        return res.redirect('/registrar');
    }

    // Clear from session immediately so plaintext passwords do not linger
    delete req.session.lastBatchCredentials;

    const csvHeader = 'Student ID,Student Name,Year & Section,Temporary Password\n';
    const csvRows = credentials.map(c => [
        sanitizeCsvCell(c.student_id),
        sanitizeCsvCell(c.name),
        sanitizeCsvCell(c.year_section),
        sanitizeCsvCell(c.temp_password)
    ].join(',')).join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="batch_temporary_passwords.csv"');
    res.status(200).send(csvHeader + csvRows);
});

app.post('/registrar/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, section, term, academic_year, course_codes, instructors, temp_password } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const yr = Math.min(4, Math.max(1, parseInt(year_level, 10) || 1));
    const sec = ['A', 'B', 'C'].includes((section || '').trim().toUpperCase()) ? section.trim().toUpperCase() : 'A';
    const pass = temp_password && temp_password.trim() ? temp_password.trim() : generateSecurePassword();

    if (!cleanId || !fName || !lName) {
        setFlash(req, 'err', 'Student ID, First Name, and Last Name are required.');
        return res.redirect('/registrar');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const existing = await client.query('SELECT username FROM users WHERE username = $1', [cleanId]);
        if (existing.rows.length > 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', `Student ID '${cleanId}' is already registered.`);
            return res.redirect('/registrar');
        }

        const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);

        await client.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name, is_archived) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5, FALSE)
        `, [cleanId, hashedPassword, fName, mName, lName]);

        await client.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, is_archived) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, FALSE)
        `, [cleanId, fName, mName, lName, yr, sec]);

        if (term && course_codes && academic_year) {
            const codes = Array.isArray(course_codes) ? course_codes : [course_codes];
            const instUsers = Array.isArray(instructors) ? instructors : (instructors ? [instructors] : []);

            for (let i = 0; i < codes.length; i++) {
                const code = codes[i];
                const facUser = instUsers[i] ? instUsers[i].trim() : '';
                let facFormalName = '';

                if (facUser) {
                    const facRes = await client.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
                    if (facRes.rows.length > 0) {
                        facFormalName = formatFormalFacultyName(facRes.rows[0]);
                    }
                }

                await client.query(`
                    INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year)
                    VALUES ($1, $2, '', $3, $4, '', $5, $6)
                    ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
                    DO UPDATE SET instructor = $3, instructor_username = $4;
                `, [cleanId, code, facFormalName, facUser, String(term), academic_year]);
            }
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', `Student '${cleanId}' (BSN${yr} - ${sec}) registered and enrolled.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Registrar add student error:', err);
        setFlash(req, 'err', 'Error registering new student.');
        res.redirect('/registrar');
    } finally {
        client.release();
    }
});

app.post('/registrar/update-student-year-section', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const yr = Math.min(4, Math.max(1, parseInt(req.body.year_level, 10) || 1));
    const sec = ['A', 'B', 'C'].includes((req.body.section || '').trim().toUpperCase()) ? req.body.section.trim().toUpperCase() : 'A';
    try {
        await pool.query(`
            UPDATE students SET year_level = $1, section = $2 WHERE student_id = $3
        `, [yr, sec, cleanId]);
        setFlash(req, 'msg', `Student class updated to BSN${yr} - ${sec}.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        console.error('Update class error:', err);
        setFlash(req, 'err', 'Failed to update Year Level and Section.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

app.post('/registrar/add-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, first_name, middle_name, last_name, temp_password, course_codes } = req.body;
    const cleanUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const pass = temp_password && temp_password.trim() ? temp_password.trim() : generateSecurePassword();

    if (!cleanUser || !fName || !lName) {
        setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
        return res.redirect('/registrar');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const existing = await client.query('SELECT username FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', `Username '${cleanUser}' is already registered.`);
            return res.redirect('/registrar');
        }

        const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);
        await client.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name, is_archived) 
            VALUES ($1, $2, 'faculty', TRUE, $3, $4, $5, FALSE)
        `, [cleanUser, hashedPassword, fName, mName, lName]);

        if (course_codes) {
            const codes = [...new Set(Array.isArray(course_codes) ? course_codes : [course_codes])];
            for (let code of codes) {
                if (code && code.trim() !== '') {
                    await client.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2) ON CONFLICT DO NOTHING;
                    `, [cleanUser, code.trim()]);
                }
            }
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Faculty account created and assigned subjects saved.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Add faculty error:', err);
        setFlash(req, 'err', 'Error creating faculty account.');
        res.redirect('/registrar');
    } finally {
        client.release();
    }
});

// Hardened: Enforces role = 'faculty' so a Registrar cannot overwrite 'admin'
app.post('/registrar/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { original_username, username, first_name, middle_name, last_name, temp_password, course_codes } = req.body;
    const origUser = original_username ? original_username.trim() : '';
    const cleanUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    if (!origUser || !cleanUser || !fName || !lName) {
        setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
        return res.redirect('/registrar');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Strictly verify target account has role = 'faculty'
        const checkTarget = await client.query(`SELECT role FROM users WHERE username = $1 AND role = 'faculty'`, [origUser]);
        if (checkTarget.rows.length === 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'Target faculty account not found or unauthorized.');
            return res.redirect('/registrar');
        }

        await client.query(`
            UPDATE users 
            SET username = $1, first_name = $2, middle_name = $3, last_name = $4
            WHERE username = $5 AND role = 'faculty'
        `, [cleanUser, fName, mName, lName, origUser]);

        const newFormalName = formatFormalFacultyName({ first_name: fName, middle_name: mName, last_name: lName });
        await client.query(`UPDATE grades SET instructor_username = $1, instructor = $2 WHERE instructor_username = $3`, [cleanUser, newFormalName, origUser]);

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users SET password_hash = $1, must_change_password = TRUE WHERE username = $2 AND role = 'faculty'
            `, [hashedPassword, cleanUser]);
        }

        await client.query(`DELETE FROM faculty_courses WHERE username = $1 OR username = $2`, [origUser, cleanUser]);
        if (course_codes) {
            const codes = [...new Set(Array.isArray(course_codes) ? course_codes : [course_codes])];
            for (let code of codes) {
                if (code && code.trim() !== '') {
                    await client.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2) ON CONFLICT DO NOTHING;
                    `, [cleanUser, code.trim()]);
                }
            }
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Faculty profile and assigned subjects updated.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Edit faculty error:', err);
        setFlash(req, 'err', 'Failed to update faculty profile.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(origUser)}`);
    } finally {
        client.release();
    }
});

// Hardened: Enforces role = 'faculty' and soft-archives
app.post('/registrar/delete-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const username = req.body.username ? req.body.username.trim() : '';
    try {
        const delRes = await pool.query(`UPDATE users SET is_archived = TRUE WHERE username = $1 AND role = 'faculty'`, [username]);
        if (delRes.rowCount > 0) {
            await pool.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
            setFlash(req, 'msg', 'Faculty account archived.');
        } else {
            setFlash(req, 'err', 'Faculty account not found or unauthorized.');
        }
        res.redirect('/registrar');
    } catch (err) {
        console.error('Delete faculty error:', err);
        setFlash(req, 'err', 'Failed to archive faculty account.');
        res.redirect('/registrar');
    }
});

app.post('/registrar/reset-student-password', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const newPass = req.body.new_password ? req.body.new_password.trim() : '';
    if (!cleanId || !newPass) {
        setFlash(req, 'err', 'Invalid password reset request.');
        return res.redirect('/registrar');
    }

    try {
        const hashedPassword = await bcrypt.hash(newPass, BCRYPT_COST);
        await pool.query(`
            UPDATE users SET password_hash = $1, must_change_password = TRUE 
            WHERE username = $2 AND role = 'student'
        `, [hashedPassword, cleanId]);

        setFlash(req, 'msg', `Password successfully reset for Student ID ${cleanId}.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        console.error('Reset student password error:', err);
        setFlash(req, 'err', 'Failed to reset student password.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

app.post('/registrar/add-single-course', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const courseCode = req.body.course_code ? req.body.course_code.trim() : '';
    const term = req.body.term ? String(req.body.term).trim() : '1';
    const targetAy = req.body.academic_year ? req.body.academic_year.trim() : '';
    const facUser = req.body.instructor ? req.body.instructor.trim() : '';

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const currentAy = targetAy || settingsRes.rows[0].current_ay;

        let facFormalName = '';
        if (facUser) {
            const facRes = await pool.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
            if (facRes.rows.length > 0) {
                facFormalName = formatFormalFacultyName(facRes.rows[0]);
            }
        }

        await pool.query(`
            INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year)
            VALUES ($1, $2, '', $3, $4, '', $5, $6)
            ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
            DO UPDATE SET instructor = $3, instructor_username = $4;
        `, [cleanId, courseCode, facFormalName, facUser, term, currentAy]);

        setFlash(req, 'msg', `Subject ${courseCode} enrolled for A.Y. ${currentAy}.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(term)}&view_ay=${encodeURIComponent(currentAy)}`);
    } catch (err) {
        console.error('Add single course error:', err);
        setFlash(req, 'err', 'Could not enroll subject.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

app.post('/registrar/update-grades-batch', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const enrolledTerm = req.body.enrolled_term ? String(req.body.enrolled_term).trim() : '';
    const academicYear = req.body.academic_year ? String(req.body.academic_year).trim() : '';
    const { course_codes, final_grades, instructors } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const codes = Array.isArray(course_codes) ? course_codes : (course_codes ? [course_codes] : []);
        const grades = Array.isArray(final_grades) ? final_grades : (final_grades !== undefined ? [final_grades] : []);
        const insts = Array.isArray(instructors) ? instructors : (instructors !== undefined ? [instructors] : []);

        for (let i = 0; i < codes.length; i++) {
            const code = codes[i];
            const cleanGrade = normalizeGrade(grades[i]);
            const computedRem = computeServerRemark(cleanGrade);
            const facUser = insts[i] ? insts[i].trim() : '';

            let facFormalName = '';
            if (facUser) {
                const facRes = await client.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
                if (facRes.rows.length > 0) {
                    facFormalName = formatFormalFacultyName(facRes.rows[0]);
                } else {
                    facFormalName = facUser; // fallback for historical free-text names
                }
            }

            if (code) {
                const existingRes = await client.query(`
                    SELECT final_grade FROM grades 
                    WHERE student_id = $1 AND course_code = $2 AND enrolled_term = $3 AND academic_year = $4
                `, [cleanId, code, enrolledTerm, academicYear]);

                const oldGrade = existingRes.rows[0] ? existingRes.rows[0].final_grade : '';

                await client.query(`
                    UPDATE grades 
                    SET final_grade = $1, instructor = $2, instructor_username = $3, remarks = $4 
                    WHERE student_id = $5 AND course_code = $6 AND enrolled_term = $7 AND academic_year = $8
                `, [cleanGrade, facFormalName, facUser, computedRem, cleanId, code, enrolledTerm, academicYear]);

                if (oldGrade !== cleanGrade) {
                    await client.query(`
                        INSERT INTO grade_audit_logs (changed_by, changed_by_role, student_id, course_code, academic_year, enrolled_term, old_grade, new_grade)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    `, [req.session.user.username, req.session.user.role, cleanId, code, academicYear, enrolledTerm, oldGrade, cleanGrade]);
                }
            }
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Grades and records updated successfully.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(enrolledTerm)}&view_ay=${encodeURIComponent(academicYear)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Registrar update grades error:', err);
        setFlash(req, 'err', 'Failed to update grades.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } finally {
        client.release();
    }
});

app.post('/registrar/delete-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const courseCode = req.body.course_code ? req.body.course_code.trim() : '';
    const term = req.body.term ? String(req.body.term).trim() : '';
    const ay = req.body.academic_year ? String(req.body.academic_year).trim() : '';
    try {
        await pool.query(`
            DELETE FROM grades 
            WHERE student_id = $1 AND course_code = $2 AND enrolled_term = $3 AND academic_year = $4
        `, [cleanId, courseCode, term, ay]);

        setFlash(req, 'msg', `Subject ${courseCode} removed from student record.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(term)}&view_ay=${encodeURIComponent(ay)}`);
    } catch (err) {
        console.error('Delete grade error:', err);
        setFlash(req, 'err', 'Could not remove subject.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

app.post('/registrar/unenroll-term', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = req.body.student_id ? req.body.student_id.trim() : '';
    const term = req.body.term ? String(req.body.term).trim() : '';
    const ay = req.body.academic_year ? String(req.body.academic_year).trim() : '';
    try {
        await pool.query(`
            DELETE FROM grades 
            WHERE student_id = $1 AND enrolled_term = $2 AND academic_year = $3
        `, [cleanId, term, ay]);

        setFlash(req, 'msg', 'Student successfully unenrolled from all subjects for this term.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(term)}&view_ay=${encodeURIComponent(ay)}`);
    } catch (err) {
        console.error('Unenroll term error:', err);
        setFlash(req, 'err', 'Failed to unenroll student from term.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

// ==================== FACULTY PORTAL ROUTES (HARDENED EXCEL CLASS ROSTER) ====================
async function getFacultyAssignedCourses(facultyUsername, facultyFullName, role) {
    if (role === 'admin') {
        const allC = await pool.query('SELECT course_code, descriptive_title, term_id FROM courses WHERE COALESCE(is_active, TRUE) = TRUE ORDER BY course_code');
        return allC.rows;
    }
    const facC = await pool.query(`
        SELECT DISTINCT c.course_code, c.descriptive_title, c.term_id
        FROM courses c
        LEFT JOIN faculty_courses fc ON fc.course_code = c.course_code AND fc.username = $1
        LEFT JOIN grades g ON g.course_code = c.course_code AND (g.instructor_username = $1 OR g.instructor = $2)
        WHERE (fc.username = $1 OR g.instructor_username = $1 OR g.instructor = $2)
          AND COALESCE(c.is_active, TRUE) = TRUE
        ORDER BY c.course_code
    `, [facultyUsername, facultyFullName]);
    return facC.rows;
}

app.get('/faculty/edit-grades', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        if (req.session.user.role === 'faculty' && systemSettings.faculty_portal_locked) {
            return req.session.destroy(() => {
                res.redirect('/?locked=1');
            });
        }

        const facultyUsername = req.session.user.username;
        const facUserRes = await pool.query('SELECT first_name, middle_name, last_name FROM users WHERE username = $1', [facultyUsername]);
        const facUser = facUserRes.rows[0] || {};
        const facultyFullName = formatFormalFacultyName(facUser);

        const rawCourseCode = req.query.course_code;
        const selectedCourse = Array.isArray(rawCourseCode) ? rawCourseCode[0].trim() : (rawCourseCode ? rawCourseCode.trim() : '');
        const selectedYearLevel = req.query.year_level ? req.query.year_level.trim() : '';
        const selectedSection = req.query.section ? req.query.section.trim().toUpperCase() : '';

        const assignedCourses = await getFacultyAssignedCourses(facultyUsername, facultyFullName, req.session.user.role);

        let enrolledStudents = [];
        let selectedCourseDetails = null;

        if (selectedCourse) {
            selectedCourseDetails = assignedCourses.find(c => c.course_code === selectedCourse) || null;
        }

        if (selectedCourseDetails && selectedYearLevel && selectedSection) {
            const validTerms = systemSettings.current_semester === 1 ? [1, 3, 5, 7] : [2, 4, 6, 8];

            let rosterQuery = `
                SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.year_level, COALESCE(s.section, 'A') AS section,
                       g.final_grade, g.instructor, g.remarks, g.enrolled_term, g.academic_year,
                       c.descriptive_title
                FROM students s
                JOIN grades g ON s.student_id = g.student_id
                JOIN courses c ON g.course_code = c.course_code
                WHERE g.course_code = $1
                  AND s.year_level = $2
                  AND UPPER(COALESCE(s.section, 'A')) = $3
                  AND g.academic_year = $4
                  AND CAST(g.enrolled_term AS INTEGER) = ANY($5)
                  AND COALESCE(s.is_archived, FALSE) = FALSE
            `;
            let rosterParams = [selectedCourse, parseInt(selectedYearLevel, 10), selectedSection, systemSettings.current_ay, validTerms];

            if (req.session.user.role !== 'admin') {
                rosterQuery += ` AND (g.instructor_username = $6 OR g.instructor = $7 OR COALESCE(TRIM(g.instructor), '') = '')`;
                rosterParams.push(facultyUsername, facultyFullName);
            }

            rosterQuery += ` ORDER BY s.last_name ASC, s.first_name ASC`;

            const rosterRes = await pool.query(rosterQuery, rosterParams);
            enrolledStudents = rosterRes.rows;
        }

        res.render('faculty_edit', {
            currentUser: req.session.user,
            facultyFullName: facultyFullName || req.session.user.fullName || req.session.user.username,
            systemSettings: systemSettings,
            assignedCourses: assignedCourses,
            selectedCourse: selectedCourse,
            selectedCourseDetails: selectedCourseDetails,
            selectedYearLevel: selectedYearLevel,
            selectedSection: selectedSection,
            enrolledStudents: enrolledStudents
        });
    } catch (err) {
        console.error('Faculty editor load error:', err);
        res.status(500).send('Error loading faculty grade sheet.');
    }
});

// Hardened Batch Save Class Grades: Re-verifies course assignment, roster membership, server-side AY, instructor, & remarks
app.post('/faculty/update-grades-sheet', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const client = await pool.connect();
    try {
        const settingsRes = await client.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        if (req.session.user.role === 'faculty' && systemSettings.faculty_portal_locked) {
            client.release();
            return req.session.destroy(() => {
                res.redirect('/?locked=1');
            });
        }

        const facultyUsername = req.session.user.username;
        const facUserRes = await client.query('SELECT first_name, middle_name, last_name FROM users WHERE username = $1', [facultyUsername]);
        const facUser = facUserRes.rows[0] || {};
        const facultyFullName = formatFormalFacultyName(facUser) || req.session.user.fullName || facultyUsername;

        const courseCode = req.body.course_code ? req.body.course_code.trim() : '';
        const yearLevel = parseInt(req.body.year_level, 10);
        const section = req.body.section ? req.body.section.trim().toUpperCase() : '';

        // 1. Re-verify course assignment on server
        const assignedCourses = await getFacultyAssignedCourses(facultyUsername, facultyFullName, req.session.user.role);
        const isAssigned = assignedCourses.some(c => c.course_code === courseCode);
        if (!isAssigned || ![1, 2, 3, 4].includes(yearLevel) || !['A', 'B', 'C'].includes(section)) {
            client.release();
            setFlash(req, 'err', 'Unauthorized course or invalid class roster selection.');
            return res.redirect('/faculty/edit-grades');
        }

        // 2. Fetch the legitimate server-side roster for the active AY & semester
        const validTerms = systemSettings.current_semester === 1 ? [1, 3, 5, 7] : [2, 4, 6, 8];
        let rosterQuery = `
            SELECT s.student_id, g.final_grade, g.enrolled_term
            FROM students s
            JOIN grades g ON s.student_id = g.student_id
            WHERE g.course_code = $1
              AND s.year_level = $2
              AND UPPER(COALESCE(s.section, 'A')) = $3
              AND g.academic_year = $4
              AND CAST(g.enrolled_term AS INTEGER) = ANY($5)
              AND COALESCE(s.is_archived, FALSE) = FALSE
        `;
        let rosterParams = [courseCode, yearLevel, section, systemSettings.current_ay, validTerms];

        if (req.session.user.role !== 'admin') {
            rosterQuery += ` AND (g.instructor_username = $6 OR g.instructor = $7 OR COALESCE(TRIM(g.instructor), '') = '')`;
            rosterParams.push(facultyUsername, facultyFullName);
        }

        const validRosterRes = await client.query(rosterQuery, rosterParams);
        const allowedRosterMap = new Map();
        validRosterRes.rows.forEach(r => allowedRosterMap.set(r.student_id, r));

        const { student_ids, final_grades } = req.body;
        const stuIds = Array.isArray(student_ids) ? student_ids : (student_ids ? [student_ids] : []);
        const grades = Array.isArray(final_grades) ? final_grades : (final_grades !== undefined ? [final_grades] : []);

        await client.query('BEGIN');
        let updatedCount = 0;

        for (let i = 0; i < stuIds.length; i++) {
            const sId = stuIds[i] ? String(stuIds[i]).trim() : '';
            const rosterEntry = allowedRosterMap.get(sId);
            if (!rosterEntry) continue; // Ignore any tampered student_id not on this roster

            const cleanGrade = normalizeGrade(grades[i]);
            const computedRemark = computeServerRemark(cleanGrade); // Always computed server-side

            await client.query(`
                UPDATE grades 
                SET final_grade = $1, 
                    remarks = $2,
                    instructor = CASE WHEN COALESCE(TRIM(instructor), '') = '' THEN $3 ELSE instructor END,
                    instructor_username = CASE WHEN COALESCE(TRIM(instructor_username), '') = '' THEN $4 ELSE instructor_username END
                WHERE student_id = $5 AND course_code = $6 AND academic_year = $7 AND enrolled_term = $8
            `, [cleanGrade, computedRemark, facultyFullName, facultyUsername, sId, courseCode, systemSettings.current_ay, rosterEntry.enrolled_term]);

            if ((rosterEntry.final_grade || '') !== cleanGrade) {
                await client.query(`
                    INSERT INTO grade_audit_logs (changed_by, changed_by_role, student_id, course_code, academic_year, enrolled_term, old_grade, new_grade)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                `, [facultyUsername, req.session.user.role, sId, courseCode, systemSettings.current_ay, rosterEntry.enrolled_term, rosterEntry.final_grade || '', cleanGrade]);
            }
            updatedCount++;
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', `Saved grades for ${updatedCount} student(s) in BSN${yearLevel} - ${section}.`);
        res.redirect(`/faculty/edit-grades?course_code=${encodeURIComponent(courseCode)}&year_level=${encodeURIComponent(yearLevel)}&section=${encodeURIComponent(section)}`);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Faculty batch grade update error:', err);
        setFlash(req, 'err', 'An error occurred while saving grades.');
        res.redirect('/faculty/edit-grades');
    } finally {
        client.release();
    }
});

// ==================== STUDENT PORTAL ROUTES ====================
app.get('/portal', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    
    if (user.role === 'admin') return res.redirect('/admin');
    if (user.role === 'registrar') return res.redirect('/registrar');
    if (user.role === 'faculty') return res.redirect('/faculty/edit-grades');

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [user.username]);
        // Fallback object if student profile row is missing so /portal never crashes
        const student = studentRes.rows[0] || {
            student_id: user.username,
            first_name: user.fullName || user.username,
            middle_name: '',
            last_name: '',
            program: 'Bachelor of Science in Nursing (BSN)',
            year_level: 1,
            section: 'A'
        };

        let selectedTerm = req.query.term;
        if (!selectedTerm || !/^[1-8]$/.test(selectedTerm)) {
            selectedTerm = ((parseInt(student.year_level || 1) - 1) * 2 + parseInt(systemSettings.current_semester)).toString();
        }

        const activeSystemTerm = ((parseInt(student.year_level || 1) - 1) * 2 + parseInt(systemSettings.current_semester)).toString();

        const activeCheckRes = await pool.query(`
            SELECT COUNT(*) AS total FROM grades WHERE student_id = $1 AND enrolled_term = $2 AND academic_year = $3
        `, [user.username, activeSystemTerm, systemSettings.current_ay]);
        
        const isOfficiallyEnrolled = parseInt(activeCheckRes.rows[0].total, 10) > 0;

        const gradesRes = await pool.query(`
            SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, g.enrolled_term, g.academic_year,
                   c.descriptive_title, c.lec_units, c.rle_units, c.total_units
            FROM grades g
            JOIN courses c ON g.course_code = c.course_code
            WHERE g.student_id = $1 AND g.enrolled_term = $2
            ORDER BY g.academic_year DESC, g.course_code ASC
        `, [user.username, selectedTerm]);

        res.render('portal', {
            currentUser: user,
            studentRecord: student,
            grades: gradesRes.rows,
            currentTerm: selectedTerm,
            systemSettings: systemSettings,
            isOfficiallyEnrolled: isOfficiallyEnrolled
        });
    } catch (err) {
        console.error('Student portal error:', err);
        res.status(500).send('Server Error');
    }
});

async function startServer() {
    try {
        await seedDatabase();
        
        const PORT = process.env.PORT || 10000;
        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    } catch (err) {
        console.error("Failed to start server:", err);
    }
}

startServer();