require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

// Fix PostgreSQL date-parsing off-by-one timezone shifting (parses as raw string YYYY-MM-DD)
require('pg').types.setTypeParser(1082, (val) => val);

const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

if (!process.env.SESSION_SECRET) {
    console.error('FATAL ERROR: SESSION_SECRET environment variable is missing.');
    process.exit(1);
}

// Flexible TLS fallback configuration for production environments
const sslConfig = process.env.NODE_ENV === 'production'
    ? (process.env.PG_CA_CERT
        ? { ca: process.env.PG_CA_CERT, rejectUnauthorized: true }
        : { rejectUnauthorized: process.env.PG_SSL_INSECURE === 'true' ? false : true })
    : false;

const app = express();
const BCRYPT_COST = 12;
const BCRYPT_BATCH_COST = 10;
const MAX_FAILED_LOGINS = 5;
const IDLE_TIMEOUT_MS = (parseInt(process.env.IDLE_TIMEOUT_MINUTES, 10) || 20) * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const LOCKOUT_MINUTES = 15;
const REGISTRAR_CONTACT = process.env.REGISTRAR_CONTACT ? ` (${process.env.REGISTRAR_CONTACT})` : '';
const GENERIC_LOGIN_ERROR = 'Invalid username or password.';

class UserError extends Error {}
function safeMsg(err, fallback) {
    if (err instanceof UserError) return err.message;
    if (err && err.code === '23505' && err.constraint === 'uq_grades_student_course_ay') {
        return 'This subject is already recorded for the student in this academic year (under another semester).';
    }
    return fallback;
}

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_COST);
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('query parser', 'simple');

app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`, "https://cdn.tailwindcss.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Static assets (logo). Mounted before the no-store middleware below so browsers can cache them.
app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));

// Automatic dark mode: add the dark-mode stylesheet to every rendered page.
// The stylesheet only takes effect when the user's device is set to dark mode (and never when printing).
// If you edit public/dark.css, change the version number (v=1) below so browsers download the new copy.
const DARK_CSS_LINK = '<link rel="stylesheet" href="/static/dark.css?v=1">';
app.use((req, res, next) => {
    const originalRender = res.render.bind(res);
    res.render = (view, options, callback) => {
        const done = typeof options === 'function' ? options : callback;
        const locals = typeof options === 'function' ? undefined : options;
        originalRender(view, locals, (err, html) => {
            if (err) {
                if (done) return done(err);
                return next(err);
            }
            const out = String(html).replace('</head>', '    ' + DARK_CSS_LINK + '\n</head>');
            if (done) return done(null, out);
            res.send(out);
        });
    };
    next();
});

app.use(express.urlencoded({ extended: false, parameterLimit: 5000, limit: '1mb' }));

app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});

// Secure Pool Configuration with fallback TLS support
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: sslConfig
});

pool.on('error', (err) => {
    console.error('Unexpected PG pool error on idle client:', err.message);
});

// Upgraded multer configuration
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

app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'user_sessions',
        createTableIfMissing: true,
        ttl: 8 * 60 * 60
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

const tooManyLogins = (req, res) => {
    res.status(429).render('login', {
        error: 'Too many failed login attempts from this connection. Please try again later.',
        popupMessage: null
    });
};

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    keyGenerator: (req) => `${req.ip}-${String((req.body && req.body.username) || 'anonymous').slice(0, 100)}`,
    standardHeaders: true,
    legacyHeaders: false,
    handler: tooManyLogins
});

const loginIpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    handler: tooManyLogins
});

const changePwLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `cp-${req.session && req.session.user ? req.session.user.username : req.ip}`,
    handler: (req, res) => {
        setFlash(req, 'err', 'Too many password change attempts. Please wait 15 minutes and try again.');
        res.redirect('/change-password');
    }
});

function generateSecurePassword() {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const num = '0123456789';
    const special = '!@#$%^&*';
    const all = upper + lower + num + special;

    const firstChar = crypto.randomInt(0, 2) === 0 
        ? upper[crypto.randomInt(0, upper.length)] 
        : lower[crypto.randomInt(0, lower.length)];

    const chars = [
        upper[crypto.randomInt(0, upper.length)],
        lower[crypto.randomInt(0, lower.length)],
        num[crypto.randomInt(0, num.length)],
        special[crypto.randomInt(0, special.length)]
    ];

    for (let i = 0; i < 5; i++) {
        chars.push(all[crypto.randomInt(0, all.length)]);
    }

    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return firstChar + chars.join('');
}

const ALLOWED_GRADES = ['1.00', '1.25', '1.50', '1.75', '2.00', '2.25', '2.50', '2.75', '3.00', '4.00', '5.00', 'X', 'INC', 'W', 'NG', ''];

function computeServerRemark(grade) {
    const passed = ['1.00', '1.25', '1.50', '1.75', '2.00', '2.25', '2.50', '2.75', '3.00'];
    if (passed.includes(grade)) return 'PASSED';
    if (grade === '4.00') return 'CONDITIONAL';
    if (grade === '5.00') return 'FAILED';
    if (grade === 'X') return 'DROPPED';
    if (grade === 'INC') return 'INCOMPLETE';
    if (grade === 'W') return 'WITHDRAWN';
    if (grade === 'NG') return 'NO GRADE';
    return '';
}

function normalizeGrade(rawGrade) {
    if (!rawGrade || String(rawGrade).trim() === '') return '';
    let cleaned = String(rawGrade).trim().toUpperCase();
    if (/^\d+(\.\d+)?$/.test(cleaned)) {
        let num = Number(cleaned);
        if (num >= 1 && num <= 5) {
            cleaned = num.toFixed(2);
        }
    }
    if (ALLOWED_GRADES.includes(cleaned)) return cleaned;
    throw new UserError(`Invalid grade value submitted: ${rawGrade}`);
}

function isValidAcademicYear(ay) {
    if (!/^\d{4}-\d{4}$/.test(ay)) return false;
    const [y1, y2] = ay.split('-').map(Number);
    return y2 === y1 + 1;
}

function formatFullName(first, middle, last, fallback) {
    const parts = [first, middle, last].map(p => (p || '').trim()).filter(Boolean);
    return parts.length > 0 ? parts.join(' ') : fallback;
}

function formatFormalFacultyName(fac) {
    if (!fac) return '';
    return [fac.last_name, [fac.first_name, fac.middle_name].filter(Boolean).join(' ')].filter(Boolean).join(', ');
}

function sanitizeCsvCell(val) {
    let str = String(val ?? '').replace(/"/g, '""');
    if (/^[=+\-@\t\r]/.test(str)) str = "'" + str;
    return `"${str}"`;
}

async function logSecurityEvent(username, event, performedBy, ip, details) {
    try {
        await pool.query(
            'INSERT INTO account_security_logs (username, event, performed_by, ip, details) VALUES ($1, $2, $3, $4, $5)',
            [username, event, performedBy, ip ? String(ip).slice(0, 64) : null, details ? String(details).slice(0, 250) : null]
        );
    } catch (err) {
        console.error('Security log write failed:', err.message);
    }
}

function setFlash(req, type, text) {
    req.session.flash = { type, text };
}

app.use((req, res, next) => {
    if (req.path === '/favicon.ico') return next();
    if (!req.session.csrfToken && req.method === 'GET') {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken || '';
    res.locals.generateSecurePassword = generateSecurePassword;

    const flash = req.session.flash;
    delete req.session.flash;
    res.locals.message = flash && flash.type === 'msg' ? flash.text : null;
    res.locals.error = flash && flash.type === 'err' ? flash.text : null;
    next();
});

function verifyCsrf(req, res, next) {
    const token = (req.body && req.body._csrf) || req.headers['x-csrf-token'];
    if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
        if (req.path === '/logout') return res.redirect('/');
        return res.status(403).send('Invalid or expired security token (CSRF). Please go back, refresh the page, and try again.');
    }
    next();
}

app.use((req, res, next) => {
    if (req.method === 'POST' && !req.is('multipart/form-data')) {
        return verifyCsrf(req, res, next);
    }
    next();
});

app.use((req, res, next) => {
    if (req.method === 'POST' && req.body && typeof req.body.temp_password === 'string') {
        const typed = req.body.temp_password.trim();
        if (typed !== '' && (typed.length < 8 || typed.length > 72)) {
            setFlash(req, 'err', 'The temporary password must be 8 to 72 characters long (or leave it blank to generate one). Nothing was saved.');
            return res.redirect(req.path.startsWith('/admin') ? '/admin' : '/registrar');
        }
    }
    next();
});

async function isAuthenticated(req, res, next) {
    if (!req.session.user) return res.redirect('/');

    const nowTs = Date.now();
    const startedAt = req.session.user.login_time || nowTs;
    const lastSeen = req.session.user.last_activity || startedAt;
    if (nowTs - lastSeen > IDLE_TIMEOUT_MS || nowTs - startedAt > ABSOLUTE_TIMEOUT_MS) {
        return req.session.destroy(() => res.redirect('/?msg=timeout'));
    }
    req.session.user.last_activity = nowTs;

    try {
        const checkRes = await pool.query('SELECT role, must_change_password, password_changed_at, COALESCE(is_archived, FALSE) AS is_archived FROM users WHERE username = $1', [req.session.user.username]);
        if (checkRes.rows.length === 0 || checkRes.rows[0].is_archived) {
            return req.session.destroy(() => res.redirect('/'));
        }
        const dbUser = checkRes.rows[0];
        
        const pwdChangedTime = new Date(dbUser.password_changed_at).getTime();
        const loginTime = req.session.user.login_time || 0;
        if (pwdChangedTime > loginTime) {
             return req.session.destroy(() => res.redirect('/?msg=session_expired'));
        }

        req.session.user.mustChangePassword = dbUser.must_change_password;
        req.session.user.role = dbUser.role;

        if (dbUser.must_change_password && req.path !== '/change-password' && req.path !== '/logout') {
            return res.redirect('/change-password');
        }
        next();
    } catch (err) {
        console.error('Auth guard error:', err);
        return res.status(503).send('Database connection error. Please try again later.');
    }
}

async function seedDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(100) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL,
                first_name VARCHAR(100),
                middle_name VARCHAR(100),
                last_name VARCHAR(100),
                must_change_password BOOLEAN DEFAULT TRUE,
                is_archived BOOLEAN DEFAULT FALSE,
                failed_login_attempts INT DEFAULT 0,
                is_locked BOOLEAN DEFAULT FALSE,
                locked_at TIMESTAMPTZ,
                last_failed_at TIMESTAMPTZ,
                password_changed_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ;`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ DEFAULT NOW();`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS account_security_logs (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                event VARCHAR(50) NOT NULL,
                performed_by VARCHAR(100),
                ip VARCHAR(64),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);

        await pool.query(`ALTER TABLE account_security_logs ADD COLUMN IF NOT EXISTS details VARCHAR(255);`);

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
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_students_year_sec ON students (year_level, section) WHERE is_archived = FALSE;`);
        await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS gender VARCHAR(10);`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS vaccine_types (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                doses_required INT NOT NULL DEFAULT 1,
                validity_months INT DEFAULT 12,
                min_days_between INT DEFAULT 30,
                restart_when_expired BOOLEAN DEFAULT FALSE
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS student_vaccinations (
                id SERIAL PRIMARY KEY,
                student_id VARCHAR(100) NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
                vaccine_id INT NOT NULL REFERENCES vaccine_types(id) ON DELETE CASCADE,
                dose_number INT NOT NULL,
                cycle_number INT DEFAULT 1,
                date_given DATE NOT NULL,
                administered_at VARCHAR(250),
                recorded_by VARCHAR(100) NOT NULL,
                notes TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);

        await pool.query(`ALTER TABLE student_vaccinations ADD COLUMN IF NOT EXISTS voided_at TIMESTAMPTZ;`);
        await pool.query(`ALTER TABLE student_vaccinations ADD COLUMN IF NOT EXISTS voided_by VARCHAR(100);`);

        try {
            await pool.query(`DROP INDEX IF EXISTS uq_student_vaccine_dose;`);
            await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_student_vaccine_dose_active ON student_vaccinations (student_id, vaccine_id, cycle_number, dose_number) WHERE voided_at IS NULL;`);
        } catch (idxErr) {
            console.warn('[SEED] Could not create unique vaccine-dose index:', idxErr.message);
        }

        await pool.query(`
            CREATE TABLE IF NOT EXISTS immunization_access_logs (
                id SERIAL PRIMARY KEY,
                student_id VARCHAR(100) NOT NULL,
                accessed_by VARCHAR(100) NOT NULL,
                action_type VARCHAR(30) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);

        // Seed precise vaccine rules according to official schedule:
        // Tetanus Toxoid: 5 doses, restart if expired (>30 days past due)
        // Hepatitis B: 3 doses + 1 booster, restart if expired (>30 days past due)
        // Flu vaccine: 4 annual doses, restart if expired (>30 days past due)
        const initialVaccines = [
            ['Tetanus Toxoid', 5, 12, 28, true],
            ['Hepatitis B', 4, 12, 28, true],
            ['Flu vaccine', 4, 12, 365, true]
        ];
        for (const v of initialVaccines) {
            await pool.query(`
                INSERT INTO vaccine_types (name, doses_required, validity_months, min_days_between, restart_when_expired)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (name) DO UPDATE SET 
                    doses_required = EXCLUDED.doses_required,
                    validity_months = EXCLUDED.validity_months,
                    min_days_between = EXCLUDED.min_days_between,
                    restart_when_expired = EXCLUDED.restart_when_expired;
            `, v);
        }

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

        await pool.query(`ALTER TABLE grades DROP CONSTRAINT IF EXISTS grades_student_id_course_code_key;`);
        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS grades_stu_course_ay_term_idx 
            ON grades (student_id, course_code, academic_year, enrolled_term);
        `);

        try {
            await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_grades_student_course_ay ON grades (student_id, course_code, academic_year);`);
        } catch (idxErr) {
            console.warn('[SEED] Could not create the one-subject-per-academic-year index:', idxErr.message);
        }

        await pool.query(`CREATE INDEX IF NOT EXISTS idx_grades_student_term ON grades (student_id, enrolled_term, academic_year);`);

        await pool.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_grades_student') THEN
                    ALTER TABLE grades ADD CONSTRAINT fk_grades_student
                        FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE RESTRICT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_grades_course') THEN
                    ALTER TABLE grades ADD CONSTRAINT fk_grades_course
                        FOREIGN KEY (course_code) REFERENCES courses(course_code) ON DELETE RESTRICT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
                    ALTER TABLE users ADD CONSTRAINT users_role_check
                        CHECK (role IN ('admin', 'faculty', 'student', 'registrar'));
                END IF;
            END $$;
        `);

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

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                id INT PRIMARY KEY,
                current_ay VARCHAR(20),
                current_semester INT,
                faculty_portal_locked BOOLEAN DEFAULT FALSE
            );
        `);
        await pool.query(`
            INSERT INTO settings (id, current_ay, current_semester, faculty_portal_locked) 
            VALUES (1, '2026-2027', 1, FALSE) 
            ON CONFLICT (id) DO NOTHING;
        `);

        const existingAdmin = await pool.query(`SELECT username FROM users WHERE username = 'admin'`);
        if (existingAdmin.rows.length === 0) {
            if (!process.env.INITIAL_ADMIN_PASSWORD) console.warn('[SEED] INITIAL_ADMIN_PASSWORD is not set. A random admin password was generated and is NOT shown anywhere. Set INITIAL_ADMIN_PASSWORD and reset the database/admin account to sign in.');
            const initAdminPass = process.env.INITIAL_ADMIN_PASSWORD || generateSecurePassword();
            const adminHash = await bcrypt.hash(initAdminPass, BCRYPT_COST);
            await pool.query(`
                INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
                VALUES ('admin', $1, 'admin', 'System', 'Administrator', TRUE)
                ON CONFLICT (username) DO NOTHING;
            `, [adminHash]);
        }

        const existingRegistrar = await pool.query(`SELECT username FROM users WHERE username = 'registrar'`);
        if (existingRegistrar.rows.length === 0) {
            if (!process.env.INITIAL_REGISTRAR_PASSWORD) console.warn('[SEED] INITIAL_REGISTRAR_PASSWORD is not set. A random registrar password was generated and is NOT shown anywhere.');
            const initRegPass = process.env.INITIAL_REGISTRAR_PASSWORD || generateSecurePassword();
            const regHash = await bcrypt.hash(initRegPass, BCRYPT_COST);
            await pool.query(`
                INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
                VALUES ('registrar', $1, 'registrar', 'CONM', 'Registrar', TRUE)
                ON CONFLICT (username) DO NOTHING;
            `, [regHash]);
        }

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

        for (const c of conmCourses) {
            await pool.query(`
                INSERT INTO courses (course_code, descriptive_title, lec_units, rle_units, total_units, term_id, is_active)
                VALUES ($1, $2, $3, $4, $5, $6, TRUE)
                ON CONFLICT (course_code) DO NOTHING;
            `, c);
        }

        console.log("Database schema verified and active.");
    } catch (err) {
        console.error("Critical database seeding error:", err);
        process.exit(1);
    }
}

app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/portal');
    const lockedPopup = req.query.locked === '1' 
        ? 'Encoding of Grades is Not Yet Officially Open. Please wait for the College Registrar to unlock the Faculty Portal.' 
        : null;
    const sessionExpired = req.query.msg === 'session_expired'
        ? 'Your session expired because your password was changed.'
        : (req.query.msg === 'timeout' ? 'You were signed out because of inactivity. Please sign in again.' : null);
    res.render('login', { error: res.locals.error || sessionExpired, popupMessage: lockedPopup });
});

app.post('/login', loginIpLimiter, loginLimiter, async (req, res) => {
    try {
        const username = req.body.username ? String(req.body.username).trim() : '';
        const password = req.body.password ? String(req.body.password) : '';

        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1 AND COALESCE(is_archived, FALSE) = FALSE', [username]);

        if (userQuery.rows.length === 0) {
            await bcrypt.compare(password, DUMMY_HASH);
            return res.status(401).render('login', { error: GENERIC_LOGIN_ERROR, popupMessage: null });
        }

        const user = userQuery.rows[0];

        if (user.is_locked) {
            const lockedAt = new Date(user.locked_at).getTime();
            const lockElapsedMs = Date.now() - lockedAt;
            if (lockElapsedMs > LOCKOUT_MINUTES * 60 * 1000) {
                await pool.query('UPDATE users SET is_locked = FALSE, failed_login_attempts = 0, locked_at = NULL WHERE username = $1', [user.username]);
                user.is_locked = false;
                user.failed_login_attempts = 0;
            } else {
                const knowsPassword = await bcrypt.compare(password, user.password_hash);
                if (knowsPassword) {
                    const minsLeft = Math.max(1, Math.ceil((LOCKOUT_MINUTES * 60 * 1000 - lockElapsedMs) / 60000));
                    return res.status(401).render('login', {
                        error: `This account is temporarily locked after too many incorrect attempts. Try again in about ${minsLeft} minute${minsLeft === 1 ? '' : 's'}, or contact the College Registrar in person or by phone${REGISTRAR_CONTACT}.`,
                        popupMessage: null
                    });
                }
                return res.status(401).render('login', { error: GENERIC_LOGIN_ERROR, popupMessage: null });
            }
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            const NEW_ATTEMPTS = `CASE WHEN last_failed_at IS NULL OR last_failed_at < NOW() - INTERVAL '24 hours'
                                       THEN 1 ELSE COALESCE(failed_login_attempts, 0) + 1 END`;
            const failRes = await pool.query(`
                UPDATE users
                SET failed_login_attempts = ${NEW_ATTEMPTS},
                    last_failed_at = NOW(),
                    is_locked = (${NEW_ATTEMPTS} >= $2),
                    locked_at = CASE WHEN ${NEW_ATTEMPTS} >= $2 THEN NOW() ELSE locked_at END
                WHERE username = $1
                RETURNING failed_login_attempts, is_locked
            `, [user.username, MAX_FAILED_LOGINS]);

            const result = failRes.rows[0];
            if (result && result.is_locked) {
                await logSecurityEvent(user.username, 'ACCOUNT_LOCKED', 'system', req.ip);
            }
            return res.status(401).render('login', {
                error: GENERIC_LOGIN_ERROR,
                popupMessage: null
            });
        }

        if (user.failed_login_attempts > 0) {
            await pool.query('UPDATE users SET failed_login_attempts = 0 WHERE username = $1', [user.username]);
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
            mustChangePassword: user.must_change_password,
            login_time: Math.max(Date.now(), new Date(user.password_changed_at).getTime() || 0)
        };

        req.session.regenerate((regenErr) => {
            if (regenErr) {
                console.error(regenErr);
                return res.status(500).render('login', { error: 'Session error occurred.', popupMessage: null });
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
        res.status(500).render('login', { error: 'An unexpected error occurred. Please try again.', popupMessage: null });
    }
});

app.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change_password', { error: res.locals.error });
});

app.post('/change-password', isAuthenticated, changePwLimiter, async (req, res) => {
    try {
        const currentPassword = req.body.current_password ? String(req.body.current_password) : '';
        const newPassword = req.body.new_password ? String(req.body.new_password) : '';

        const userRes = await pool.query('SELECT password_hash FROM users WHERE username = $1', [req.session.user.username]);
        if (userRes.rows.length === 0) return res.redirect('/');

        const currentHash = userRes.rows[0].password_hash;
        const isCurrentMatch = await bcrypt.compare(currentPassword, currentHash);
        if (!isCurrentMatch) {
            return res.render('change_password', { error: 'Incorrect current password.' });
        }

        const isReused = await bcrypt.compare(newPassword, currentHash);
        if (isReused) {
            return res.render('change_password', { error: 'New password cannot be the same as your temporary or current password.' });
        }

        const isValid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$/.test(newPassword);
        if (!isValid) {
            return res.render('change_password', { 
                error: 'Password must be 8 to 72 characters long and include uppercase letters, lowercase letters, numbers, and special characters.' 
            });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_COST);
        const pwUpdate = await pool.query(`
            UPDATE users 
            SET password_hash = $1, must_change_password = FALSE, password_changed_at = NOW()
            WHERE username = $2
            RETURNING password_changed_at
        `, [hashedNewPassword, req.session.user.username]);

        req.session.user.mustChangePassword = false;
        req.session.user.login_time = new Date(pwUpdate.rows[0].password_changed_at).getTime();

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
    const pendingFile = req.session.lastBatchFilePath;
    if (pendingFile) {
        try { if (fs.existsSync(pendingFile)) fs.unlinkSync(pendingFile); } catch (e) {}
    }
    req.session.destroy(() => res.redirect('/'));
});

// ==================== ADMIN ROUTES ====================
app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.redirect('/portal');

    try {
        const selectedStaffUsername = req.query.staff_user ? String(req.query.staff_user).trim() : '';
        const searchStudentId = req.query.search_student_id ? String(req.query.search_student_id).trim() : '';

        const staffRes = await pool.query(`
            SELECT username, role, must_change_password, first_name, middle_name, last_name 
            FROM users 
            WHERE role IN ('faculty', 'registrar') AND COALESCE(is_archived, FALSE) = FALSE
            ORDER BY role DESC, last_name ASC, username ASC
        `);

        const archivedStaffRes = await pool.query(`
            SELECT username, role, first_name, middle_name, last_name
            FROM users
            WHERE role IN ('faculty', 'registrar') AND COALESCE(is_archived, FALSE) = TRUE
            ORDER BY role DESC, last_name ASC, username ASC
        `);

        let selectedStaff = null;
        if (selectedStaffUsername) {
            selectedStaff = staffRes.rows.find(f => f.username === selectedStaffUsername) || null;
        }

        let searchedStudents = [];
        if (searchStudentId) {
            const stuSearchRes = await pool.query(`
                SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.program, s.year_level, COALESCE(s.section, 'A') AS section,
                       s.gender, s.is_archived, u.must_change_password
                FROM students s
                LEFT JOIN users u ON s.student_id = u.username
                WHERE s.student_id ILIKE $1
                ORDER BY s.is_archived ASC, s.student_id ASC
            `, [`%${searchStudentId.replace(/[\\%_]/g, '\\$&')}%`]);
            searchedStudents = stuSearchRes.rows;
        }

        const allActiveRes = await pool.query(`
            SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.program, s.year_level, COALESCE(s.section, 'A') AS section
            FROM students s
            JOIN users u ON s.student_id = u.username
            WHERE COALESCE(s.is_archived, FALSE) = FALSE AND u.role = 'student'
            ORDER BY s.last_name ASC
        `);
        const allActiveStudents = allActiveRes.rows;

        const archivedRes = await pool.query(`
            SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.program, s.year_level, COALESCE(s.section, 'A') AS section
            FROM students s
            JOIN users u ON s.student_id = u.username
            WHERE COALESCE(s.is_archived, FALSE) = TRUE AND u.role = 'student'
            ORDER BY s.last_name ASC
        `);
        const allArchivedStudents = archivedRes.rows;

        res.render('admin', {
            currentUser: req.session.user,
            staffList: staffRes.rows,
            archivedStaffList: archivedStaffRes.rows,
            selectedStaff: selectedStaff,
            searchStudentId: searchStudentId,
            searchedStudents: searchedStudents,
            allActiveStudents: allActiveStudents,
            allArchivedStudents: allArchivedStudents
        });
    } catch (err) {
        console.error('Admin load error:', err);
        res.status(500).send('Unable to load administrator dashboard.');
    }
});

app.post('/admin/add-staff', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    try {
        const cleanUser = req.body.username ? String(req.body.username).trim() : '';
        const staffRole = req.body.role === 'registrar' ? 'registrar' : 'faculty';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';
        const pass = req.body.temp_password && String(req.body.temp_password).trim() ? String(req.body.temp_password).trim() : generateSecurePassword();

        if (!cleanUser || !fName || !lName) {
            setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
            return res.redirect('/admin');
        }

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

        await logSecurityEvent(cleanUser, 'STAFF_CREATED', req.session.user.username, req.ip, staffRole + ' (admin)');
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

    let client;
    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';
        const yr = Math.min(4, Math.max(1, parseInt(req.body.year_level, 10) || 1));
        const rawSec = String(req.body.section || '').trim().toUpperCase();
        const sec = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';
        const pass = req.body.temp_password && String(req.body.temp_password).trim() ? String(req.body.temp_password).trim() : generateSecurePassword();

        if (!cleanId || !fName || !lName) {
            setFlash(req, 'err', 'Student ID, First Name, and Last Name are required.');
            return res.redirect('/admin');
        }
        const rawGender = String(req.body.gender || '').trim();
        const gender = ['Male', 'Female'].includes(rawGender) ? rawGender : '';
        if (!gender) {
            setFlash(req, 'err', 'Please select a Gender.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
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
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, gender, is_archived) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, $7, FALSE)
        `, [cleanId, fName, mName, lName, yr, sec, gender]);

        await client.query('COMMIT');
        setFlash(req, 'msg', `Student account '${cleanId}' (BSN${yr} - ${sec}) created successfully.`);
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Admin add student error:', err);
        setFlash(req, 'err', 'Error creating student account.');
        res.redirect('/admin');
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/delete-user', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const username = req.body.username ? String(req.body.username).trim() : '';
        const action = req.body.action === 'restore' ? 'restore' : 'archive';
        
        if (!username || username === 'admin') {
            setFlash(req, 'err', 'Cannot modify the primary system administrator.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
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
        await client.query(
            'INSERT INTO account_security_logs (username, event, performed_by) VALUES ($1, $2, $3)',
            [username, archiveFlag ? 'ACCOUNT_ARCHIVED' : 'ACCOUNT_RESTORED', req.session.user.username]
        );

        if (dbRole === 'student') {
            await client.query('UPDATE students SET is_archived = $1 WHERE student_id = $2', [archiveFlag, username]);
        } else if (dbRole === 'faculty' && archiveFlag) {
            await client.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', `Account '${username}' has been ${archiveFlag ? 'archived (grades preserved)' : 'restored'}.`);
        res.redirect('/admin');
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Archive user error:', err);
        setFlash(req, 'err', 'Failed to update account archive status.');
        res.redirect('/admin');
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/bulk-archive-users', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        let userIds = req.body.userIds;
        if (!userIds) {
            setFlash(req, 'err', 'No users selected for archiving.');
            return res.redirect('/admin');
        }
        if (!Array.isArray(userIds)) userIds = [userIds];
        userIds = userIds.map(id => String(id).trim()).filter(id => id && id !== 'admin');

        if (userIds.length === 0) {
            setFlash(req, 'err', 'Invalid selection.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
        await client.query('BEGIN');

        const archived = await client.query(`
            UPDATE users SET is_archived = TRUE
            WHERE username = ANY($1::text[]) AND role = 'student' AND COALESCE(is_archived, FALSE) = FALSE
            RETURNING username
        `, [userIds]);
        const ids = archived.rows.map(r => r.username);

        if (ids.length > 0) {
            await client.query('UPDATE students SET is_archived = TRUE WHERE student_id = ANY($1::text[])', [ids]);
            await client.query(
                `INSERT INTO account_security_logs (username, event, performed_by) SELECT unnest($1::text[]), 'ACCOUNT_ARCHIVED', $2`,
                [ids, req.session.user.username]
            );
        }

        await client.query('COMMIT');
        if (ids.length === 0) {
            setFlash(req, 'err', 'No active student accounts matched the selection.');
        } else {
            setFlash(req, 'msg', `Successfully archived ${ids.length} student account(s).`);
        }
        res.redirect('/admin');
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Bulk archive error:', err);
        setFlash(req, 'err', 'Failed to archive accounts.');
        res.redirect('/admin');
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/bulk-restore-users', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        let userIds = req.body.userIds;
        if (!userIds) {
            setFlash(req, 'err', 'No users selected for restoring.');
            return res.redirect('/admin');
        }
        if (!Array.isArray(userIds)) userIds = [userIds];
        userIds = userIds.map(id => String(id).trim()).filter(id => id && id !== 'admin');

        if (userIds.length === 0) {
            setFlash(req, 'err', 'Invalid selection.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
        await client.query('BEGIN');

        const restored = await client.query(`
            UPDATE users SET is_archived = FALSE
            WHERE username = ANY($1::text[]) AND role = 'student' AND COALESCE(is_archived, FALSE) = TRUE
            RETURNING username
        `, [userIds]);
        const ids = restored.rows.map(r => r.username);

        if (ids.length > 0) {
            await client.query('UPDATE students SET is_archived = FALSE WHERE student_id = ANY($1::text[])', [ids]);
            await client.query(
                `INSERT INTO account_security_logs (username, event, performed_by) SELECT unnest($1::text[]), 'ACCOUNT_RESTORED', $2`,
                [ids, req.session.user.username]
            );
        }

        await client.query('COMMIT');
        if (ids.length === 0) {
            setFlash(req, 'err', 'No archived student accounts matched the selection.');
        } else {
            setFlash(req, 'msg', `Successfully restored ${ids.length} student account(s). They can log in again with their existing passwords.`);
        }
        res.redirect('/admin');
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Bulk restore error:', err);
        setFlash(req, 'err', 'Failed to restore accounts.');
        res.redirect('/admin');
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/bulk-delete-users', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    if (process.env.ALLOW_PERMANENT_DELETE !== 'true') {
        setFlash(req, 'err', 'Permanent deletion is turned off to protect academic and health records. Please use Archive instead.');
        return res.redirect('/admin');
    }

    let client;
    try {
        let userIds = req.body.userIds;
        if (!userIds) {
            setFlash(req, 'err', 'No users selected for deletion.');
            return res.redirect('/admin');
        }
        if (!Array.isArray(userIds)) userIds = [userIds];
        userIds = userIds.map(id => String(id).trim()).filter(id => id && id !== 'admin');

        if (userIds.length === 0) {
            setFlash(req, 'err', 'Invalid selection.');
            return res.redirect('/admin');
        }

        if (String(req.body.confirm_text || '').trim() !== 'DELETE') {
            setFlash(req, 'err', 'Nothing was deleted. Type DELETE in the confirmation box to permanently delete accounts.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
        await client.query('BEGIN');

        const found = await client.query(
            `SELECT username FROM users WHERE username = ANY($1::text[]) AND role = 'student' AND COALESCE(is_archived, FALSE) = TRUE FOR UPDATE`,
            [userIds]
        );
        const ids = found.rows.map(r => r.username);

        if (ids.length === 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'No archived student accounts matched. Only archived accounts can be permanently deleted. Archive them first.');
            return res.redirect('/admin');
        }

        await client.query('DELETE FROM grades WHERE student_id = ANY($1::text[])', [ids]);
        await client.query('DELETE FROM student_vaccinations WHERE student_id = ANY($1::text[])', [ids]);
        await client.query('DELETE FROM students WHERE student_id = ANY($1::text[])', [ids]);
        await client.query(`DELETE FROM users WHERE username = ANY($1::text[]) AND role = 'student'`, [ids]);

        await client.query(
            `INSERT INTO account_security_logs (username, event, performed_by) SELECT unnest($1::text[]), 'ACCOUNT_DELETED', $2`,
            [ids, req.session.user.username]
        );

        await client.query('COMMIT');
        setFlash(req, 'msg', `Permanently deleted ${ids.length} student account(s). Audit logs were retained.`);
        res.redirect('/admin');
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Bulk delete error:', err);
        setFlash(req, 'err', 'Failed to permanently delete accounts.');
        res.redirect('/admin');
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const origUser = req.body.original_username ? String(req.body.original_username).trim() : '';
        const cleanUser = req.body.username ? String(req.body.username).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';

        if (!origUser || !cleanUser || !fName || !lName) {
            setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
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

        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') {
            const hashedPassword = await bcrypt.hash(String(req.body.temp_password).trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE, failed_login_attempts = 0, is_locked = FALSE, locked_at = NULL, password_changed_at = NOW()
                WHERE username = $2
            `, [hashedPassword, cleanUser]);
        }

        await client.query('COMMIT');
        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') await logSecurityEvent(cleanUser, 'PASSWORD_RESET', req.session.user.username);
        await logSecurityEvent(cleanUser, 'STAFF_UPDATED', req.session.user.username, req.ip, 'staff profile (admin)');
        setFlash(req, 'msg', 'Staff profile updated successfully.');
        res.redirect(`/admin?staff_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Admin edit staff error:', err);
        setFlash(req, 'err', 'Failed to update staff profile.');
        res.redirect(`/admin?staff_user=${encodeURIComponent(req.body.original_username)}`);
    } finally {
        if (client) client.release();
    }
});

app.post('/admin/edit-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';
        const yr = Math.min(4, Math.max(1, parseInt(req.body.year_level, 10) || 1));
        const rawSec = String(req.body.section || '').trim().toUpperCase();
        const sec = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';
        
        const rawGender = String(req.body.gender || '').trim();
        const gender = ['Male', 'Female'].includes(rawGender) ? rawGender : '';

        if (!cleanId || !fName || !lName) {
            setFlash(req, 'err', 'Student ID, First Name, and Last Name are required.');
            return res.redirect('/admin');
        }

        client = await pool.connect();
        await client.query('BEGIN');
        const stuUpdate = await client.query(`
            UPDATE students 
            SET first_name = $1, middle_name = $2, last_name = $3, year_level = $4, section = $5,
                gender = COALESCE(NULLIF($7::text, ''), gender)
            WHERE student_id = $6
        `, [fName, mName, lName, yr, sec, cleanId, gender]);

        if (stuUpdate.rowCount === 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'Student record not found.');
            return res.redirect('/admin');
        }

        await client.query(`
            UPDATE users 
            SET first_name = $1, middle_name = $2, last_name = $3
            WHERE username = $4 AND role = 'student'
        `, [fName, mName, lName, cleanId]);

        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') {
            const hashedPassword = await bcrypt.hash(String(req.body.temp_password).trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE, failed_login_attempts = 0, is_locked = FALSE, locked_at = NULL, password_changed_at = NOW()
                WHERE username = $2 AND role = 'student'
            `, [hashedPassword, cleanId]);
        }

        await client.query('COMMIT');
        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') await logSecurityEvent(cleanId, 'PASSWORD_RESET', req.session.user.username);
        setFlash(req, 'msg', 'Student profile updated successfully.');
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Admin edit student error:', err);
        setFlash(req, 'err', 'Failed to update student profile.');
        res.redirect(`/admin?search_student_id=${encodeURIComponent(String(req.body.student_id || '').trim())}`);
    } finally {
        if (client) client.release();
    }
});

// ==================== ACCURATE VACCINATION SCHEDULE & INTERVAL CALCULATOR ====================
function addDaysYmd(ymd, days) {
    const [y, m, d] = String(ymd).split('-').map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    dt.setUTCDate(dt.getUTCDate() + (parseInt(days, 10) || 0));
    return dt.toISOString().slice(0, 10);
}

function addMonthsYmd(ymd, months) {
    const [y, m, d] = String(ymd).split('-').map(Number);
    const dt = new Date(Date.UTC(y, m - 1 + months, d));
    return dt.toISOString().slice(0, 10);
}

function getNextDoseRequiredDate(vaccineName, doseNumber, lastDateStr) {
    // Exact schedule intervals matching user guidelines:
    // Tetanus Toxoid: 2nd: 4 weeks (28 days) after 1st. 3rd: 6 months after 2nd. 4th: 1 year after 3rd. 5th: 1 year after 4th.
    // Hepatitis B: 2nd: 4 weeks (28 days) after 1st. 3rd: 5 months after 2nd (6 months total from 1st).
    // Flu vaccine: Annual intervals (365 days).
    if (vaccineName === 'Tetanus Toxoid') {
        if (doseNumber === 1) return addDaysYmd(lastDateStr, 28);
        if (doseNumber === 2) return addMonthsYmd(lastDateStr, 6);
        if (doseNumber === 3 || doseNumber === 4) return addDaysYmd(lastDateStr, 365);
    } else if (vaccineName === 'Hepatitis B') {
        if (doseNumber === 1) return addDaysYmd(lastDateStr, 28);
        if (doseNumber === 2) return addMonthsYmd(lastDateStr, 5);
    } else if (vaccineName === 'Flu vaccine') {
        return addDaysYmd(lastDateStr, 365);
    }
    return addDaysYmd(lastDateStr, 30);
}

async function calculateImmunizationStatus(client, studentId) {
    const vaccinesRes = await client.query('SELECT * FROM vaccine_types ORDER BY id');
    const vaccines = vaccinesRes.rows;
    const report = [];

    const todayStr = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);

    for (const v of vaccines) {
        const dosesRes = await client.query(`
            SELECT *, to_char(date_given, 'YYYY-MM-DD') AS date_str FROM student_vaccinations 
            WHERE student_id = $1 AND vaccine_id = $2 AND voided_at IS NULL
            ORDER BY cycle_number DESC, dose_number DESC, date_given DESC
        `, [studentId, v.id]);

        const doses = dosesRes.rows;
        if (doses.length === 0) {
            report.push({
                vaccine_id: v.id,
                name: v.name,
                doses_required: v.doses_required,
                last_dose_date: null,
                last_dose_id: null,
                dose_number: 0,
                status: 'Not started',
                status_cls: 'bg-slate-100 text-slate-700 border-slate-300',
                next_due_date: null,
                must_restart: false,
                doses_history: []
            });
            continue;
        }

        const latest = doses[0];
        const lastDateStr = latest.date_str;
        
        let nextDueDate = null;
        let status = 'Valid';
        let statusCls = 'bg-emerald-100 text-emerald-800 border-emerald-300';
        let mustRestart = false;

        if (latest.dose_number < v.doses_required) {
            // Calculate precise target date for the next scheduled dose
            const targetDueStr = getNextDoseRequiredDate(v.name, latest.dose_number, lastDateStr);
            // 30-day grace period rule: if today exceeds targetDueStr by more than 30 days, it is expired and must restart
            const deadlineStr = addDaysYmd(targetDueStr, 30);

            nextDueDate = targetDueStr;

            if (todayStr > deadlineStr) {
                status = 'Expired (restart at 1st dose)';
                statusCls = 'bg-red-100 text-red-800 border-red-300';
                mustRestart = true;
            } else if (todayStr > targetDueStr) {
                status = 'Overdue (within grace period)';
                statusCls = 'bg-amber-100 text-amber-800 border-amber-300';
            } else {
                status = 'In progress';
                statusCls = 'bg-indigo-100 text-indigo-800 border-indigo-300';
            }
        } else {
            // Completed series (valid for 1 year before annual booster/renewal)
            const expiryStr = addDaysYmd(lastDateStr, 365);
            nextDueDate = expiryStr;
            if (todayStr > expiryStr) {
                status = 'Series Expired (renewal needed)';
                statusCls = 'bg-amber-100 text-amber-800 border-amber-300';
            } else {
                status = 'Completed & Valid';
                statusCls = 'bg-emerald-100 text-emerald-800 border-emerald-300';
            }
        }

        report.push({
            vaccine_id: v.id,
            name: v.name,
            doses_required: v.doses_required,
            last_dose_date: lastDateStr,
            last_dose_id: latest.id,
            dose_number: latest.dose_number,
            status: status,
            status_cls: statusCls,
            next_due_date: nextDueDate,
            must_restart: mustRestart,
            doses_history: doses
        });
    }
    return report;
}

app.get('/registrar/api/lookup-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const studentId = req.query.student_id ? String(req.query.student_id).trim() : '';
    if (!studentId) return res.status(400).json({ error: 'Student ID required' });

    let client;
    try {
        client = await pool.connect();
        const studentRes = await client.query('SELECT * FROM students WHERE student_id = $1 AND COALESCE(is_archived, FALSE) = FALSE', [studentId]);
        
        if (studentRes.rows.length === 0) {
            return res.json({ exists: false, message: 'No student record. Please enroll the student.' });
        }

        const student = studentRes.rows[0];
        const immunizationReport = await calculateImmunizationStatus(client, studentId);

        await client.query(
            'INSERT INTO immunization_access_logs (student_id, accessed_by, action_type) VALUES ($1, $2, $3)',
            [studentId, req.session.user.username, 'VIEW']
        );

        res.json({
            exists: true,
            student: student,
            immunization: immunizationReport
        });
    } catch (err) {
        console.error('API Student lookup error:', err);
        res.status(500).json({ error: 'Lookup failed' });
    } finally {
        if (client) client.release();
    }
});

app.get('/registrar', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }

    let client;
    try {
        client = await pool.connect();
        const targetStudentId = req.query.student_id ? String(req.query.student_id).trim() : '';
        const selectedFacultyUser = req.query.faculty_user ? String(req.query.faculty_user).trim() : '';
        let selectedTerm = /^[1-8]$/.test(String(req.query.view_term || '')) ? String(req.query.view_term) : '';

        const settingsRes = await client.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        let student = null;
        let grades = [];
        let immunizationReport = [];
        let selectedAy = req.query.view_ay ? String(req.query.view_ay).trim() : systemSettings.current_ay;

        const allCoursesRes = await client.query('SELECT * FROM courses WHERE COALESCE(is_active, TRUE) = TRUE ORDER BY term_id, course_code');
        const allCoursesRaw = allCoursesRes.rows;

        const facultyListRes = await client.query(`
            SELECT username, first_name, middle_name, last_name 
            FROM users 
            WHERE role = 'faculty' AND COALESCE(is_archived, FALSE) = FALSE
            ORDER BY last_name ASC, username ASC
        `);
        const facultyList = facultyListRes.rows;

        const lockedRoles = req.session.user.role === 'admin' ? ['student', 'faculty', 'registrar'] : ['student', 'faculty'];
        const lockedRes = await client.query(`
            SELECT username, role, first_name, middle_name, last_name, locked_at
            FROM users
            WHERE COALESCE(is_locked, FALSE) = TRUE AND locked_at > NOW() - INTERVAL '${LOCKOUT_MINUTES} minutes' AND COALESCE(is_archived, FALSE) = FALSE AND role = ANY($1::text[])
            ORDER BY locked_at DESC NULLS LAST
        `, [lockedRoles]);

        let selectedFaculty = null;
        let facultyAssignedCourses = [];

        if (selectedFacultyUser) {
            selectedFaculty = facultyList.find(f => f.username === selectedFacultyUser) || null;
            if (selectedFaculty) {
                const facCoursesRes = await client.query(`
                    SELECT course_code FROM faculty_courses WHERE username = $1
                `, [selectedFacultyUser]);
                facultyAssignedCourses = facCoursesRes.rows.map(fc => fc.course_code);
            }
        }

        if (targetStudentId) {
            const studentRes = await client.query('SELECT * FROM students WHERE student_id = $1 AND COALESCE(is_archived, FALSE) = FALSE', [targetStudentId]);
            student = studentRes.rows[0] || null;

            if (!student) {
                setFlash(req, 'err', `No student record found for ID '${targetStudentId}'. Please check the number or use Register.`);
                return res.redirect('/registrar');
            }

            if (student) {
                const defaultTerm = ((parseInt(student.year_level, 10) - 1) * 2 + parseInt(systemSettings.current_semester, 10)).toString();
                if (!selectedTerm) selectedTerm = defaultTerm;
                const gradesRes = await client.query(`
                    SELECT g.id, g.course_code, g.final_grade, g.instructor, g.instructor_username, g.remarks, g.enrolled_term, g.academic_year,
                           c.descriptive_title, c.lec_units, c.rle_units, c.total_units
                    FROM grades g
                    JOIN courses c ON g.course_code = c.course_code
                    WHERE g.student_id = $1 AND g.enrolled_term = $2 AND g.academic_year = $3
                    ORDER BY g.course_code ASC
                `, [targetStudentId, selectedTerm, selectedAy]);
                grades = gradesRes.rows;

                immunizationReport = await calculateImmunizationStatus(client, targetStudentId);
                await client.query(
                    'INSERT INTO immunization_access_logs (student_id, accessed_by, action_type) VALUES ($1, $2, $3)',
                    [targetStudentId, req.session.user.username, 'VIEW']
                );
            }
        }

        res.render('registrar', {
            currentUser: req.session.user,
            systemSettings: systemSettings,
            selectedStudent: student,
            grades: grades,
            immunizationReport: immunizationReport,
            availableCourses: allCoursesRaw,
            allCoursesRaw: allCoursesRaw,
            currentTerm: selectedTerm || '1',
            currentViewAy: selectedAy,
            facultyList: facultyList,
            lockedAccounts: lockedRes.rows,
            selectedFaculty: selectedFaculty,
            facultyAssignedCourses: facultyAssignedCourses,
            hasBatchCredentials: Boolean(req.session.lastBatchFilePath && fs.existsSync(req.session.lastBatchFilePath))
        });
    } catch (err) {
        console.error('Registrar load error:', err);
        res.status(500).send('Error loading registrar dashboard.');
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/update-settings', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    const ay = String(req.body.current_ay || '').trim();
    const sem = parseInt(req.body.current_semester, 10) === 2 ? 2 : 1;
    if (!isValidAcademicYear(ay)) {
        setFlash(req, 'err', 'Invalid academic year. Use the format YYYY-YYYY, for example 2026-2027.');
        return res.redirect('/registrar');
    }
    try {
        await pool.query('UPDATE settings SET current_ay = $1, current_semester = $2 WHERE id = 1', [ay, sem]);
        await logSecurityEvent('system', 'SETTINGS_CHANGED', req.session.user.username, req.ip, `A.Y. ${ay}, Semester ${sem}`);
        setFlash(req, 'msg', 'Active Academic Year and Semester updated system-wide.');
        res.redirect('/registrar');
    } catch (err) {
        console.error('Update settings error:', err);
        setFlash(req, 'err', 'Failed to update settings.');
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
        await logSecurityEvent('system', 'FACULTY_LOCK_TOGGLED', req.session.user.username, req.ip, newState ? 'Faculty portal locked' : 'Faculty portal unlocked');
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

app.post('/registrar/batch-upload', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    upload.single('file')(req, res, (uploadErr) => {
        if (uploadErr) {
            setFlash(req, 'err', uploadErr.message || 'Invalid file upload.');
            return res.redirect('/registrar');
        }

        const token = (req.body && req.body._csrf) || req.query._csrf;
        if (!token || token !== req.session.csrfToken) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            return res.status(403).send('Invalid security token (CSRF).');
        }

        if (!req.file) {
            setFlash(req, 'err', 'Please select a valid CSV file.');
            return res.redirect('/registrar');
        }

        const rows = [];
        const stream = fs.createReadStream(req.file.path).pipe(csv({
            mapHeaders: ({ header }) => header ? header.trim().toLowerCase() : ''
        }));

        stream.on('data', (row) => rows.push(row));
        stream.on('error', (streamErr) => {
            console.error('CSV stream error:', streamErr);
            if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            setFlash(req, 'err', 'Could not parse CSV stream.');
            return res.redirect('/registrar');
        });

        stream.on('end', async () => {
            if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

            if (rows.length === 0) {
                setFlash(req, 'err', 'The uploaded CSV file is empty.');
                return res.redirect('/registrar');
            }
            if (rows.length > 300) {
                setFlash(req, 'err', 'Batch limit is 300 students per upload.');
                return res.redirect('/registrar');
            }

            let client;
            const generatedCredentials = [];
            let enrolledCount = 0;

            try {
                client = await pool.connect();
                const facRes = await client.query(`SELECT username, first_name, middle_name, last_name FROM users WHERE role = 'faculty'`);
                const facultyMap = new Map();
                facRes.rows.forEach(f => {
                    facultyMap.set(f.username.toLowerCase(), { username: f.username, formalName: formatFormalFacultyName(f) });
                    facultyMap.set(formatFormalFacultyName(f).toLowerCase(), { username: f.username, formalName: formatFormalFacultyName(f) });
                });

                const coursesRes = await client.query('SELECT course_code FROM courses WHERE COALESCE(is_active, TRUE) = TRUE');
                const validCourseCodes = new Set(coursesRes.rows.map(c => c.course_code.toUpperCase()));

                await client.query('BEGIN');

                for (let idx = 0; idx < rows.length; idx++) {
                    const row = rows[idx];
                    const cleanId = row.student_id ? String(row.student_id).trim() : '';
                    const fName = row.first_name ? String(row.first_name).trim() : '';
                    const mName = row.middle_name ? String(row.middle_name).trim() : '';
                    const lName = row.last_name ? String(row.last_name).trim() : '';

                    if (!cleanId || !fName || !lName) {
                        throw new UserError(`Row ${idx + 2} is missing student_id, first_name, or last_name.`);
                    }

                    const rawYear = String(row.year_level || '1').replace(/[^0-9]/g, '');
                    const cleanYear = parseInt(rawYear, 10);
                    if (![1, 2, 3, 4].includes(cleanYear)) {
                        throw new UserError(`Row ${idx + 2} (${cleanId}) has an invalid year_level.`);
                    }

                    const rawSec = row.section ? String(row.section).trim().toUpperCase() : 'A';
                    const cleanSection = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';

                    const rawGenderCsv = row.gender ? String(row.gender).trim() : '';
                    let cleanGender = null;
                    if (rawGenderCsv) {
                        const gNorm = rawGenderCsv.charAt(0).toUpperCase() + rawGenderCsv.slice(1).toLowerCase();
                        if (!['Male', 'Female'].includes(gNorm)) {
                            throw new UserError(`Row ${idx + 2} (${cleanId}) has an invalid gender. Use Male or Female.`);
                        }
                        cleanGender = gNorm;
                    }

                    const userCheck = await client.query('SELECT username, role, COALESCE(is_archived, FALSE) AS is_archived FROM users WHERE username = $1', [cleanId]);
                    if (userCheck.rows.length > 0) {
                        if (userCheck.rows[0].role !== 'student') {
                            throw new UserError(`Row ${idx + 2}: Student ID '${cleanId}' conflicts with a staff account.`);
                        }
                        if (userCheck.rows[0].is_archived) {
                            throw new UserError(`Row ${idx + 2}: Student ID '${cleanId}' is archived. Ask the administrator to restore the account first.`);
                        }
                        await client.query(`
                            UPDATE users SET first_name = $1, middle_name = $2, last_name = $3 WHERE username = $4
                        `, [fName, mName, lName, cleanId]);
                    } else {
                        const tempPassword = generateSecurePassword();
                        const hashedPassword = await bcrypt.hash(tempPassword, BCRYPT_BATCH_COST);

                        await client.query(`
                            INSERT INTO users (username, password_hash, role, first_name, middle_name, last_name, must_change_password, is_archived) 
                            VALUES ($1, $2, 'student', $3, $4, $5, TRUE, FALSE)
                        `, [cleanId, hashedPassword, fName, mName, lName]);

                        generatedCredentials.push({
                            student_id: cleanId,
                            name: `${lName}, ${fName} ${mName}`.trim(),
                            year_section: `BSN${cleanYear} - ${cleanSection}`,
                            temp_password: tempPassword
                        });
                    }

                    await client.query(`
                        INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, gender, is_archived) 
                        VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, $7::varchar(10), FALSE)
                        ON CONFLICT (student_id) DO UPDATE SET first_name = $2, middle_name = $3, last_name = $4, year_level = $5, section = $6, gender = COALESCE($7::varchar(10), students.gender)
                    `, [cleanId, fName, mName, lName, cleanYear, cleanSection, cleanGender]);

                    if (row.semester && row.subjects && row.academic_year) {
                        const cleanSem = parseInt(String(row.semester).trim(), 10);
                        if (![1, 2].includes(cleanSem)) {
                            throw new UserError(`Row ${idx + 2} (${cleanId}) has an invalid semester.`);
                        }
                        const cleanAy = String(row.academic_year).trim();
                        if (!isValidAcademicYear(cleanAy)) {
                            throw new UserError(`Row ${idx + 2} (${cleanId}) has an invalid academic year format.`);
                        }

                        const termId = ((cleanYear - 1) * 2 + cleanSem).toString();
                        const courseCodes = String(row.subjects).split(',').map(s => s.trim().toUpperCase()).filter(Boolean);

                        for (const code of courseCodes) {
                            if (!validCourseCodes.has(code)) {
                                throw new UserError(`Row ${idx + 2} (${cleanId}) lists unknown or inactive course code '${code}'.`);
                            }

                            const instructorKey = `instructor_${code.toLowerCase().replace(/\s+/g, '_')}`;
                            const rawInst = String(row[instructorKey] || row.instructor || '').trim();
                            const matchedFac = facultyMap.get(rawInst.toLowerCase());
                            const instName = matchedFac ? matchedFac.formalName : rawInst;
                            const instUser = matchedFac ? matchedFac.username : '';

                            await client.query(`
                                INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year) 
                                VALUES ($1, $2, '', $3, $4, '', $5, $6)
                                ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
                                DO UPDATE SET 
                                    instructor = COALESCE(NULLIF($3, ''), grades.instructor),
                                    instructor_username = COALESCE(NULLIF($4, ''), grades.instructor_username);
                            `, [cleanId, code, instName, instUser, termId, cleanAy]);
                        }
                    }
                    enrolledCount++;
                }

                await client.query('COMMIT');
                
                if (generatedCredentials.length > 0) {
                    if (req.session.lastBatchFilePath && fs.existsSync(req.session.lastBatchFilePath)) {
                        try { fs.unlinkSync(req.session.lastBatchFilePath); } catch (e) {}
                    }
                    const csvHeader = 'Student ID,Student Name,Year & Section,Temporary Password\n';
                    const csvRows = generatedCredentials.map(c => [
                        sanitizeCsvCell(c.student_id),
                        sanitizeCsvCell(c.name),
                        sanitizeCsvCell(c.year_section),
                        `"${String(c.temp_password).replace(/"/g, '""')}"`
                    ].join(',')).join('\n');
                    
                    const tempFilePath = path.join('uploads', `batch_creds_${crypto.randomBytes(16).toString('hex')}.csv`);
                    fs.writeFileSync(tempFilePath, csvHeader + csvRows, { encoding: 'utf8', mode: 0o600 });
                    req.session.lastBatchFilePath = tempFilePath;
                }

                await logSecurityEvent(req.session.user.username, 'BATCH_UPLOAD', req.session.user.username, req.ip, `${enrolledCount} students processed, ${generatedCredentials.length} new accounts`);
                setFlash(req, 'msg', `${enrolledCount} students processed (${generatedCredentials.length} new accounts generated).`);
                res.redirect('/registrar');
            } catch (err) {
                if (client) await client.query('ROLLBACK').catch(() => {});
                console.error('Batch upload error:', err);
                setFlash(req, 'err', safeMsg(err, 'Batch upload failed. No changes were saved.'));
                res.redirect('/registrar');
            } finally {
                if (client) client.release();
            }
        });
    });
});

app.get('/registrar/export-batch-credentials', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    
    const filePath = req.session.lastBatchFilePath;
    if (!filePath || !fs.existsSync(filePath)) {
        setFlash(req, 'err', 'No new student credentials available to download.');
        return res.redirect('/registrar');
    }

    delete req.session.lastBatchFilePath;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="batch_temporary_passwords.csv"');
    res.status(200).sendFile(path.resolve(filePath), (err) => {
        if (err) console.error('Error sending credentials file:', err);
        try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {}
    });
});

app.post('/registrar/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';
        const yr = Math.min(4, Math.max(1, parseInt(req.body.year_level, 10) || 1));
        const rawSec = String(req.body.section || '').trim().toUpperCase();
        const sec = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';
        const rawGender = String(req.body.gender || '').trim();
        const gender = ['Male', 'Female'].includes(rawGender) ? rawGender : '';
        const pass = req.body.temp_password && String(req.body.temp_password).trim() ? String(req.body.temp_password).trim() : generateSecurePassword();

        if (!cleanId || !fName || !lName) {
            setFlash(req, 'err', 'Student ID, First Name, and Last Name are required.');
            return res.redirect('/registrar');
        }
        if (!gender) {
            setFlash(req, 'err', 'Please select a Gender.');
            return res.redirect('/registrar');
        }

        client = await pool.connect();
        await client.query('BEGIN');
        
        const existingUser = await client.query('SELECT username, role, COALESCE(is_archived, FALSE) AS is_archived FROM users WHERE username = $1', [cleanId]);
        if (existingUser.rows.length > 0 && existingUser.rows[0].role !== 'student') {
            throw new UserError(`Student ID '${cleanId}' conflicts with a staff account.`);
        }
        const existingProfile = await client.query('SELECT COALESCE(is_archived, FALSE) AS is_archived FROM students WHERE student_id = $1', [cleanId]);
        if ((existingUser.rows.length > 0 && existingUser.rows[0].is_archived) || (existingProfile.rows.length > 0 && existingProfile.rows[0].is_archived)) {
            throw new UserError(`Student ID '${cleanId}' is archived. Please ask the administrator to restore the account before enrolling.`);
        }
        if (existingUser.rows.length > 0) {
            await client.query(`UPDATE users SET first_name = $1, middle_name = $2, last_name = $3 WHERE username = $4 AND role = 'student'`, [fName, mName, lName, cleanId]);
        }
        if (existingUser.rows.length === 0) {
            const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);
            await client.query(`
                INSERT INTO users (username, password_hash, role, first_name, middle_name, last_name, must_change_password, is_archived) 
                VALUES ($1, $2, 'student', $3, $4, $5, TRUE, FALSE)
            `, [cleanId, hashedPassword, fName, mName, lName]);
        }

        await client.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level, section, gender, is_archived) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5, $6, $7, FALSE)
            ON CONFLICT (student_id) DO UPDATE SET first_name = $2, middle_name = $3, last_name = $4, year_level = $5, section = $6, gender = $7
        `, [cleanId, fName, mName, lName, yr, sec, gender]);

        const settingsRes = await client.query('SELECT current_ay, current_semester FROM settings WHERE id = 1');
        const ay = settingsRes.rows[0].current_ay;
        const sem = parseInt(settingsRes.rows[0].current_semester, 10) === 2 ? 2 : 1;
        const term = String((yr - 1) * 2 + sem);

        if (req.body.course_codes) {
            const codes = Array.isArray(req.body.course_codes) ? req.body.course_codes : [req.body.course_codes];

            if (!/^[1-8]$/.test(term)) throw new UserError('Invalid term.');
            if (!isValidAcademicYear(ay)) throw new UserError('Invalid academic year format.');

            for (let i = 0; i < codes.length; i++) {
                const code = codes[i];
                const facUser = req.body[`instructor__${code}`] ? String(req.body[`instructor__${code}`]).trim() : '';
                let facFormalName = '';

                if (facUser) {
                    const facRes = await client.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
                    if (facRes.rows.length > 0) {
                        facFormalName = formatFormalFacultyName(facRes.rows[0]);
                    } else {
                        throw new UserError('Selected instructor is not a valid faculty account.');
                    }
                }

                const checkCourse = await client.query('SELECT course_code FROM courses WHERE course_code = $1 AND COALESCE(is_active, TRUE) = TRUE', [code]);
                if (checkCourse.rows.length === 0) throw new UserError(`Subject ${code} is inactive or not found.`);

                await client.query(`
                    INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year)
                    VALUES ($1, $2, '', $3, $4, '', $5, $6)
                    ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
                    DO UPDATE SET instructor = COALESCE(NULLIF($3, ''), grades.instructor), instructor_username = COALESCE(NULLIF($4, ''), grades.instructor_username);
                `, [cleanId, code, facFormalName, facUser, term, ay]);
            }
        }

        await client.query('COMMIT');
        await logSecurityEvent(cleanId, 'STUDENT_REGISTERED', req.session.user.username, req.ip, `BSN${yr}-${sec}, A.Y. ${ay}, Sem ${sem}`);
        setFlash(req, 'msg', `Student '${cleanId}' (BSN${yr} - ${sec}) pre-registered for A.Y. ${ay}, ${sem === 1 ? '1st' : '2nd'} Semester.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}#immunizationPanel`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Registrar add student error:', err);
        setFlash(req, 'err', safeMsg(err, 'Error registering new student.'));
        res.redirect('/registrar');
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/record-vaccine', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const studentId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const vaccineId = parseInt(req.body.vaccine_id, 10);
        const dateGiven = req.body.date_given ? String(req.body.date_given).trim() : '';
        const administeredAt = req.body.administered_at ? String(req.body.administered_at).trim() : '';
        const notes = req.body.notes ? String(req.body.notes).trim() : '';

        if (!studentId || !vaccineId || !dateGiven) {
            setFlash(req, 'err', 'Student ID, Vaccine, and Date Given are required.');
            return res.redirect(`/registrar?student_id=${encodeURIComponent(studentId)}`);
        }

        const parsedDate = new Date(`${dateGiven}T00:00:00Z`);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dateGiven) || Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== dateGiven) {
            throw new UserError('Please enter a valid date.');
        }
        const todayPh = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
        if (dateGiven > todayPh) throw new UserError('Date given cannot be in the future.');

        client = await pool.connect();
        await client.query('BEGIN');

        const vRes = await client.query('SELECT * FROM vaccine_types WHERE id = $1', [vaccineId]);
        if (vRes.rows.length === 0) throw new UserError('Invalid vaccine type.');
        const vaccine = vRes.rows[0];

        const lastDoseRes = await client.query(`
            SELECT *, to_char(date_given, 'YYYY-MM-DD') AS date_str FROM student_vaccinations 
            WHERE student_id = $1 AND vaccine_id = $2 AND voided_at IS NULL
            ORDER BY cycle_number DESC, dose_number DESC LIMIT 1
        `, [studentId, vaccineId]);

        let nextDoseNum = 1;
        let cycleNum = 1;

        if (lastDoseRes.rows.length > 0) {
            const last = lastDoseRes.rows[0];
            const lastDateStr = last.date_str;

            if (dateGiven < lastDateStr) {
                throw new UserError(`The date cannot be earlier than the previous dose (${lastDateStr}).`);
            }

            // Check if series expired past 30-day grace period
            const targetDueStr = getNextDoseRequiredDate(vaccine.name, last.dose_number, lastDateStr);
            const deadlineStr = addDaysYmd(targetDueStr, 30);

            if (dateGiven > deadlineStr && vaccine.restart_when_expired && last.dose_number < vaccine.doses_required) {
                cycleNum = last.cycle_number + 1;
                nextDoseNum = 1;
            } else if (last.dose_number < vaccine.doses_required) {
                nextDoseNum = last.dose_number + 1;
                cycleNum = last.cycle_number;
            } else {
                cycleNum = last.cycle_number + 1;
                nextDoseNum = 1;
            }
        }

        await client.query(`
            INSERT INTO student_vaccinations (student_id, vaccine_id, dose_number, cycle_number, date_given, administered_at, recorded_by, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [studentId, vaccineId, nextDoseNum, cycleNum, dateGiven, administeredAt, req.session.user.username, notes]);

        await client.query(
            'INSERT INTO immunization_access_logs (student_id, accessed_by, action_type) VALUES ($1, $2, $3)',
            [studentId, req.session.user.username, 'EDIT']
        );

        await client.query('COMMIT');
        setFlash(req, 'msg', `Successfully recorded Dose ${nextDoseNum} for ${vaccine.name}.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(studentId)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Record vaccine error:', err);
        const backId = String(req.body.student_id || '').trim();
        setFlash(req, 'err', err && err.code === '23505'
            ? 'That dose was already recorded. Please check the record.'
            : safeMsg(err, 'Failed to record vaccine dose.'));
        res.redirect(backId ? `/registrar?student_id=${encodeURIComponent(backId)}` : '/registrar');
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/void-vaccine', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    const studentId = req.body.student_id ? String(req.body.student_id).trim() : '';
    try {
        const doseId = parseInt(req.body.dose_id, 10);
        if (!studentId || !Number.isInteger(doseId)) throw new UserError('Invalid request.');

        client = await pool.connect();
        await client.query('BEGIN');

        const doseRes = await client.query(`
            SELECT d.id, d.vaccine_id, d.dose_number, d.cycle_number, v.name
            FROM student_vaccinations d JOIN vaccine_types v ON v.id = d.vaccine_id
            WHERE d.id = $1 AND d.student_id = $2 AND d.voided_at IS NULL
            FOR UPDATE OF d
        `, [doseId, studentId]);
        if (doseRes.rows.length === 0) throw new UserError('Dose record not found.');
        const dose = doseRes.rows[0];

        const newer = await client.query(`
            SELECT 1 FROM student_vaccinations
            WHERE student_id = $1 AND vaccine_id = $2 AND voided_at IS NULL
              AND (cycle_number > $3 OR (cycle_number = $3 AND dose_number > $4))
            LIMIT 1
        `, [studentId, dose.vaccine_id, dose.cycle_number, dose.dose_number]);
        if (newer.rows.length > 0) throw new UserError('Only the most recently recorded dose can be removed.');

        await client.query('UPDATE student_vaccinations SET voided_at = NOW(), voided_by = $1 WHERE id = $2', [req.session.user.username, doseId]);
        await client.query(
            'INSERT INTO immunization_access_logs (student_id, accessed_by, action_type) VALUES ($1, $2, $3)',
            [studentId, req.session.user.username, 'VOID']
        );

        await client.query('COMMIT');
        setFlash(req, 'msg', `Removed dose ${dose.dose_number} of ${dose.name}.`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Void vaccine error:', err);
        setFlash(req, 'err', safeMsg(err, 'Failed to remove the vaccine dose.'));
    } finally {
        if (client) client.release();
    }
    res.redirect(studentId ? `/registrar?student_id=${encodeURIComponent(studentId)}` : '/registrar');
});

app.post('/registrar/update-student-year-section', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const yr = Math.min(4, Math.max(1, parseInt(req.body.year_level, 10) || 1));
        const rawSec = String(req.body.section || '').trim().toUpperCase();
        const sec = ['A', 'B', 'C'].includes(rawSec) ? rawSec : 'A';
        
        const oldClassRes = await pool.query('SELECT year_level, section FROM students WHERE student_id = $1', [cleanId]);
        const updateRes = await pool.query(`
            UPDATE students SET year_level = $1, section = $2 WHERE student_id = $3
        `, [yr, sec, cleanId]);

        if (updateRes.rowCount === 0) {
            setFlash(req, 'err', 'Student record not found.');
        } else {
            const oldC = oldClassRes.rows[0] || {};
            await logSecurityEvent(cleanId, 'YEAR_SECTION_CHANGED', req.session.user.username, req.ip, `BSN${oldC.year_level}-${oldC.section || 'A'} to BSN${yr}-${sec}`);
            setFlash(req, 'msg', `Student class updated to BSN${yr} - ${sec}.`);
        }
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        console.error('Update class error:', err);
        setFlash(req, 'err', 'Failed to update Year Level and Section.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(String(req.body.student_id || '').trim())}`);
    }
});

app.post('/registrar/add-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const cleanUser = req.body.username ? String(req.body.username).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';
        const pass = req.body.temp_password && String(req.body.temp_password).trim() ? String(req.body.temp_password).trim() : generateSecurePassword();

        if (!cleanUser || !fName || !lName) {
            setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
            return res.redirect('/registrar');
        }

        client = await pool.connect();
        await client.query('BEGIN');
        const existing = await client.query('SELECT username FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            await client.query('ROLLBACK');
            setFlash(req, 'err', `Username '${cleanUser}' is already registered.`);
            return res.redirect('/registrar');
        }

        const hashedPassword = await bcrypt.hash(pass, BCRYPT_COST);
        await client.query(`
            INSERT INTO users (username, password_hash, role, first_name, middle_name, last_name, must_change_password, is_archived)
            VALUES ($1, $2, 'faculty', $3, $4, $5, TRUE, FALSE)
        `, [cleanUser, hashedPassword, fName, mName, lName]);

        if (req.body.course_codes) {
            const codes = [...new Set(Array.isArray(req.body.course_codes) ? req.body.course_codes : [req.body.course_codes])];
            for (let code of codes) {
                if (code && String(code).trim() !== '') {
                    await client.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2) ON CONFLICT DO NOTHING;
                    `, [cleanUser, String(code).trim()]);
                }
            }
        }

        await client.query('COMMIT');
        await logSecurityEvent(cleanUser, 'STAFF_CREATED', req.session.user.username, req.ip, 'faculty (registrar)');
        setFlash(req, 'msg', 'Faculty account created and assigned subjects saved.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Add faculty error:', err);
        setFlash(req, 'err', 'Error creating faculty account.');
        res.redirect('/registrar');
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const origUser = req.body.original_username ? String(req.body.original_username).trim() : '';
        const cleanUser = req.body.username ? String(req.body.username).trim() : '';
        const fName = req.body.first_name ? String(req.body.first_name).trim() : '';
        const mName = req.body.middle_name ? String(req.body.middle_name).trim() : '';
        const lName = req.body.last_name ? String(req.body.last_name).trim() : '';

        if (!origUser || !cleanUser || !fName || !lName) {
            setFlash(req, 'err', 'Username, First Name, and Last Name are required.');
            return res.redirect('/registrar');
        }

        client = await pool.connect();
        await client.query('BEGIN');
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

        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') {
            const hashedPassword = await bcrypt.hash(String(req.body.temp_password).trim(), BCRYPT_COST);
            await client.query(`
                UPDATE users SET password_hash = $1, must_change_password = TRUE, password_changed_at = NOW(), failed_login_attempts = 0, is_locked = FALSE, locked_at = NULL WHERE username = $2 AND role = 'faculty'
            `, [hashedPassword, cleanUser]);
        }

        await client.query(`DELETE FROM faculty_courses WHERE username = $1 OR username = $2`, [origUser, cleanUser]);
        if (req.body.course_codes) {
            const codes = [...new Set(Array.isArray(req.body.course_codes) ? req.body.course_codes : [req.body.course_codes])];
            for (let code of codes) {
                if (code && String(code).trim() !== '') {
                    await client.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2) ON CONFLICT DO NOTHING;
                    `, [cleanUser, code.trim()]);
                }
            }
        }

        await client.query('COMMIT');
        if (req.body.temp_password && String(req.body.temp_password).trim() !== '') await logSecurityEvent(cleanUser, 'PASSWORD_RESET', req.session.user.username);
        await logSecurityEvent(cleanUser, 'STAFF_UPDATED', req.session.user.username, req.ip, 'faculty profile / subjects (registrar)');
        setFlash(req, 'msg', 'Faculty profile updated.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Edit faculty error:', err);
        setFlash(req, 'err', 'Failed to update faculty profile.');
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(req.body.original_username)}`);
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/delete-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const username = req.body.username ? String(req.body.username).trim() : '';
    try {
        const delRes = await pool.query(`UPDATE users SET is_archived = TRUE WHERE username = $1 AND role = 'faculty'`, [username]);
        if (delRes.rowCount > 0) {
            await pool.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
            await logSecurityEvent(username, 'ACCOUNT_ARCHIVED', req.session.user.username, req.ip, 'faculty (registrar)');
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

    const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
    if (!cleanId) {
        setFlash(req, 'err', 'Invalid password reset request.');
        return res.redirect('/registrar');
    }

    try {
        const newPass = generateSecurePassword();
        const hashedPassword = await bcrypt.hash(newPass, BCRYPT_COST);
        const updateRes = await pool.query(`
            UPDATE users SET password_hash = $1, must_change_password = TRUE, password_changed_at = NOW(), failed_login_attempts = 0, is_locked = FALSE, locked_at = NULL 
            WHERE username = $2 AND role = 'student'
        `, [hashedPassword, cleanId]);

        if (updateRes.rowCount === 0) {
            setFlash(req, 'err', 'Student account not found.');
        } else {
            await logSecurityEvent(cleanId, 'PASSWORD_RESET', req.session.user.username);
            setFlash(req, 'msg', `Password reset for Student ID ${cleanId}. Temporary password (shown once): ${newPass}`);
        }
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    } catch (err) {
        console.error('Reset student password error:', err);
        setFlash(req, 'err', 'Failed to reset student password.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
    }
});

const SECURITY_EVENTS = ['ACCOUNT_LOCKED', 'PASSWORD_RESET_UNLOCK', 'PASSWORD_RESET', 'ADMIN_RECOVERY', 'ACCOUNT_ARCHIVED', 'ACCOUNT_RESTORED', 'ACCOUNT_DELETED', 'SETTINGS_CHANGED', 'FACULTY_LOCK_TOGGLED', 'YEAR_SECTION_CHANGED', 'STAFF_CREATED', 'STAFF_UPDATED', 'STUDENT_REGISTERED', 'BATCH_UPLOAD'];

app.get('/registrar/security-log', isAuthenticated, async (req, res) => {
    const role = req.session.user.role;
    if (role !== 'registrar' && role !== 'admin') return res.redirect('/portal');

    try {
        const q = req.query.q ? String(req.query.q).trim().slice(0, 100) : '';
        const eventFilter = SECURITY_EVENTS.includes(String(req.query.event || '')) ? String(req.query.event) : '';
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const PAGE_SIZE = 50;

        const conditions = [];
        const params = [];

        if (role !== 'admin') {
            params.push(['student', 'faculty']);
            conditions.push(`u.role = ANY($${params.length}::text[])`);
        }
        if (q) {
            params.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`);
            conditions.push(`l.username ILIKE $${params.length}`);
        }
        if (eventFilter) {
            params.push(eventFilter);
            conditions.push(`l.event = $${params.length}`);
        }
        const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

        const countRes = await pool.query(
            `SELECT COUNT(*) AS total FROM account_security_logs l LEFT JOIN users u ON u.username = l.username ${where}`,
            params
        );
        const total = parseInt(countRes.rows[0].total, 10);
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const safePage = Math.min(page, totalPages);

        const listParams = [...params, PAGE_SIZE, (safePage - 1) * PAGE_SIZE];
        const logRes = await pool.query(`
            SELECT l.id, l.username, l.event, l.performed_by, l.ip, l.details, l.created_at,
                   u.role, u.first_name, u.middle_name, u.last_name
            FROM account_security_logs l
            LEFT JOIN users u ON u.username = l.username
            ${where}
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        `, listParams);

        res.render('security_log', {
            currentUser: req.session.user,
            logs: logRes.rows,
            q: q,
            eventFilter: eventFilter,
            page: safePage,
            totalPages: totalPages,
            total: total
        });
    } catch (err) {
        console.error('Security log load error:', err);
        res.status(500).send('Unable to load the account security log.');
    }
});

const IMMUNIZATION_ACTIONS = ['VIEW', 'EDIT', 'VOID', 'RULES'];

app.get('/registrar/immunization-log', isAuthenticated, async (req, res) => {
    const role = req.session.user.role;
    if (role !== 'registrar' && role !== 'admin') return res.redirect('/portal');

    try {
        const q = req.query.q ? String(req.query.q).trim().slice(0, 100) : '';
        const actionFilter = IMMUNIZATION_ACTIONS.includes(String(req.query.action || '')) ? String(req.query.action) : '';
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const PAGE_SIZE = 50;

        const conditions = [];
        const params = [];
        if (q) {
            params.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`);
            conditions.push(`(l.student_id ILIKE $${params.length} OR l.accessed_by ILIKE $${params.length})`);
        }
        if (actionFilter) {
            params.push(actionFilter);
            conditions.push(`l.action_type = $${params.length}`);
        }
        const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

        const countRes = await pool.query(`SELECT COUNT(*) AS total FROM immunization_access_logs l ${where}`, params);
        const total = parseInt(countRes.rows[0].total, 10);
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const safePage = Math.min(page, totalPages);

        const logRes = await pool.query(`
            SELECT l.id, l.student_id, l.accessed_by, l.action_type, l.created_at,
                   s.first_name, s.middle_name, s.last_name
            FROM immunization_access_logs l
            LEFT JOIN students s ON s.student_id = l.student_id
            ${where}
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        `, [...params, PAGE_SIZE, (safePage - 1) * PAGE_SIZE]);

        res.render('immunization_log', {
            currentUser: req.session.user,
            logs: logRes.rows,
            q: q,
            actionFilter: actionFilter,
            page: safePage,
            totalPages: totalPages,
            total: total
        });
    } catch (err) {
        console.error('Immunization log load error:', err);
        res.status(500).send('Unable to load the immunization access log.');
    }
});

app.get('/registrar/grade-logs', isAuthenticated, async (req, res) => {
    const role = req.session.user.role;
    if (role !== 'registrar' && role !== 'admin') return res.redirect('/portal');

    try {
        const q = req.query.q ? String(req.query.q).trim().slice(0, 100) : '';
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const PAGE_SIZE = 50;
        const conditions = [];
        const params = [];

        if (q) {
            params.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`);
            conditions.push(`(student_id ILIKE $${params.length} OR course_code ILIKE $${params.length})`);
        }
        const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

        const countRes = await pool.query(`SELECT COUNT(*) AS total FROM grade_audit_logs ${where}`, params);
        const total = parseInt(countRes.rows[0].total, 10);
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const safePage = Math.min(page, totalPages);

        const listParams = [...params, PAGE_SIZE, (safePage - 1) * PAGE_SIZE];
        const logRes = await pool.query(`
            SELECT * FROM grade_audit_logs 
            ${where} 
            ORDER BY changed_at DESC, id DESC 
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        `, listParams);

        res.render('grade_logs', {
            currentUser: req.session.user,
            logs: logRes.rows,
            q: q,
            page: safePage,
            totalPages: totalPages,
            total: total
        });
    } catch (err) {
        console.error('Grade log load error:', err);
        res.status(500).send('Unable to load the grade audit log.');
    }
});

app.post('/registrar/unlock-account', isAuthenticated, async (req, res) => {
    const actorRole = req.session.user.role;
    if (actorRole !== 'registrar' && actorRole !== 'admin') return res.status(403).send('Access denied');

    try {
        const username = req.body.username ? String(req.body.username).trim() : '';
        const typedPass = req.body.temp_password ? String(req.body.temp_password).trim() : '';

        if (req.body.verified !== 'yes') {
            setFlash(req, 'err', 'Please confirm that you verified the person\'s identity before resetting the password.');
            return res.redirect('/registrar');
        }
        const allowedRoles = actorRole === 'admin' ? ['student', 'faculty', 'registrar'] : ['student', 'faculty'];

        const target = await pool.query(`
            SELECT username FROM users
            WHERE username = $1 AND COALESCE(is_archived, FALSE) = FALSE AND role = ANY($2::text[])
        `, [username, allowedRoles]);

        if (target.rows.length === 0) {
            setFlash(req, 'err', 'Account not found, or you are not allowed to reset it.');
            return res.redirect('/registrar');
        }

        const newPass = typedPass || generateSecurePassword();
        const hashedPassword = await bcrypt.hash(newPass, BCRYPT_COST);

        await pool.query(`
            UPDATE users
            SET password_hash = $1, must_change_password = TRUE, password_changed_at = NOW(),
                failed_login_attempts = 0, is_locked = FALSE, locked_at = NULL
            WHERE username = $2
        `, [hashedPassword, username]);

        await logSecurityEvent(username, 'PASSWORD_RESET_UNLOCK', req.session.user.username);

        setFlash(req, 'msg', typedPass
            ? `Account '${username}' unlocked. The user must change the temporary password at next login.`
            : `Account '${username}' unlocked. Temporary password (shown once, give it to the user in person): ${newPass}`);
        res.redirect('/registrar');
    } catch (err) {
        console.error('Unlock account error:', err);
        setFlash(req, 'err', 'Failed to unlock account.');
        res.redirect('/registrar');
    }
});

app.post('/registrar/add-single-course', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const courseCode = req.body.course_code ? String(req.body.course_code).trim() : '';
        const term = req.body.term ? String(req.body.term).trim() : '1';
        const targetAy = req.body.academic_year ? String(req.body.academic_year).trim() : '';

        if (!/^[1-8]$/.test(term)) throw new UserError('Invalid term.');
        if (!isValidAcademicYear(targetAy)) throw new UserError('Invalid academic year format.');

        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const currentAy = targetAy || settingsRes.rows[0].current_ay;

        const checkCourse = await pool.query('SELECT course_code FROM courses WHERE course_code = $1 AND COALESCE(is_active, TRUE) = TRUE', [courseCode]);
        if (checkCourse.rows.length === 0) {
            setFlash(req, 'err', `Subject ${courseCode} not found in active catalog.`);
            return res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}`);
        }

        const facUser = req.body.instructor ? String(req.body.instructor).trim() : '';
        let facFormalName = '';
        if (facUser) {
            const facRes = await pool.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
            if (facRes.rows.length > 0) {
                facFormalName = formatFormalFacultyName(facRes.rows[0]);
            } else {
                throw new UserError('Selected instructor is not a valid faculty account.');
            }
        }

        await pool.query(`
            INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year)
            VALUES ($1, $2, '', $3, $4, '', $5, $6)
            ON CONFLICT (student_id, course_code, academic_year, enrolled_term) 
            DO UPDATE SET instructor = COALESCE(NULLIF($3, ''), grades.instructor),
                          instructor_username = COALESCE(NULLIF($4, ''), grades.instructor_username);
        `, [cleanId, courseCode, facFormalName, facUser, term, currentAy]);

        setFlash(req, 'msg', `Subject ${courseCode} successfully enrolled for A.Y. ${currentAy}.`);
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(term)}&view_ay=${encodeURIComponent(currentAy)}`);
    } catch (err) {
        console.error('Add single course error:', err);
        setFlash(req, 'err', safeMsg(err, 'Could not enroll subject.'));
        res.redirect(req.body.student_id ? `/registrar?student_id=${encodeURIComponent(String(req.body.student_id).trim())}` : '/registrar');
    }
});

app.post('/registrar/update-grades-batch', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        const cleanId = req.body.student_id ? String(req.body.student_id).trim() : '';
        const enrolledTerm = req.body.enrolled_term ? String(req.body.enrolled_term).trim() : '';
        const academicYear = req.body.academic_year ? String(req.body.academic_year).trim() : '';
        const { course_codes, final_grades } = req.body;
        
        if (!/^[1-8]$/.test(enrolledTerm)) throw new UserError('Invalid term.');
        if (!isValidAcademicYear(academicYear)) throw new UserError('Invalid academic year format.');

        client = await pool.connect();
        await client.query('BEGIN');
        
        const codes = Array.isArray(course_codes) ? course_codes : (course_codes ? [course_codes] : []);
        const grades = Array.isArray(final_grades) ? final_grades : (final_grades !== undefined ? [final_grades] : []);

        if (grades.length > 0 && codes.length !== grades.length) {
            throw new UserError('The submitted grades did not match the subject list. Please reload the page and try again.');
        }

        for (let i = 0; i < codes.length; i++) {
            const code = codes[i];
            const cleanGrade = normalizeGrade(grades[i]);
            const computedRem = computeServerRemark(cleanGrade);
            const facUser = req.body[`instructor__${code}`] !== undefined ? String(req.body[`instructor__${code}`]).trim() : undefined;

            let facFormalName = undefined;
            if (facUser !== undefined && facUser !== '') {
                const facRes = await client.query(`SELECT first_name, middle_name, last_name FROM users WHERE username = $1 AND role = 'faculty'`, [facUser]);
                if (facRes.rows.length > 0) {
                    facFormalName = formatFormalFacultyName(facRes.rows[0]);
                } else {
                    throw new UserError('Selected instructor is not a valid faculty account.');
                }
            }

            if (code) {
                const existingRes = await client.query(`
                    SELECT final_grade, instructor, instructor_username FROM grades 
                    WHERE student_id = $1 AND course_code = $2 AND enrolled_term = $3 AND academic_year = $4
                `, [cleanId, code, enrolledTerm, academicYear]);

                if (existingRes.rows.length > 0) {
                    const oldGrade = existingRes.rows[0].final_grade || '';
                    const finalInst = facFormalName !== undefined ? facFormalName : existingRes.rows[0].instructor;
                    const finalInstUser = facUser !== undefined ? facUser : existingRes.rows[0].instructor_username;

                    await client.query(`
                        UPDATE grades 
                        SET final_grade = $1, instructor = $2, instructor_username = $3, remarks = $4 
                        WHERE student_id = $5 AND course_code = $6 AND enrolled_term = $7 AND academic_year = $8
                    `, [cleanGrade, finalInst, finalInstUser, computedRem, cleanId, code, enrolledTerm, academicYear]);

                    if (oldGrade !== cleanGrade) {
                        await client.query(`
                            INSERT INTO grade_audit_logs (changed_by, changed_by_role, student_id, course_code, academic_year, enrolled_term, old_grade, new_grade)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        `, [req.session.user.username, req.session.user.role, cleanId, code, academicYear, enrolledTerm, oldGrade, cleanGrade]);
                    }
                } else {
                    await client.query(`
                        INSERT INTO grades (student_id, course_code, final_grade, instructor, instructor_username, remarks, enrolled_term, academic_year) 
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT DO NOTHING
                    `, [cleanId, code, cleanGrade, facFormalName || '', facUser || '', computedRem, enrolledTerm, academicYear]);
                    
                    await client.query(`
                        INSERT INTO grade_audit_logs (changed_by, changed_by_role, student_id, course_code, academic_year, enrolled_term, old_grade, new_grade)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    `, [req.session.user.username, req.session.user.role, cleanId, code, academicYear, enrolledTerm, 'ENROLLED', cleanGrade]);
                }
            }
        }

        await client.query('COMMIT');
        setFlash(req, 'msg', 'Grades and records updated successfully.');
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(enrolledTerm)}&view_ay=${encodeURIComponent(academicYear)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Registrar update grades error:', err);
        setFlash(req, 'err', safeMsg(err, 'Failed to update grades.'));
        res.redirect(req.body.student_id ? `/registrar?student_id=${encodeURIComponent(String(req.body.student_id).trim())}` : '/registrar');
    } finally {
        if (client) client.release();
    }
});

app.post('/registrar/delete-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const cleanId = String(req.body.student_id || '').trim();
    const courseCode = String(req.body.course_code || '').trim();
    const term = String(req.body.term || '').trim();
    const ay = String(req.body.academic_year || '').trim();

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const gradeRes = await client.query(`
            SELECT * FROM grades
            WHERE student_id = $1 AND course_code = $2 AND enrolled_term = $3 AND academic_year = $4
            FOR UPDATE
        `, [cleanId, courseCode, term, ay]);

        if (gradeRes.rows.length > 0) {
            const oldGrade = gradeRes.rows[0].final_grade || '';
            await client.query('DELETE FROM grades WHERE id = $1', [gradeRes.rows[0].id]);
            await client.query(`
                INSERT INTO grade_audit_logs (changed_by, changed_by_role, student_id, course_code, academic_year, enrolled_term, old_grade, new_grade)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'DELETED')
            `, [req.session.user.username, req.session.user.role, cleanId, courseCode, ay, term, oldGrade]);
            await client.query('COMMIT');
            setFlash(req, 'msg', `Subject ${courseCode} removed from student record.`);
        } else {
            await client.query('ROLLBACK');
            setFlash(req, 'err', 'Subject record not found.');
        }
        res.redirect(`/registrar?student_id=${encodeURIComponent(cleanId)}&view_term=${encodeURIComponent(term)}&view_ay=${encodeURIComponent(ay)}`);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Delete grade error:', err);
        setFlash(req, 'err', 'Could not remove subject.');
        res.redirect('/registrar');
    } finally {
        if (client) client.release();
    }
});

async function getFacultyAssignedCourses(facultyUsername, facultyFullName, role) {
    if (role === 'admin') {
        const allC = await pool.query('SELECT course_code, descriptive_title, term_id FROM courses WHERE COALESCE(is_active, TRUE) = TRUE ORDER BY course_code');
        return allC.rows;
    }
    const facC = await pool.query(`
        SELECT DISTINCT c.course_code, c.descriptive_title, c.term_id
        FROM courses c
        LEFT JOIN faculty_courses fc ON fc.course_code = c.course_code AND fc.username = $1
        LEFT JOIN grades g ON g.course_code = c.course_code AND g.instructor_username = $1
        WHERE (fc.username = $1 OR g.instructor_username = $1)
          AND COALESCE(c.is_active, TRUE) = TRUE
        ORDER BY c.course_code
    `, [facultyUsername]);
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
        const selectedYearLevel = req.query.year_level ? String(req.query.year_level).trim() : '';
        const selectedSection = req.query.section ? String(req.query.section).trim().toUpperCase() : '';

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
                rosterQuery += ` AND g.instructor_username = $6`;
                rosterParams.push(facultyUsername);
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

app.post('/faculty/update-grades-sheet', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let client;
    try {
        client = await pool.connect();
        const settingsRes = await client.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        if (req.session.user.role === 'faculty' && systemSettings.faculty_portal_locked) {
            return req.session.destroy(() => {
                res.redirect('/?locked=1');
            });
        }

        const facultyUsername = req.session.user.username;
        const facUserRes = await client.query('SELECT first_name, middle_name, last_name FROM users WHERE username = $1', [facultyUsername]);
        const facUser = facUserRes.rows[0] || {};
        const facultyFullName = formatFormalFacultyName(facUser) || req.session.user.fullName || facultyUsername;

        const courseCode = req.body.course_code ? String(req.body.course_code).trim() : '';
        const yearLevel = parseInt(req.body.year_level, 10);
        const section = req.body.section ? String(req.body.section).trim().toUpperCase() : '';

        const assignedCourses = await getFacultyAssignedCourses(facultyUsername, facultyFullName, req.session.user.role);
        const isAssigned = assignedCourses.some(c => c.course_code === courseCode);
        if (!isAssigned || ![1, 2, 3, 4].includes(yearLevel) || !['A', 'B', 'C'].includes(section)) {
            setFlash(req, 'err', 'Unauthorized course or invalid class roster selection.');
            return res.redirect('/faculty/edit-grades');
        }

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
            rosterQuery += ` AND g.instructor_username = $6`;
            rosterParams.push(facultyUsername);
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
            if (!rosterEntry) continue;

            const cleanGrade = normalizeGrade(grades[i]);
            const computedRemark = computeServerRemark(cleanGrade);

            await client.query(`
                UPDATE grades 
                SET final_grade = $1, 
                    remarks = $2
                WHERE student_id = $3 AND course_code = $4 AND academic_year = $5 AND enrolled_term = $6
            `, [cleanGrade, computedRemark, sId, courseCode, systemSettings.current_ay, rosterEntry.enrolled_term]);

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
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Faculty batch grade update error:', err);
        setFlash(req, 'err', safeMsg(err, 'An error occurred while saving grades.'));
        res.redirect('/faculty/edit-grades');
    } finally {
        if (client) client.release();
    }
});

app.get('/portal', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    
    if (user.role === 'admin') return res.redirect('/admin');
    if (user.role === 'registrar') return res.redirect('/registrar');
    if (user.role === 'faculty') return res.redirect('/faculty/edit-grades');

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [user.username]);
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
            selectedTerm = ((parseInt(student.year_level || 1, 10) - 1) * 2 + parseInt(systemSettings.current_semester, 10)).toString();
        }

        const activeSystemTerm = ((parseInt(student.year_level || 1, 10) - 1) * 2 + parseInt(systemSettings.current_semester, 10)).toString();

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

function cleanupStaleTempFiles() {
    try {
        const dir = 'uploads';
        if (!fs.existsSync(dir)) return;
        const cutoff = Date.now() - 30 * 60 * 1000;
        for (const f of fs.readdirSync(dir)) {
            if (f.startsWith('.')) continue;
            const p = path.join(dir, f);
            try {
                const st = fs.statSync(p);
                if (st.isFile() && st.mtimeMs < cutoff) fs.unlinkSync(p);
            } catch (e) {}
        }
    } catch (err) {
        console.error('Temp file cleanup error:', err.message);
    }
}

app.use((req, res) => {
    res.status(404).send('Page not found. <a href="/">Back to the portal</a>');
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (res.headersSent) return next(err);
    res.status(500).send('Something went wrong. Please go back and try again. <a href="/">Back to the portal</a>');
});

async function startServer() {
    try {
        await seedDatabase();
        cleanupStaleTempFiles();
        setInterval(cleanupStaleTempFiles, 5 * 60 * 1000).unref();
        
        const PORT = process.env.PORT || 10000;
        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    } catch (err) {
        if (err.message !== "process.exit") console.error("Failed to start server:", err);
    }
}

startServer();