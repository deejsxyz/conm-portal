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

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

if (!process.env.SESSION_SECRET) {
    console.error('FATAL ERROR: SESSION_SECRET environment variable is missing.');
    process.exit(1);
}

const app = express();
const BCRYPT_COST = 12;
const BCRYPT_BATCH_COST = 10;
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;
const REGISTRAR_CONTACT = process.env.REGISTRAR_CONTACT ? ` (${process.env.REGISTRAR_CONTACT})` : '';

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_COST);
const unknownLoginFailures = new Map();
const UNKNOWN_TTL_MS = LOCKOUT_MINUTES * 60 * 1000;
const UNKNOWN_MAX_ENTRIES = 5000;

function unknownKey(name) { return String(name || '').toLowerCase().slice(0, 100); }

function isUnknownLocked(name) {
    const e = unknownLoginFailures.get(unknownKey(name));
    return !!e && (Date.now() - e.last) <= UNKNOWN_TTL_MS && e.count >= MAX_FAILED_LOGINS;
}

function recordUnknownFailure(name) {
    const key = unknownKey(name);
    const now = Date.now();
    let e = unknownLoginFailures.get(key);
    if (!e || (now - e.last) > UNKNOWN_TTL_MS) e = { count: 0, last: now };
    e.count += 1;
    e.last = now;
    unknownLoginFailures.delete(key);
    unknownLoginFailures.set(key, e);
    while (unknownLoginFailures.size > UNKNOWN_MAX_ENTRIES) {
        unknownLoginFailures.delete(unknownLoginFailures.keys().next().value);
    }
    return e.count;
}

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

app.use(express.urlencoded({ extended: false }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' 
        ? (process.env.PG_CA_CERT ? { ca: process.env.PG_CA_CERT } : { rejectUnauthorized: false })
        : false
});

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
        createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('login', {
            error: 'Too many failed login attempts. Please try again later.',
            popupMessage: null
        });
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
    let g = String(rawGrade).trim().toUpperCase();
    if (/^[1-5]$/.test(g)) g = `${g}.00`;
    if (ALLOWED_GRADES.includes(g)) return g;
    throw new Error(`Invalid grade value submitted: ${rawGrade}`);
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

async function logSecurityEvent(username, event, performedBy, ip) {
    try {
        await pool.query(
            'INSERT INTO account_security_logs (username, event, performed_by, ip) VALUES ($1, $2, $3, $4)',
            [username, event, performedBy, ip ? String(ip).slice(0, 64) : null]
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

async function isAuthenticated(req, res, next) {
    if (!req.session.user) return res.redirect('/');
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
        await pool.query(`ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'faculty', 'student', 'registrar'));`);
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

        await pool.query(`CREATE INDEX IF NOT EXISTS idx_grades_student_term ON grades (student_id, enrolled_term, academic_year);`);

        await pool.query(`DELETE FROM grades WHERE student_id NOT IN (SELECT student_id FROM students);`);
        await pool.query(`DELETE FROM grades WHERE course_code NOT IN (SELECT course_code FROM courses);`);
        await pool.query(`ALTER TABLE grades DROP CONSTRAINT IF EXISTS fk_grades_student;`);
        await pool.query(`ALTER TABLE grades ADD CONSTRAINT fk_grades_student FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE RESTRICT;`);
        await pool.query(`ALTER TABLE grades DROP CONSTRAINT IF EXISTS fk_grades_course;`);
        await pool.query(`ALTER TABLE grades ADD CONSTRAINT fk_grades_course FOREIGN KEY (course_code) REFERENCES courses(course_code) ON DELETE RESTRICT;`);

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
            const initAdminPass = process.env.INITIAL_ADMIN_PASSWORD || generateSecurePassword();
            const adminHash = await bcrypt.hash(initAdminPass, BCRYPT_COST);
            await pool.query(`
                INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
                VALUES ('admin', $1, 'admin', 'System', 'Administrator', TRUE)
                ON CONFLICT (username) DO NOTHING;
            `, [adminHash]);
            if (!process.env.INITIAL_ADMIN_PASSWORD) {
                console.log(`[BOOT SEED] Created 'admin' account. Temporary Password: ${initAdminPass}`);
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
                console.log(`[BOOT SEED] Created 'registrar' account. Temporary Password: ${initRegPass}`);
            }
        }

        console.log("Database schema verified and active.");
    } catch (err) {
        console.error("Critical database seeding error:", err);
        process.exit(1);
    }
}

app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/portal');
    res.render('login', { error: res.locals.error, popupMessage: null });
});

app.get('/registrar', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }

    try {
        const targetStudentId = req.query.student_id ? String(req.query.student_id).trim() : '';
        const selectedFacultyUser = req.query.faculty_user ? String(req.query.faculty_user).trim() : '';
        let selectedTerm = '1'; 

        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        let student = null;
        let grades = [];
        let selectedAy = req.query.view_ay ? String(req.query.view_ay).trim() : systemSettings.current_ay;

        const allCoursesRes = await pool.query('SELECT * FROM courses WHERE COALESCE(is_active, TRUE) = TRUE ORDER BY term_id, course_code');
        const allCoursesRaw = allCoursesRes.rows;

        const facultyListRes = await pool.query(`
            SELECT username, first_name, middle_name, last_name 
            FROM users 
            WHERE role = 'faculty' AND COALESCE(is_archived, FALSE) = FALSE
            ORDER BY last_name ASC, username ASC
        `);
        const facultyList = facultyListRes.rows;

        const lockedRoles = req.session.user.role === 'admin' ? ['student', 'faculty', 'registrar'] : ['student', 'faculty'];
        const lockedRes = await pool.query(`
            SELECT username, role, first_name, middle_name, last_name, locked_at
            FROM users
            WHERE COALESCE(is_locked, FALSE) = TRUE AND COALESCE(is_archived, FALSE) = FALSE AND role = ANY($1::text[])
            ORDER BY locked_at DESC NULLS LAST
        `, [lockedRoles]);

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
                const defaultTerm = ((parseInt(student.year_level, 10) - 1) * 2 + parseInt(systemSettings.current_semester, 10)).toString();
                selectedTerm = req.query.view_term && /^[1-8]$/.test(req.query.view_term) ? String(req.query.view_term) : defaultTerm;

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
            lockedAccounts: lockedRes.rows,
            selectedFaculty: selectedFaculty,
            facultyAssignedCourses: facultyAssignedCourses,
            hasBatchCredentials: Array.isArray(req.session.lastBatchCredentials) && req.session.lastBatchCredentials.length > 0
        });
    } catch (err) {
        console.error('Registrar route error:', err);
        res.status(500).send(`Internal Server Error: ${err.message}`);
    }
});

// Other required routes (login, portal, logout, etc.)
app.post('/login', loginLimiter, async (req, res) => {
    try {
        const username = req.body.username ? String(req.body.username).trim() : '';
        const password = req.body.password ? String(req.body.password) : '';
        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1 AND COALESCE(is_archived, FALSE) = FALSE', [username]);

        if (userQuery.rows.length === 0) {
            await bcrypt.compare(password, DUMMY_HASH);
            return res.status(401).render('login', { error: 'Invalid username or password.', popupMessage: null });
        }

        const user = userQuery.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).render('login', { error: 'Invalid username or password.', popupMessage: null });
        }

        req.session.regenerate(() => {
            req.session.user = { username: user.username, role: user.role, fullName: user.username, login_time: Date.now() };
            if (user.role === 'admin') return res.redirect('/admin');
            if (user.role === 'registrar') return res.redirect('/registrar');
            return res.redirect('/portal');
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).render('login', { error: 'Internal Server Error', popupMessage: null });
    }
});

app.get('/portal', isAuthenticated, (req, res) => {
    res.render('portal', { currentUser: req.session.user, studentRecord: {}, grades: [], systemSettings: { current_semester: 1, current_ay: '2026-2027' }, isOfficiallyEnrolled: true, currentTerm: '1' });
});

app.post('/logout', isAuthenticated, (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

async function startServer() {
    await seedDatabase();
    const PORT = process.env.PORT || 10000;
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}

startServer();