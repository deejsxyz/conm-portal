require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const upload = multer({ dest: 'uploads/' });

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

function formatFullName(first, middle, last, fallback) {
    const parts = [first, middle, last].map(p => (p || '').trim()).filter(Boolean);
    return parts.length > 0 ? parts.join(' ') : fallback;
}

async function seedDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS courses (
                course_code VARCHAR(50) PRIMARY KEY,
                descriptive_title VARCHAR(255) NOT NULL,
                lec_units INT DEFAULT 0,
                rle_units INT DEFAULT 0,
                total_units INT DEFAULT 0,
                term_id INT NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS faculty_courses (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                course_code VARCHAR(50) NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS grades (
                id SERIAL PRIMARY KEY,
                student_id VARCHAR(100),
                student_number VARCHAR(100),
                course_code VARCHAR(50),
                final_grade VARCHAR(50),
                instructor VARCHAR(100),
                remarks VARCHAR(50)
            );
        `);

        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS course_code VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS final_grade VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS instructor VARCHAR(100);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS remarks VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS student_id VARCHAR(100);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS enrolled_term VARCHAR(10);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS academic_year VARCHAR(20) DEFAULT '2026-2027';`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                id INT PRIMARY KEY,
                current_ay VARCHAR(20),
                current_semester INT
            );
        `);
        await pool.query(`
            INSERT INTO settings (id, current_ay, current_semester) 
            VALUES (1, '2026-2027', 1) 
            ON CONFLICT (id) DO NOTHING;
        `);

        await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;`);
        await pool.query(`ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'faculty', 'student', 'registrar'));`);

        const adminPassword = await bcrypt.hash('admin2026', 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, first_name, last_name) 
            VALUES ('admin', $1, 'admin', 'System', 'Administrator')
            ON CONFLICT (username) DO NOTHING;
        `, [adminPassword]);

        const registrarPassword = await bcrypt.hash('registrar2026', 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) 
            VALUES ('registrar', $1, 'registrar', 'CONM', 'Registrar', FALSE)
            ON CONFLICT (username) 
            DO UPDATE SET password_hash = $1, role = 'registrar', must_change_password = FALSE;
        `, [registrarPassword]);

        // EXACT 24 OFFICIAL CONM SUBJECTS CATALOG
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
        await pool.query(`DELETE FROM courses WHERE course_code <> ALL($1::text[])`, [validCodes]);

        for (let c of conmCourses) {
            await pool.query(`
                INSERT INTO courses (course_code, descriptive_title, lec_units, rle_units, total_units, term_id) 
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (course_code) 
                DO UPDATE SET descriptive_title = $2, lec_units = $3, rle_units = $4, total_units = $5, term_id = $6;
            `, c);
        }

        console.log("Database strictly restricted to the 24 official CONM subjects.");
    } catch (err) {
        console.error("Seeding notice:", err.message);
    }
}

function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/');
}

app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/portal');
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userQuery.rows.length === 0) {
            return res.render('login', { error: 'Invalid username or password.' });
        }

        const user = userQuery.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.render('login', { error: 'Invalid username or password.' });
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

        req.session.user = { 
            username: user.username, 
            role: user.role, 
            fullName: fullName,
            mustChangePassword: user.must_change_password 
        };

        if (user.must_change_password) {
            return res.redirect('/change-password');
        }

        if (user.role === 'admin') {
            return res.redirect('/admin');
        } else if (user.role === 'registrar') {
            return res.redirect('/registrar');
        } else if (user.role === 'faculty') {
            return res.redirect('/faculty/edit-grades');
        } else {
            return res.redirect('/portal');
        }
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Database error occurred.' });
    }
});

app.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change_password', { error: null });
});

app.post('/change-password', isAuthenticated, async (req, res) => {
    const { new_password } = req.body;
    
    const isValid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(new_password);
    if (!isValid) {
        return res.render('change_password', { 
            error: 'Password must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters.' 
        });
    }

    try {
        const hashedNewPassword = await bcrypt.hash(new_password, 10);
        await pool.query(`
            UPDATE users 
            SET password_hash = $1, must_change_password = FALSE 
            WHERE username = $2
        `, [hashedNewPassword, req.session.user.username]);

        req.session.user.mustChangePassword = false;

        if (req.session.user.role === 'admin') {
            return res.redirect('/admin');
        } else if (req.session.user.role === 'registrar') {
            return res.redirect('/registrar');
        } else if (req.session.user.role === 'faculty') {
            return res.redirect('/faculty/edit-grades');
        } else {
            return res.redirect('/portal');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating password');
    }
});

// Admin Routes
app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.redirect('/portal');

    const selectedStaffUsername = req.query.staff_user ? req.query.staff_user.trim() : '';
    const searchStudentId = req.query.search_student_id ? req.query.search_student_id.trim() : '';

    try {
        const staffRes = await pool.query(`
            SELECT username, role, must_change_password, first_name, middle_name, last_name 
            FROM users 
            WHERE role IN ('faculty', 'registrar') 
            ORDER BY role DESC, last_name ASC, username ASC
        `);

        let selectedStaff = null;
        if (selectedStaffUsername) {
            selectedStaff = staffRes.rows.find(f => f.username === selectedStaffUsername) || null;
        }

        const countsRes = await pool.query(`
            SELECT year_level, COUNT(*) AS total 
            FROM students 
            GROUP BY year_level
        `);
        const yearCounts = { 1: 0, 2: 0, 3: 0, 4: 0 };
        countsRes.rows.forEach(r => {
            yearCounts[r.year_level] = parseInt(r.total, 10);
        });

        let searchedStudents = [];
        if (searchStudentId) {
            const stuSearchRes = await pool.query(`
                SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.program, s.year_level,
                       u.must_change_password
                FROM students s
                LEFT JOIN users u ON s.student_id = u.username
                WHERE s.student_id ILIKE $1
                ORDER BY s.student_id ASC
            `, [`%${searchStudentId}%`]);
            searchedStudents = stuSearchRes.rows;
        }

        res.render('admin', {
            currentUser: req.session.user,
            staffList: staffRes.rows,
            selectedStaff: selectedStaff,
            yearCounts: yearCounts,
            searchStudentId: searchStudentId,
            searchedStudents: searchedStudents,
            message: req.query.msg || null,
            error: req.query.err || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error loading admin dashboard');
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
    const pass = temp_password ? temp_password.trim() : (staffRole === 'registrar' ? 'registrar2026' : 'conm2026');

    if (!cleanUser || !fName || !lName) {
        return res.redirect('/admin?err=Username, First Name, and Last Name are required.');
    }

    try {
        const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            return res.redirect(`/admin?err=Error: The username '${cleanUser}' is already registered in the system.`);
        }

        const hashedPassword = await bcrypt.hash(pass, 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, $3, TRUE, $4, $5, $6)
        `, [cleanUser, hashedPassword, staffRole, fName, mName, lName]);

        res.redirect(`/admin?staff_user=${encodeURIComponent(cleanUser)}&msg=Staff account created successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect('/admin?err=Database error while creating staff account.');
    }
});

app.post('/admin/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, temp_password } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const pass = temp_password ? temp_password.trim() : 'password123';

    try {
        const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanId]);
        if (existing.rows.length > 0) {
            return res.redirect(`/admin?err=Error: The Student ID '${cleanId}' is already registered in the system.`);
        }

        const hashedPassword = await bcrypt.hash(pass, 10);

        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5)
        `, [cleanId, hashedPassword, fName, mName, lName]);

        await pool.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5)
        `, [cleanId, fName, mName, lName, year_level || 1]);

        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}&msg=Student account successfully created.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?err=Error adding new student: ${err.message}`);
    }
});

app.post('/admin/delete-user', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, role } = req.body;
    try {
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
        if (role === 'student') {
            await pool.query('DELETE FROM students WHERE student_id = $1', [username]);
            await pool.query('DELETE FROM grades WHERE student_id = $1', [username]);
        }
        if (role === 'faculty') {
            await pool.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
        }
        res.redirect('/admin?msg=User account successfully deleted.');
    } catch (err) {
        console.error(err);
        res.redirect('/admin?err=Failed to delete user account.');
    }
});

app.post('/admin/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { original_username, username, first_name, middle_name, last_name, temp_password } = req.body;
    const cleanUser = username.trim();
    
    try {
        await pool.query(`
            UPDATE users 
            SET username = $1, first_name = $2, middle_name = $3, last_name = $4
            WHERE username = $5
        `, [cleanUser, first_name.trim(), middle_name.trim(), last_name.trim(), original_username]);

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), 10);
            await pool.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE 
                WHERE username = $2
            `, [hashedPassword, cleanUser]);
        }

        res.redirect(`/admin?staff_user=${encodeURIComponent(cleanUser)}&msg=Staff profile updated successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?staff_user=${encodeURIComponent(original_username)}&err=Failed to update staff profile.`);
    }
});

app.post('/admin/edit-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, temp_password } = req.body;
    
    try {
        await pool.query(`
            UPDATE students 
            SET first_name = $1, middle_name = $2, last_name = $3, year_level = $4
            WHERE student_id = $5
        `, [first_name.trim(), middle_name.trim(), last_name.trim(), year_level, student_id]);

        await pool.query(`
            UPDATE users 
            SET first_name = $1, middle_name = $2, last_name = $3
            WHERE username = $4
        `, [first_name.trim(), middle_name.trim(), last_name.trim(), student_id]);

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), 10);
            await pool.query(`
                UPDATE users 
                SET password_hash = $1, must_change_password = TRUE 
                WHERE username = $2
            `, [hashedPassword, student_id]);
        }

        res.redirect(`/admin?search_student_id=${encodeURIComponent(student_id)}&msg=Student profile updated successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?search_student_id=${encodeURIComponent(student_id)}&err=Failed to update student profile.`);
    }
});

// Registrar Portal Routes
app.get('/registrar', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }

    const targetStudentId = req.query.student_id ? req.query.student_id.trim() : '';
    const selectedFacultyUser = req.query.faculty_user ? req.query.faculty_user.trim() : '';
    let selectedTerm = '1'; 

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        let student = null;
        let grades = [];
        let availableCourses = [];

        const allCoursesRes = await pool.query('SELECT * FROM courses ORDER BY term_id, course_code');
        const allCoursesRaw = allCoursesRes.rows;
        availableCourses = allCoursesRaw; 

        const facultyListRes = await pool.query(`
            SELECT username, first_name, middle_name, last_name 
            FROM users 
            WHERE role = 'faculty' 
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
            const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [targetStudentId]);
            student = studentRes.rows[0] || null;

            if (student) {
                selectedTerm = ((parseInt(student.year_level) - 1) * 2 + parseInt(systemSettings.current_semester)).toString();

                const gradesRes = await pool.query(`
                    SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, g.enrolled_term, g.academic_year,
                           c.descriptive_title, c.lec_units, c.rle_units, c.total_units
                    FROM grades g
                    JOIN courses c ON g.course_code = c.course_code
                    WHERE g.student_id = $1 AND g.enrolled_term = $2
                    ORDER BY g.course_code ASC
                `, [targetStudentId, selectedTerm]);
                grades = gradesRes.rows;
            }
        }

        res.render('registrar', {
            currentUser: req.session.user,
            systemSettings: systemSettings,
            selectedStudent: student,
            grades: grades,
            availableCourses: availableCourses,
            allCoursesRaw: allCoursesRaw,
            currentTerm: selectedTerm,
            facultyList: facultyList,
            selectedFaculty: selectedFaculty,
            facultyAssignedCourses: facultyAssignedCourses,
            hasBatchCredentials: !!req.session.lastBatchCredentials,
            message: req.query.msg || null,
            error: req.query.err || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send(`Error loading registrar dashboard: ${err.message}`);
    }
});

app.post('/registrar/update-settings', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    const { current_ay, current_semester } = req.body;
    try {
        await pool.query('UPDATE settings SET current_ay = $1, current_semester = $2 WHERE id = 1', [current_ay, current_semester]);
        res.redirect(`/registrar?msg=${encodeURIComponent('Active Academic Year and Semester updated successfully.')}`);
    } catch (err) {
        console.error(err);
        res.redirect('/registrar?err=Failed to update settings.');
    }
});

app.post('/registrar/batch-upload', isAuthenticated, upload.single('file'), (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const students = [];
    const generatedCredentials = [];
    
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (row) => {
            students.push(row);
        })
        .on('end', async () => {
            try {
                for (const student of students) {
                    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    const lower = 'abcdefghijklmnopqrstuvwxyz';
                    const num = '0123456789';
                    const special = '!@#$%^&*';
                    const all = upper + lower + num + special;
                    
                    let passArray = [
                        upper[Math.floor(Math.random() * upper.length)],
                        lower[Math.floor(Math.random() * lower.length)],
                        num[Math.floor(Math.random() * num.length)],
                        special[Math.floor(Math.random() * special.length)]
                    ];
                    
                    for (let i = 0; i < 4; i++) {
                        passArray.push(all[Math.floor(Math.random() * all.length)]);
                    }
                    
                    const tempPassword = passArray.sort(() => Math.random() - 0.5).join('');
                    const hashedPassword = await bcrypt.hash(tempPassword, 10);
                    
                    await pool.query(
                        `INSERT INTO users (username, password_hash, role, first_name, middle_name, last_name, must_change_password) 
                         VALUES ($1, $2, 'student', $3, $4, $5, TRUE) 
                         ON CONFLICT (username) DO NOTHING`,
                        [student.student_id, hashedPassword, student.first_name, student.middle_name, student.last_name]
                    );

                    await pool.query(
                        `INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level) 
                         VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5)
                         ON CONFLICT (student_id) DO NOTHING`,
                        [student.student_id, student.first_name, student.middle_name, student.last_name, student.year_level || 1]
                    );

                    if (student.year_level && student.semester && student.subjects && student.academic_year) {
                        const termId = (parseInt(student.year_level) - 1) * 2 + parseInt(student.semester);
                        const courseCodes = student.subjects.split(',').map(s => s.trim()).filter(s => s);
                        
                        for (const code of courseCodes) {
                            const instructorKey = `instructor_${code.replace(/\s+/g, '_')}`;
                            const assignedInstructor = student[instructorKey] || student.instructor || '';

                            await pool.query(
                                `INSERT INTO grades (student_id, course_code, final_grade, instructor, remarks, enrolled_term, academic_year) 
                                 VALUES ($1, $2, '', $3, '', $4, $5)
                                 ON CONFLICT (student_id, course_code) 
                                 DO UPDATE SET enrolled_term = $4, academic_year = $5, instructor = COALESCE(NULLIF($3, ''), grades.instructor);`,
                                [student.student_id, code, assignedInstructor, termId.toString(), student.academic_year]
                            );
                        }
                    }

                    generatedCredentials.push({
                        student_id: student.student_id,
                        name: `${student.last_name}, ${student.first_name} ${student.middle_name || ''}`.trim(),
                        temp_password: tempPassword
                    });
                }
                
                fs.unlinkSync(req.file.path);
                req.session.lastBatchCredentials = generatedCredentials;
                res.redirect(`/registrar?msg=${encodeURIComponent(students.length + ' students successfully registered and enrolled via Google Forms CSV!')}`);
                
            } catch (err) {
                console.error("Batch Upload Error:", err);
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                res.redirect('/registrar?err=Error processing batch upload. Ensure your CSV format is correct.');
            }
        });
});

app.get('/registrar/export-batch-credentials', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');
    
    const credentials = req.session.lastBatchCredentials;
    if (!credentials || credentials.length === 0) {
        return res.status(400).send('No recent batch upload credentials found in session.');
    }

    let csvHeader = 'Student ID,Student Name,Temporary Password\n';
    let csvRows = credentials.map(c => `"${c.student_id}","${c.name}","${c.temp_password}"`).join('\n');
    let csvContent = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="batch_temporary_passwords.csv"');
    res.status(200).send(csvContent);
});

app.post('/registrar/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level, term, academic_year, course_codes, instructors, temp_password } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const pass = temp_password ? temp_password.trim() : 'password123';

    try {
        const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanId]);
        if (existing.rows.length > 0) {
            return res.redirect(`/registrar?err=Error: The Student ID '${cleanId}' is already registered in the system.`);
        }

        const hashedPassword = await bcrypt.hash(pass, 10);

        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5)
        `, [cleanId, hashedPassword, fName, mName, lName]);

        await pool.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5)
        `, [cleanId, fName, mName, lName, year_level || 1]);

        if (term && course_codes && academic_year) {
            const codes = Array.isArray(course_codes) ? course_codes : [course_codes];
            const insts = Array.isArray(instructors) ? instructors : (instructors ? [instructors] : []);

            for (let i = 0; i < codes.length; i++) {
                const code = codes[i];
                const instructor = insts[i] || '';

                await pool.query(`
                    INSERT INTO grades (student_id, course_code, final_grade, instructor, remarks, enrolled_term, academic_year)
                    VALUES ($1, $2, '', $3, '', $4, $5)
                    ON CONFLICT (student_id, course_code) 
                    DO UPDATE SET enrolled_term = $4, academic_year = $5, instructor = $3;
                `, [cleanId, code, instructor, term, academic_year]);
            }
        }

        res.redirect(`/registrar?student_id=${cleanId}&msg=Student registered and officially enrolled in selected subjects with assigned instructors.`);
    } catch (err) {
        console.error(err);
        res.status(500).send(`Error adding new student: ${err.message}`);
    }
});

app.post('/registrar/add-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, first_name, middle_name, last_name, temp_password, course_codes } = req.body;
    const cleanUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';
    const pass = temp_password ? temp_password.trim() : 'conm2026';

    try {
        const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            return res.redirect(`/registrar?err=Error: The username '${cleanUser}' is already registered in the system.`);
        }

        const hashedPassword = await bcrypt.hash(pass, 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'faculty', TRUE, $3, $4, $5)
        `, [cleanUser, hashedPassword, fName, mName, lName]);

        if (course_codes) {
            const codes = Array.isArray(course_codes) ? course_codes : [course_codes];
            for (let code of codes) {
                if (code && code.trim() !== '') {
                    await pool.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2);
                    `, [cleanUser, code.trim()]);
                }
            }
        }

        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}&msg=Faculty account created and assigned subjects saved successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?err=Error adding faculty: ${err.message}`);
    }
});

app.post('/registrar/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { original_username, username, first_name, middle_name, last_name, temp_password, course_codes } = req.body;
    const cleanUser = username ? username.trim() : '';

    try {
        await pool.query(`
            UPDATE users 
            SET username = $1, first_name = $2, middle_name = $3, last_name = $4
            WHERE username = $5
        `, [cleanUser, first_name.trim(), middle_name.trim(), last_name.trim(), original_username]);

        if (cleanUser !== original_username) {
            await pool.query(`UPDATE faculty_courses SET username = $1 WHERE username = $2`, [cleanUser, original_username]);
        }

        if (temp_password && temp_password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(temp_password.trim(), 10);
            await pool.query(`
                UPDATE users SET password_hash = $1, must_change_password = TRUE WHERE username = $2
            `, [hashedPassword, cleanUser]);
        }

        await pool.query(`DELETE FROM faculty_courses WHERE username = $1`, [cleanUser]);
        if (course_codes) {
            const codes = Array.isArray(course_codes) ? course_codes : [course_codes];
            for (let code of codes) {
                if (code && code.trim() !== '') {
                    await pool.query(`
                        INSERT INTO faculty_courses (username, course_code) 
                        VALUES ($1, $2);
                    `, [cleanUser, code.trim()]);
                }
            }
        }

        res.redirect(`/registrar?faculty_user=${encodeURIComponent(cleanUser)}&msg=Faculty profile and assigned subjects updated successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?faculty_user=${encodeURIComponent(original_username)}&err=Failed to update faculty profile.`);
    }
});

app.post('/registrar/delete-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username } = req.body;
    try {
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
        await pool.query('DELETE FROM faculty_courses WHERE username = $1', [username]);
        res.redirect('/registrar?msg=Faculty account successfully deleted.');
    } catch (err) {
        console.error(err);
        res.redirect('/registrar?err=Failed to delete faculty account.');
    }
});

app.post('/registrar/reset-student-password', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, new_password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(new_password, 10);
        await pool.query(`
            UPDATE users SET password_hash = $1, must_change_password = TRUE 
            WHERE username = $2 AND role = 'student'
        `, [hashedPassword, student_id]);

        res.redirect(`/registrar?student_id=${student_id}&msg=Password successfully reset for ${student_id}.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?student_id=${student_id}&err=Failed to reset password.`);
    }
});

app.post('/registrar/add-single-course', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, course_code, term, instructor } = req.body;
    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];
        const currentAy = systemSettings.current_ay;

        await pool.query(`
            INSERT INTO grades (student_id, course_code, final_grade, instructor, remarks, enrolled_term, academic_year)
            VALUES ($1, $2, '', $3, '', $4, $5)
            ON CONFLICT (student_id, course_code) 
            DO UPDATE SET enrolled_term = $4, academic_year = $5, instructor = $3;
        `, [student_id, course_code, instructor || '', term, currentAy]);

        res.redirect(`/registrar?student_id=${student_id}&msg=Subject successfully enrolled with assigned instructor for A.Y. ${currentAy}.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?student_id=${student_id}&err=${encodeURIComponent(err.message)}`);
    }
});

app.post('/registrar/update-grades-batch', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, course_codes, final_grades, instructors, remarks_list } = req.body;
    
    try {
        const codes = Array.isArray(course_codes) ? course_codes : [course_codes];
        let grades = Array.isArray(final_grades) ? final_grades : [final_grades];
        const insts = Array.isArray(instructors) ? instructors : [instructors];
        const remarks = Array.isArray(remarks_list) ? remarks_list : [remarks_list];

        for (let i = 0; i < codes.length; i++) {
            const code = codes[i];
            let grade = grades[i] ? grades[i].trim() : '';
            
            if (/^\d+$/.test(grade)) {
                grade = `${grade}.00`;
            }

            const inst = insts[i] || '';
            const rem = remarks[i] || '';

            if (code) {
                await pool.query(`
                    UPDATE grades 
                    SET final_grade = $1, instructor = $2, remarks = $3 
                    WHERE student_id = $4 AND course_code = $5
                `, [grade, inst, rem, student_id, code]);
            }
        }

        res.redirect(`/registrar?student_id=${student_id}&msg=Grades and records updated successfully!`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?student_id=${student_id}&err=${encodeURIComponent(err.message)}`);
    }
});

app.post('/registrar/delete-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'registrar' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, course_code } = req.body;
    try {
        await pool.query(`
            DELETE FROM grades 
            WHERE student_id = $1 AND course_code = $2
        `, [student_id, course_code]);

        res.redirect(`/registrar?student_id=${student_id}&msg=Subject removed from student record.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/registrar?student_id=${student_id}&err=${encodeURIComponent(err.message)}`);
    }
});

// Faculty Portal Routes
app.get('/faculty/edit-grades', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }
    
    const facultyUsername = req.session.user.username;
    const facUserRes = await pool.query('SELECT first_name, middle_name, last_name FROM users WHERE username = $1', [facultyUsername]);
    const facUser = facUserRes.rows[0] || {};
    // Format strictly as LAST NAME, FIRST NAME MIDDLE NAME (no comma between first and middle)
    const facultyFullName = [facUser.last_name, [facUser.first_name, facUser.middle_name].filter(Boolean).join(' ')].filter(Boolean).join(', ');

    const rawCourseCode = req.query.course_code;
    const selectedCourse = Array.isArray(rawCourseCode) ? rawCourseCode[0].trim() : (rawCourseCode ? rawCourseCode.trim() : '');
    const searchLastName = req.query.last_name ? req.query.last_name.trim() : '';
    const searchFirstName = req.query.first_name ? req.query.first_name.trim() : '';
    const searchMiddleName = req.query.middle_name ? req.query.middle_name.trim() : '';

    try {
        const settingsRes = await pool.query('SELECT * FROM settings WHERE id = 1');
        const systemSettings = settingsRes.rows[0];

        let assignedCourses = [];
        if (req.session.user.role === 'admin') {
            const allC = await pool.query('SELECT course_code, descriptive_title FROM courses ORDER BY course_code');
            assignedCourses = allC.rows;
        } else {
            // FIX: Faculty dropdown now checks both assigned teaching loads AND subjects where students are actively enrolled under this instructor
            const facC = await pool.query(`
                SELECT DISTINCT c.course_code, c.descriptive_title 
                FROM courses c
                LEFT JOIN faculty_courses fc ON fc.course_code = c.course_code AND fc.username = $1
                LEFT JOIN grades g ON g.course_code = c.course_code AND g.instructor = $2
                WHERE fc.username = $1 OR g.instructor = $2
                ORDER BY c.course_code
            `, [facultyUsername, facultyFullName]);
            assignedCourses = facC.rows;
        }

        let matchingStudent = null;
        let gradeRecord = null;

        if (selectedCourse && searchLastName && searchFirstName && searchMiddleName) {
            const studentRes = await pool.query(`
                SELECT s.student_id, s.first_name, s.middle_name, s.last_name, s.year_level
                FROM students s
                WHERE s.last_name = $1 AND s.first_name = $2 AND s.middle_name = $3
            `, [searchLastName, searchFirstName, searchMiddleName]);

            if (studentRes.rows.length > 0) {
                matchingStudent = studentRes.rows[0];

                const validTerms = systemSettings.current_semester === 1 ? [1, 3, 5, 7] : [2, 4, 6, 8];
                
                let gradeQuery = `
                    SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, g.enrolled_term, g.academic_year,
                           c.descriptive_title
                    FROM grades g
                    JOIN courses c ON g.course_code = c.course_code
                    WHERE g.student_id = $1 
                      AND g.course_code = $2
                      AND g.academic_year = $3 
                      AND CAST(g.enrolled_term AS INTEGER) = ANY($4)
                `;
                let gradeParams = [matchingStudent.student_id, selectedCourse, systemSettings.current_ay, validTerms];

                if (req.session.user.role !== 'admin') {
                    gradeQuery += ` AND g.instructor = $5`;
                    gradeParams.push(facultyFullName);
                }

                const gradeRes = await pool.query(gradeQuery, gradeParams);
                if (gradeRes.rows.length > 0) {
                    gradeRecord = gradeRes.rows[0];
                }
            }
        }

        res.render('faculty_edit', {
            currentUser: req.session.user,
            systemSettings: systemSettings,
            assignedCourses: assignedCourses,
            selectedCourse: selectedCourse,
            searchLastName: searchLastName,
            searchFirstName: searchFirstName,
            searchMiddleName: searchMiddleName,
            matchingStudent: matchingStudent,
            gradeRecord: gradeRecord,
            message: req.query.msg || null,
            error: req.query.err || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send(`Error loading faculty editor: ${err.message}`);
    }
});

app.post('/faculty/update-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, course_code, academic_year, final_grade, instructor, remarks } = req.body;
    
    try {
        let cleanGrade = final_grade ? final_grade.trim() : '';
        if (/^\d+$/.test(cleanGrade)) {
            cleanGrade = `${cleanGrade}.00`;
        }

        await pool.query(`
            UPDATE grades 
            SET final_grade = $1, instructor = $2, remarks = $3 
            WHERE student_id = $4 AND course_code = $5 AND academic_year = $6
        `, [cleanGrade, instructor || '', remarks || '', student_id, course_code, academic_year]);

        res.redirect(`/faculty/edit-grades?course_code=${encodeURIComponent(course_code)}&msg=Grade updated successfully!`);
    } catch (err) {
        console.error(err);
        res.redirect(`/faculty/edit-grades?err=${encodeURIComponent(err.message)}`);
    }
});

// Portal Routes
app.get('/portal', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    
    if (user.role === 'admin') return res.redirect('/admin');
    if (user.role === 'registrar') return res.redirect('/registrar');
    if (user.role === 'faculty') return res.redirect('/faculty/edit-grades');

    const selectedTerm = req.query.term || '4';

    try {
        const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [user.username]);
        const student = studentRes.rows[0];

        const gradesRes = await pool.query(`
            SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, g.enrolled_term,
                   c.descriptive_title, c.lec_units, c.rle_units, c.total_units
            FROM grades g
            JOIN courses c ON g.course_code = c.course_code
            WHERE g.student_id = $1 AND g.enrolled_term = $2
        `, [user.username, selectedTerm]);

        res.render('portal', {
            currentUser: user,
            studentRecord: student,
            grades: gradesRes.rows,
            currentTerm: selectedTerm
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
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