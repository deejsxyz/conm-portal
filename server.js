require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Helper to build a clean Full Name string
function formatFullName(first, middle, last, fallback) {
    const parts = [first, middle, last].map(p => (p || '').trim()).filter(Boolean);
    return parts.length > 0 ? parts.join(' ') : fallback;
}

// Database seed and initialization function
async function seedDatabase() {
    try {
        // Create courses table if it doesn't exist
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

        // Create or update grades table schema automatically
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

        // Ensure columns exist if grades table was pre-existing
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS course_code VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS final_grade VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS instructor VARCHAR(100);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS remarks VARCHAR(50);`);
        await pool.query(`ALTER TABLE grades ADD COLUMN IF NOT EXISTS student_id VARCHAR(100);`);

        // Seed default admin account if it doesn't exist
        const adminPassword = await bcrypt.hash('admin2026', 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, first_name, last_name) 
            VALUES ('admin', $1, 'admin', 'System', 'Administrator')
            ON CONFLICT (username) DO NOTHING;
        `, [adminPassword]);

        // Official BSN Curriculum Seed
        const allCourses = [
            // Term 1
            ['GEC 101', 'Understanding the Self', 3, 0, 3, 1],
            ['GEC 104', 'Mathematics in the Modern World', 3, 0, 3, 1],
            ['GEC 206', 'Art Appreciation', 3, 0, 3, 1],
            ['COR 101', 'Contemporary English', 3, 0, 3, 1],
            ['NCM 100', 'Theoretical Foundation of Nursing', 3, 0, 3, 1],
            ['MC 1', 'Anatomy and Physiology', 3, 2, 5, 1],
            ['MC2', 'Biochemistry', 3, 2, 5, 1],
            ['PHE 101', 'Wellness and Fitness', 2, 0, 2, 1],
            // Term 2
            ['GEC 105', 'Purposive Communication', 3, 0, 3, 2],
            ['GEC 108', 'Ethics', 3, 0, 3, 2],
            ['COR 102', 'Contemporary Mathematics', 3, 0, 3, 2],
            ['NCM 101', 'Health Assessment', 3, 2, 5, 2],
            ['NCM 102', 'Health Education', 3, 0, 3, 2],
            ['NCM 103', 'Fundamentals of Nursing Practice', 3, 2, 5, 2],
            ['MC3', 'Microbiology and Parasitology', 3, 1, 4, 2],
            ['PE 2', 'Self Defense', 2, 0, 2, 2],
            // Term 3
            ['NCM 104', 'Community Health Nursing 1', 3, 1, 4, 3],
            ['NCM 105', 'Nutrition and Diet Therapy', 3, 0, 3, 3],
            ['NCM 106', 'Pharmacology', 3, 0, 3, 3],
            ['NCM 107', 'Care of Mother, Child Adolescent (Well Clients)', 5, 4, 9, 3],
            ['NCM 108', 'Health Care Ethics (Bioethics)', 3, 0, 3, 3],
            ['NSTP 101', 'NSTP', 3, 0, 3, 3],
            ['PHE 3', 'Swimming', 2, 0, 2, 3],
            // Term 4
            ['GEC 102', 'Readings in Philippine History', 3, 0, 3, 4],
            ['GEC 107', 'Science, Technology, & Society', 3, 0, 3, 4],
            ['GEC E1', 'The Entrepreneurial Mind (Nursing Entrepreneurial)', 3, 0, 3, 4],
            ['NCM 110', 'Care of Mother, Child Adolescent (Acute and Chronic)', 6, 6, 12, 4],
            ['NSTP 102', 'NSTP', 3, 0, 3, 4],
            ['PHE 4', 'Sports', 2, 0, 2, 4],
            // Term 5
            ['NCM 111', 'Nursing Research 1', 3, 0, 3, 5],
            ['NCM 112', 'Care of Clients with Problems in Oxygenation, Fluid & Electrolytes, Infectious, Inflammatory, & Immunologic Response, Cellular Aberrations; Acute and Chronic', 8, 6, 14, 5],
            ['NCM 113', 'Community Health Nursing 2 (Population Group and Community Guide Clients)', 2, 1, 3, 5],
            ['NCM 114', 'Care of Older Adult', 2, 1, 3, 5],
            ['COR 104', 'Great Books and Philippine Popular Culture', 3, 0, 3, 5],
            // Term 6
            ['NCM 115', 'Nursing Research 2', 3, 0, 3, 6],
            ['NCM 116', 'Care of Clients with Problems in Nutrition & Gastro-Intestinal, Metabolism and Endocrine Perception & Coordination (Acute & Chronic)', 5, 4, 9, 6],
            ['NCM 117', 'Care of Clients with Maladaptive Patterns of Behavior (Acute & Chronic)', 4, 4, 8, 6],
            ['GEC E3', 'Elective 3-Nursing Personality Enhancement Program (NPEP)', 3, 0, 3, 6],
            // Term 7
            ['GEC 109', 'Life, Works, and Writings of Rizal', 3, 0, 3, 7],
            ['NCM 118', 'Nursing Care of Clients with Life Threatening Conditions, Acutely III/Multi-organs Problems, High Acuity & Emergency Situation, Acute & Chronic', 5, 4, 9, 7],
            ['NCM 119', 'Nursing Leadership & Management', 4, 3, 7, 7],
            ['CA 1', 'Course Audit 1', 3, 0, 3, 7],
            // Term 8
            ['GEC 103', 'The Contemporary World', 3, 0, 3, 8],
            ['NCM 121', 'Disaster Nursing', 2, 1, 3, 8],
            ['NCM 122', 'Intensive Nursing Practicum (Hospital and Community Settings)', 0, 8, 8, 8],
            ['CA 2', 'Course Audit 2', 3, 0, 3, 8]
        ];

        for (let c of allCourses) {
            await pool.query(`
                INSERT INTO courses (course_code, descriptive_title, lec_units, rle_units, total_units, term_id) 
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (course_code) DO NOTHING;
            `, c);
        }

        console.log("Database schema and seed data verified successfully.");
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
            res.redirect('/admin');
        } else if (req.session.user.role === 'faculty') {
            res.redirect('/faculty/edit-grades');
        } else {
            res.redirect('/portal');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating password');
    }
});

// Admin Routes
app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.redirect('/portal');

    const selectedFacultyUsername = req.query.faculty_user ? req.query.faculty_user.trim() : '';
    const searchStudentId = req.query.search_student_id ? req.query.search_student_id.trim() : '';

    try {
        const facultyRes = await pool.query(`
            SELECT username, role, must_change_password, first_name, middle_name, last_name 
            FROM users 
            WHERE role = 'faculty' 
            ORDER BY last_name ASC, username ASC
        `);

        let selectedFaculty = null;
        if (selectedFacultyUsername) {
            selectedFaculty = facultyRes.rows.find(f => f.username === selectedFacultyUsername) || null;
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
            facultyList: facultyRes.rows,
            selectedFaculty: selectedFaculty,
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

app.post('/admin/add-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, first_name, middle_name, last_name, temp_password } = req.body;
    const cleanUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    if (!cleanUser || !fName || !lName || !temp_password) {
        return res.redirect('/admin?err=Username, First Name, Last Name, and Temporary Password are required.');
    }

    try {
        const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUser]);
        if (existing.rows.length > 0) {
            return res.redirect('/admin?err=Username already exists.');
        }

        const hashedPassword = await bcrypt.hash(temp_password, 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'faculty', TRUE, $3, $4, $5)
        `, [cleanUser, hashedPassword, fName, mName, lName]);

        res.redirect(`/admin?faculty_user=${encodeURIComponent(cleanUser)}&msg=Faculty account created successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect('/admin?err=Database error while creating faculty.');
    }
});

app.post('/admin/edit-faculty', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { original_username, username, first_name, middle_name, last_name } = req.body;
    const origUser = original_username ? original_username.trim() : '';
    const newUser = username ? username.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    try {
        if (origUser !== newUser) {
            const check = await pool.query('SELECT 1 FROM users WHERE username = $1', [newUser]);
            if (check.rows.length > 0) {
                return res.redirect(`/admin?faculty_user=${encodeURIComponent(origUser)}&err=Username already taken.`);
            }
        }

        await pool.query(`
            UPDATE users 
            SET username = $1, first_name = $2, middle_name = $3, last_name = $4
            WHERE username = $5 AND role = 'faculty'
        `, [newUser, fName, mName, lName, origUser]);

        res.redirect(`/admin?faculty_user=${encodeURIComponent(newUser)}&msg=Faculty profile updated successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?faculty_user=${encodeURIComponent(origUser)}&err=Error updating faculty details.`);
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
        const hashedPassword = await bcrypt.hash(pass, 10);
        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5)
            ON CONFLICT (username) DO NOTHING;
        `, [cleanId, hashedPassword, fName, mName, lName]);

        await pool.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5)
            ON CONFLICT (student_id) DO NOTHING;
        `, [cleanId, fName, mName, lName, year_level || 1]);

        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}&msg=Student created successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?err=${encodeURIComponent(err.message)}`);
    }
});

app.post('/admin/edit-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    try {
        await pool.query(`
            UPDATE students 
            SET student_number = $1, first_name = $2, middle_name = $3, last_name = $4, year_level = $5
            WHERE student_id = $6
        `, [cleanId, fName, mName, lName, year_level, cleanId]);

        await pool.query(`
            UPDATE users 
            SET first_name = $1, middle_name = $2, last_name = $3
            WHERE username = $4 AND role = 'student'
        `, [fName, mName, lName, cleanId]);

        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}&msg=Student record updated.`);
    } catch (err) {
        console.error(err);
        res.redirect(`/admin?search_student_id=${encodeURIComponent(cleanId)}&err=Error updating student record.`);
    }
});

app.post('/admin/reset-user-password', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, role } = req.body;
    const defaultPass = role === 'faculty' ? 'conm2026' : 'password123';
    const redirectQuery = role === 'faculty' ? `faculty_user=${encodeURIComponent(username)}&` : `search_student_id=${encodeURIComponent(username)}&`;

    try {
        const defaultHash = await bcrypt.hash(defaultPass, 10);
        await pool.query(`
            UPDATE users 
            SET password_hash = $1, must_change_password = TRUE 
            WHERE username = $2
        `, [defaultHash, username]);

        res.redirect(`/admin?${redirectQuery}msg=Password reset successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect('/admin?err=Failed to reset password.');
    }
});

app.post('/admin/delete-user', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { username, role } = req.body;
    try {
        if (role === 'student') {
            await pool.query(`DELETE FROM grades WHERE student_id = $1`, [username]);
            await pool.query(`DELETE FROM students WHERE student_id = $1`, [username]);
        }
        await pool.query(`DELETE FROM users WHERE username = $1`, [username]);
        res.redirect(`/admin?msg=Account removed successfully.`);
    } catch (err) {
        console.error(err);
        res.redirect('/admin?err=Failed to delete account.');
    }
});

// Student & Faculty Portal Routes
app.get('/portal', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    
    if (user.role === 'admin') return res.redirect('/admin');
    if (user.role === 'faculty') return res.redirect('/faculty/edit-grades');

    const selectedTerm = req.query.term || '4';

    try {
        const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [user.username]);
        const student = studentRes.rows[0];

        const gradesRes = await pool.query(`
            SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, 
                   c.descriptive_title, c.lec_units, c.rle_units, c.total_units
            FROM grades g
            JOIN courses c ON g.course_code = c.course_code
            WHERE g.student_id = $1 AND c.term_id = $2
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

app.get('/faculty/edit-grades', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') {
        return res.redirect('/portal');
    }
    
    const targetStudentId = req.query.student_id ? req.query.student_id.trim() : '';
    const selectedTerm = req.query.term || '4';

    try {
        let student = null;
        let grades = [];

        const coursesRes = await pool.query('SELECT * FROM courses WHERE term_id = $1', [selectedTerm]);
        const availableCourses = coursesRes.rows;

        if (targetStudentId) {
            const studentRes = await pool.query('SELECT * FROM students WHERE student_id = $1', [targetStudentId]);
            student = studentRes.rows[0] || null;

            if (student) {
                const gradesRes = await pool.query(`
                    SELECT g.id, g.course_code, g.final_grade, g.instructor, g.remarks, 
                           c.descriptive_title, c.lec_units, c.rle_units, c.total_units
                    FROM grades g
                    JOIN courses c ON g.course_code = c.course_code
                    WHERE g.student_id = $1 AND c.term_id = $2
                `, [targetStudentId, selectedTerm]);
                grades = gradesRes.rows;
            }
        }

        res.render('faculty_edit', {
            currentUser: req.session.user,
            selectedStudent: student,
            grades: grades,
            availableCourses: availableCourses,
            currentTerm: selectedTerm
        });
    } catch (err) {
        console.error(err);
        res.status(500).send(`Error loading faculty editor: ${err.message}`);
    }
});

app.post('/faculty/add-student', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, first_name, middle_name, last_name, year_level } = req.body;
    const cleanId = student_id ? student_id.trim() : '';
    const fName = first_name ? first_name.trim() : '';
    const mName = middle_name ? middle_name.trim() : '';
    const lName = last_name ? last_name.trim() : '';

    try {
        const defaultPasswordHash = await bcrypt.hash('password123', 10);

        await pool.query(`
            INSERT INTO users (username, password_hash, role, must_change_password, first_name, middle_name, last_name) 
            VALUES ($1, $2, 'student', TRUE, $3, $4, $5)
            ON CONFLICT (username) DO NOTHING;
        `, [cleanId, defaultPasswordHash, fName, mName, lName]);

        await pool.query(`
            INSERT INTO students (student_id, student_number, first_name, middle_name, last_name, program, year_level) 
            VALUES ($1, $1, $2, $3, $4, 'Bachelor of Science in Nursing (BSN)', $5)
            ON CONFLICT (student_id) DO NOTHING;
        `, [cleanId, fName, mName, lName, year_level || 1]);

        res.redirect(`/faculty/edit-grades?student_id=${cleanId}`);
    } catch (err) {
        console.error(err);
        res.status(500).send(`Error adding new student: ${err.message}`);
    }
});

app.post('/faculty/add-single-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    let { student_id, course_code, final_grade, instructor, term } = req.body;
    
    final_grade = final_grade.trim();
    if (/^\d+$/.test(final_grade)) {
        final_grade = `${final_grade}.00`;
    }

    try {
        const numGrade = parseFloat(final_grade);
        const remarks = (numGrade && numGrade <= 3.00) ? 'PASSED' : 'FAILED';

        await pool.query(`
            INSERT INTO grades (student_id, course_code, final_grade, instructor, remarks)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (student_id, course_code) 
            DO UPDATE SET final_grade = $3, instructor = $4, remarks = $5;
        `, [student_id, course_code, final_grade, instructor, remarks]);

        res.redirect(`/faculty/edit-grades?student_id=${student_id}&term=${term}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error assigning grade');
    }
});

app.post('/faculty/init-courses', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, term } = req.body;
    try {
        const termCourses = await pool.query('SELECT course_code FROM courses WHERE term_id = $1', [term]);
        
        for (let course of termCourses.rows) {
            await pool.query(`
                INSERT INTO grades (student_id, course_code, final_grade, instructor, remarks)
                VALUES ($1, $2, '1.50', $3, 'PASSED')
                ON CONFLICT (student_id, course_code) DO NOTHING;
            `, [student_id, course.course_code, req.session.user.fullName || 'TBD']);
        }

        res.redirect(`/faculty/edit-grades?student_id=${student_id}&term=${term}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error initializing courses');
    }
});

app.post('/faculty/update-grades-batch', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, term, course_codes, final_grades, instructors, remarks_list } = req.body;
    
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

            const inst = insts[i];
            const rem = remarks[i];

            if (code) {
                await pool.query(`
                    UPDATE grades 
                    SET final_grade = $1, instructor = $2, remarks = $3 
                    WHERE student_id = $4 AND course_code = $5
                `, [grade, inst, rem, student_id, code]);
            }
        }

        res.redirect(`/faculty/edit-grades?student_id=${student_id}&term=${term}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating grades batch');
    }
});

app.post('/faculty/delete-grade', isAuthenticated, async (req, res) => {
    if (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin') return res.status(403).send('Access denied');

    const { student_id, course_code, term } = req.body;
    try {
        await pool.query(`
            DELETE FROM grades 
            WHERE student_id = $1 AND course_code = $2
        `, [student_id, course_code]);

        res.redirect(`/faculty/edit-grades?student_id=${student_id}&term=${term}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting grade record');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// Secure Server Startup wrapped correctly in an async function
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