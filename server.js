const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const path = require("path");
const session = require("express-session");

const app = express();

// Enable CORS if frontend is on a different port (not strictly needed here since we serve from same port)
app.use(cors());

// Middleware to parse JSON request bodies
app.use(express.json());

// Session Handling Middleware
// Used to store logged-in user session securely
app.use(session({
    secret: "college_enrollment_secret", // A secret key used to sign the session ID cookie
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve static files from the current directory, except HTML files
// We will manually handle HTML files to protect the dashboard
app.use(express.static(path.join(__dirname), { index: false }));

// 1. Create/connect to the SQLite database file "database.db"
const db = new sqlite3.Database("./database.db", (err) => {
    if (err) {
        console.error("Error opening database", err);
    } else {
        console.log("Connected to the SQLite database.");
    }
});

// Create 4 tables if they do not exist
db.serialize(() => {
    // New Table: users (for authentication)
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    `);

    // 1st Table: students
    db.run(`
        CREATE TABLE IF NOT EXISTS students (
            student_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    `);

    // 2nd Table: courses
    db.run(`
        CREATE TABLE IF NOT EXISTS courses (
            course_id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_name TEXT UNIQUE,
            capacity INTEGER DEFAULT 0
        )
    `);

    // 3rd Table: enrollments
    db.run(`
        CREATE TABLE IF NOT EXISTS enrollments (
            enrollment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            course_id INTEGER,
            FOREIGN KEY(student_id) REFERENCES students(student_id),
            FOREIGN KEY(course_id) REFERENCES courses(course_id),
            UNIQUE(student_id, course_id)
        )
    `);

    // 3. Insert sample data automatically
    // Using INSERT OR IGNORE to prevent duplicates when server is restarted multiple times
    
    // Insert default user 'admin' with password '1234'
    db.run(`INSERT OR IGNORE INTO users (user_id, username, password, role) VALUES (1, 'admin', '1234', 'admin')`);
    
    // Insert default user 'student1' with password '1234'
    db.run(`INSERT OR IGNORE INTO users (user_id, username, password, role) VALUES (2, 'student1', '1234', 'student')`);
    
    db.run(`INSERT OR IGNORE INTO students (student_id, name) VALUES (1, 'Arun')`);
    db.run(`INSERT OR IGNORE INTO courses (course_id, course_name, capacity) VALUES (1, 'DBMS', 2), (2, 'AI', 1), (3, 'ML', 3)`);
});

// Middleware to check authentication for protected routes
function isAuthenticated(req, res, next) {
    if (req.session.user_id) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized access. Please log in." });
    }
}

// Middleware to check if user is admin
function isAdmin(req, res, next) {
    if (req.session.user_id && req.session.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Access denied. Admin only." });
    }
}

// Middleware to check if user is student
function isStudent(req, res, next) {
    if (req.session.user_id && req.session.role === 'student') {
        next();
    } else {
        res.status(403).json({ error: "Access denied. Student only." });
    }
}

// Redirect root to login page
app.get("/", (req, res) => {
    res.redirect("/login.html");
});

// Serve login page
app.get("/login.html", (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});

// Serve dashboard page (Protected for students)
app.get("/dashboard.html", (req, res) => {
    if (req.session.user_id && req.session.role === 'student') {
        res.sendFile(path.join(__dirname, "dashboard.html"));
    } else {
        res.redirect("/login.html");
    }
});

// Serve admin page (Protected for admins)
app.get("/admin.html", (req, res) => {
    if (req.session.user_id && req.session.role === 'admin') {
        res.sendFile(path.join(__dirname, "admin.html"));
    } else {
        res.redirect("/login.html");
    }
});

// --- Authentication API Endpoints ---

// POST /login -> verify username & password
app.post("/login", (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ error: "Username, password, and role are required" });
    }

    // Verify credentials against the database
    db.get("SELECT * FROM users WHERE username = ? AND password = ? AND role = ?", [username, password, role], (err, row) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        
        if (row) {
            // Valid credentials: Store user details in session
            req.session.user_id = row.user_id;
            req.session.username = row.username;
            req.session.role = row.role;
            res.json({ success: true, message: "Login successful", role: row.role });
        } else {
            // Invalid credentials
            res.status(401).json({ error: "Invalid credentials or role" });
        }
    });
});

// POST /logout -> destroy session
app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: "Could not log out" });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ success: true, message: "Logged out successfully" });
    });
});

// API Endpoints

// GET /admin/courses -> return all courses for admin
app.get("/admin/courses", isAdmin, (req, res) => {
    const searchQuery = req.query.search;
    let query = `
        SELECT courses.course_id, courses.course_name, courses.capacity,
               COUNT(enrollments.enrollment_id) AS enrolled_count
        FROM courses
        LEFT JOIN enrollments ON courses.course_id = enrollments.course_id
    `;
    let params = [];

    if (searchQuery) {
        query += ` WHERE courses.course_name LIKE ?`;
        params.push(`%${searchQuery}%`);
    }

    query += ` GROUP BY courses.course_id`;

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// GET /courses -> return all courses
// Protected route: only accessible if user is logged in
app.get("/courses", isStudent, (req, res) => {
    const searchQuery = req.query.search;
    let query = `
        SELECT courses.course_id, courses.course_name, courses.capacity,
               COUNT(enrollments.enrollment_id) AS enrolled_count
        FROM courses
        LEFT JOIN enrollments ON courses.course_id = enrollments.course_id
    `;
    let params = [];

    // Filter by search query if provided
    if (searchQuery) {
        query += ` WHERE courses.course_name LIKE ?`;
        params.push(`%${searchQuery}%`);
    }

    query += ` GROUP BY courses.course_id`;

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// GET /my-courses -> return courses enrolled by the logged-in student (assuming student_id = 1)
app.get("/my-courses", isStudent, (req, res) => {
    const student_id = 1; // Assuming logged-in user is student_id = 1
    const query = `
        SELECT courses.course_id, courses.course_name, courses.capacity
        FROM enrollments
        JOIN courses ON enrollments.course_id = courses.course_id
        WHERE enrollments.student_id = ?
    `;
    db.all(query, [student_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// POST /add-course -> allow admin to add a new course
app.post("/add-course", isAdmin, (req, res) => {
    const { course_name, capacity } = req.body;

    if (!course_name || capacity === undefined) {
        return res.status(400).json({ error: "course_name and capacity are required" });
    }

    db.run(
        "INSERT INTO courses (course_name, capacity) VALUES (?, ?)",
        [course_name, capacity],
        function (err) {
            if (err) {
                // Handle unique constraint error
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: "Course already exists" });
                }
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, message: "Course added successfully" });
        }
    );
});

// POST /enroll -> enroll a student into a course
// Protected route: only accessible if user is logged in
app.post("/enroll", isStudent, (req, res) => {
    const { course_id } = req.body;
    // For simplicity, we use student_id 1 ('Arun') since there is no login logic for multiple students
    const student_id = 1;

    if (!course_id) {
        return res.status(400).json({ error: "course_id is required" });
    }

    // Check capacity first
    const capacityQuery = `
        SELECT courses.capacity, COUNT(enrollments.enrollment_id) AS enrolled_count
        FROM courses
        LEFT JOIN enrollments ON courses.course_id = enrollments.course_id
        WHERE courses.course_id = ?
        GROUP BY courses.course_id
    `;

    db.get(capacityQuery, [course_id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: "Database error checking capacity" });
        }
        if (!row) {
            return res.status(404).json({ error: "Course not found" });
        }

        if (row.enrolled_count >= row.capacity) {
            return res.status(400).json({ error: "Course Full" });
        }

        // Proceed to enroll
        db.run(
            "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)",
            [student_id, course_id],
            function (err) {
                if (err) {
                    // Check for duplicate enrollment (UNIQUE constraint)
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: "Already Enrolled" });
                    }
                    return res.status(500).json({ error: err.message });
                }
                res.json({ success: true, message: "Enrolled successfully" });
            }
        );
    });
});

// GET /enrollments -> show all enrollments with student name and course name (use JOIN)
// Protected route: only accessible if user is logged in
app.get("/enrollments", isAdmin, (req, res) => {
    // SQL JOIN to get student name and course name based on IDs
    const query = `
        SELECT enrollments.enrollment_id, students.name AS student_name, courses.course_name 
        FROM enrollments
        JOIN students ON enrollments.student_id = students.student_id
        JOIN courses ON enrollments.course_id = courses.course_id
    `;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// DELETE /course/:id -> allow admin to delete a course
app.delete("/course/:id", isAdmin, (req, res) => {
    const courseId = req.params.id;

    // First delete related enrollments
    db.run("DELETE FROM enrollments WHERE course_id = ?", [courseId], function(err) {
        if (err) {
            return res.status(500).json({ error: "Error deleting related enrollments" });
        }
        
        // Then delete the course
        db.run("DELETE FROM courses WHERE course_id = ?", [courseId], function(err) {
            if (err) {
                return res.status(500).json({ error: "Error deleting course" });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: "Course not found" });
            }
            res.json({ success: true, message: "Course deleted successfully" });
        });
    });
});

// Start the server
app.listen(3000, () => {
    console.log("Server running on port 3000");
    console.log("You can access the application at http://localhost:3000");
});