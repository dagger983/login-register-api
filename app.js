const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


const app = express();
const dbPath = path.join(__dirname, "login.db");
const secretKey =  "your-secret-key";

let db = null;

app.use(bodyParser.json());

const initializeDBandServer = async () => {
    try {
        db = new sqlite3.Database(dbPath);
        createTable();
        app.listen(process.env.PORT || 1406, () => {
            console.log("Server running on port", 1406);
        });
    } catch (e) {
        console.log(`DB_ERROR : ${e.message}`);
        process.exit(1);
    }
};

const createTable = () => {
    const createUserTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            age INTEGER,
            password TEXT,
            email TEXT UNIQUE
        )
    `;
    db.run(createUserTable, (err) => {
        if (err) {
            console.error("Error creating table:", err.message);
        } else {
            console.log("Users table created successfully");
        }
    });
};

initializeDBandServer();

// Register endpoint
app.post("/register", async (req, res) => {
    const { username, age, password, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const checkExistingUser = `SELECT * FROM users WHERE email = ? OR username = ?`;
        db.get(checkExistingUser, [email, username], async (err, row) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send("Internal Server Error");
            }
            if (row) {
                return res.status(400).send("Email or username already exists");
            } else {
                const insertUser = `INSERT INTO users (username, age, password, email) VALUES (?, ?, ?, ?)`;
                db.run(insertUser, [username, age, hashedPassword, email], (err) => {
                    if (err) {
                        console.error(err.message);
                        return res.status(500).send("Internal Server Error");
                    }
                    return res.status(201).send("User registered successfully");
                });
            }
        });
    } catch (error) {
        console.error("Error registering user:", error.message);
        return res.status(500).send("Internal Server Error");
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const getUser = `SELECT * FROM users WHERE username = ?`;

    try {
        db.get(getUser, [username], async (err, row) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send("Internal Server Error");
            }
            if (!row) {
                return res.status(400).send("Invalid Username or Password");
            } else {
                const passwordMatch = await bcrypt.compare(password, row.password);
                if (!passwordMatch) {
                    return res.status(400).send("Invalid Username or Password");
                }

                const token = jwt.sign({ id: row.id, username: row.username }, secretKey, { expiresIn: "1h" });
                return res.json({ token });
            }
        });
    } catch (error) {
        console.error("Error logging in user:", error.message);
        return res.status(500).send("Internal Server Error");
    }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send("Access Denied");
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            console.error(err.message);
            return res.status(403).send("Invalid Token");
        }
        req.user = decoded;
        next();
    });
};

// Protected route
app.get("/protected", verifyToken, (req, res) => {
    res.send("Protected Route Accessed");
});

// Start the server
