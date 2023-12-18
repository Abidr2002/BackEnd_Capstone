const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const argon2 = require("argon2");
const dotenv = require('dotenv');
const session = require("express-session");
const MemoryStore = require('memorystore')(session);

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const sessionSecret = process.env.SESSION_SECRET
const dbHost = process.env.DB_HOST
const dbUser = process.env.DB_USER 
const dbPassword = process.env.DB_PASSWORD
const dbName = process.env.DB_NAME 
const dbPort = process.env.DB_PORT 

const app = express();

app.set("trust proxy", 1)

app.use(express.json());

const corsOptions = {
    origin: ["http://localhost:5173", "https://fit-life-hub.vercel.app"],
    methods: ["POST", "GET"],
    credentials: true,
};

app.use(cors(corsOptions));

app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        // Handle CORS authorization error
        return res.status(401).json({ Error: 'Unauthorized CORS', Details: err.message });
    }
    next();
});

app.use(
  session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      store: new MemoryStore({
        checkPeriod: 86400000,
      }),
  })
);


const dbConfig = {
    host: dbHost,
    user: dbUser,
    password: dbPassword,
    database: dbName,
    port: dbPort
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect((err) => {
    if (err) {
      console.error('Error connecting to database:', err);
      // Mencoba menyambung kembali setelah penundaan
      setTimeout(handleDisconnect, 5000); // Misalnya, mencoba setiap 5 detik
      return;
    }
    console.log('Connected to database!');
  });

  db.on('error', (err) => {
    console.error('Database error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

handleDisconnect();

const verifyUser = (req, res, next) => {
  const sessionUser = req.session.user;
  if (!sessionUser) {
      return res.status(401).json({ Error: "Not Authenticated" });
  } else {
      req.username = sessionUser.username;
      req.userId = sessionUser.userId;
      next();
  }
};

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "Success", userId: req.userId, data: req.username });
});

app.post("/register", (req, res) => {
    const checkUsernameQuery = "SELECT * FROM account WHERE `username` = ?";
    const checkEmailQuery = "SELECT * FROM account WHERE `email` = ?";
    const insertUserQuery = "INSERT INTO account (`username`, `email`, `password`) VALUES (?)";

    db.query(checkUsernameQuery, [req.body.username], (err, usernameResult) => {
        if (err) {
            return res.status(500).json({ Error: "Error checking username existence", Details: err });
        }

        db.query(checkEmailQuery, [req.body.email], (err, emailResult) => {
            if (err) {
                return res.status(500).json({ Error: "Error checking email existence", Details: err });
            }

            if (usernameResult.length > 0 && emailResult.length > 0) {
                return res.status(400).json({ Error: "Username and Email already registered" });
            }

            if (usernameResult.length > 0) {
                return res.status(400).json({ Error: "Username already registered" });
            }

            if (emailResult.length > 0) {
                return res.status(400).json({ Error: "Email already registered" });
            }

            argon2.hash(req.body.password.toString()).then((hash) => {
                const formData = [req.body.username, req.body.email, hash];

                db.query(insertUserQuery, [formData], (err, result) => {
                    if (err) {
                        return res.status(500).json({ Error: "Error registering user", Details: err });
                    }
                    return res.status(201).json({ Status: "Success" });
                });
            });
        });
    });
});

app.post("/login", (req, res) => {
  const sql = "SELECT id, username, password FROM account WHERE username = ?";
  db.query(sql, [req.body.username], (err, data) => {
      if (err) {
          return res.status(500).json({ Error: "Login error in server", Details: err });
      }
      if (data.length > 0) {
          const hashedPassword = data[0].password;
          argon2.verify(hashedPassword, req.body.password.toString()).then((response) => {
              if (response) {
                  const userId = data[0].id;
                  const username = data[0].username;

                  req.session.user = { userId, username };

                  return res.status(200).json({ Status: "Success" });
              } else {
                  return res.status(401).json({ Error: "Wrong Password" });
              }
          });
      } else {
          return res.status(404).json({ Error: "Username not registered" });
      }
  });
});


app.post('/save-calc', verifyUser, (req, res) => {
    const { date, age, weight, height, bmi, calories, bodyWeight } = req.body;
    const sql = "INSERT INTO result (`id_user`, `date`, `age`, `weight`, `height`, `bmi`, `calories`, `ideal_weight`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    const values = [
        req.userId,
        date,
        age,
        weight,
        height,
        bmi,
        calories,
        bodyWeight
    ];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error("Error saving user data:", err);
            return res.status(500).json({ Error: "Error saving user data" });
        }
        return res.status(200).json({ Status: "Success" });
    });
});

app.get('/get-calc', verifyUser, (req, res) => {
    const userId = req.userId;
    const sql = "SELECT * FROM result WHERE id_user = ?";

    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error("Error fetching user data:", err);
            return res.status(500).json({ Error: "Error fetching user data" });
        }
        return res.status(200).json({ Status: "Success", userData: result });
    });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
      if (err) {
          console.error("Error destroying session:", err);
          return res.status(500).json({ Error: "Error during logout" });
      }

      res.clearCookie("connect.sid");

      return res.status(200).json({ Status: "Success" });
  });
});

const PORT = process.env.PORT || 8888;

app.listen(PORT, () => {
    console.log("Backend server is running on port", PORT);
});
