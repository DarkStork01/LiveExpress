const { error } = require('console');
const express = require('express');
const path = require('path');
const escapeHTML = require("escape-html");

//Create the Express App
const app = express();
const PORT = 3000;

const { authenticateToken } = require("./middleware/authMiddleware");

const jwt = require('jsonwebtoken');
const cookieParser = require("cookie-parser")
require("dotenv").config();


const rateLimit = require("express-rate-limit");
// Limit users to 5 signups per 15 minutes per IP
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 signup attempts per windowMs
  message: "Too many signup attempts from this IP, please try again later.",
  headers: true, // Send rate limit info in headers
});


const mysql = require('mysql2');
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'myappdb'

});



const fs = require("fs");
const https = require("https");

const options = {
  key: fs.readFileSync(path.join(__dirname, "config", "server.key")),
  cert: fs.readFileSync(path.join(__dirname, "config", "server.cert"))
};


const axios = require("axios"); ///!!!

//Set our engine EJS
app.set('view engine', 'ejs');
app.set('views',path.join(__dirname, 'views'));

//Create our middleware
app.use(express.json());
app.use(express.urlencoded({extended: true}));


app.use(express.static(path.join(__dirname, 'public')));

function sanitizeInput(str) {
  if (!str) return ""; // Return an empty string if `str` is undefined or null
  return escapeHTML(str.trim());
}

function logEvent(type, description) {
  // Format the current time as "YYYY-MM-DD HH:MM:SS" for MySQL
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  
  const insertLogQuery = 'INSERT INTO logs (type, description, time) VALUES (?, ?, ?)';
  db.query(insertLogQuery, [type, description, now], (err) => {
    if (err) {
      console.error('Error logging event:', err);
    }
  });
}


function generatePremiumToken() {
  const user = {
    username: "premiumUser", // Change to an actual username from your database
    role: "premium"
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1h" });

  console.log("Generated Premium Token:", token);
}

generatePremiumToken();

app.use(cookieParser()); // Enable cookie parsing middleware
// Function to generate JWT token
function generateToken(user) {
  return jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, {
  expiresIn: process.env.JWT_EXPIRES_IN, // Token expires in 1 hour
  });
};



//Database/Storage
const users = [];

db.connect((err) =>{
    if(err){
        console.error('Database connection failed' + err.stack);
        return;
    }
    console.log('Connected to my Database! ')
});


//Getting Data from signup method 2
const bcrypt = require("bcrypt"); // Import bcrypt for hashing


app.post("/signup", signupLimiter, async (req, res) => {
    let { email, username, password } = req.body;
    
  try {
    // **Hash the password before storing it**
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    // Store the sanitized username and **hashed password**
    const insertUserQuery = "INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)";

    db.query(insertUserQuery, [email, username, hashedPassword, 'free'], (err, result) => {
      if (err) {
        console.error("Error inserting user:", err);
        return res.render("signup", { error: "Could not sign up user." });
      }
      res.redirect("/login"); // Redirect after successful signup
    });

    
  } catch (err) {
    console.error("Hashing error:", err);
    res.render("signup", { error: "Something went wrong. Try again." });
  }

  //Instead of verifying the password with bcrypt, check if it's equal to the universal password
  // const universalPassword ='pwd';
  // if (password != universalPassword) {
  //   return res.status(401).send('Incorrect passwod')
  // }

  logEvent('Signup', `New user signed up: ${username}`);
});



app.get('/login', (req, res) => {
  // Render the login page with empty error and message
  res.render('login', { error: null, message: null });
});

app.post('/login', async (req, res) => {
  let { username, email, password, 'g-recaptcha-response': recaptchaResponse } = req.body;

  console.log("Login Request Body:", req.body); // Debugging: Log the request body

  // Sanitize inputs
  identifier = sanitizeInput(username || email || "");
  sanitizedPassword = sanitizeInput(password || "");

  console.log("Sanitized Identifier:", identifier); // Debugging: Log the sanitized email
  console.log("Sanitized Password:", sanitizedPassword); // Debugging: Log the sanitized password

  // Verify reCAPTCHA
  const recaptchaSecretKey = process.env.RECAPTCHA_SECRET_KEY;
  const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecretKey}&response=${recaptchaResponse}`;

  try {
    console.log("Verifying CAPTCHA..."); // Debugging: Log CAPTCHA verification start
    const recaptchaResult = await axios.post(recaptchaVerificationUrl);
    console.log("CAPTCHA Verification Result:", recaptchaResult.data); // Debugging: Log CAPTCHA result

    if (!recaptchaResult.data.success) {
      console.log("CAPTCHA verification failed."); // Debugging: Log CAPTCHA failure
      return res.render("login", { error: "CAPTCHA verification failed. Please try again.", message: null });
    }
  } catch (err) {
    console.error("Error verifying CAPTCHA:", err); // Debugging: Log CAPTCHA error
    return res.render("login", { error: "CAPTCHA verification failed. Please try again.", message: null });
  }

  // Proceed with login if CAPTCHA is valid
  const findUserQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(findUserQuery, [identifier, identifier], async (err, results) => {
    if (err) {
      console.error('Error retrieving user:', err); 
      return res.render('login', { error: 'Database error.', message: null });
    }

    if (results.length === 0) {
      console.log("User not found."); 
      return res.render('login', { error: 'Invalid email or password.', message: null });
    }

    const user = results[0];
    console.log("User found:", user); // Debugging: Log the retrieved user

    const isPasswordValid = await bcrypt.compare(sanitizedPassword, user.password);
    console.log("Password valid:", isPasswordValid); // Debugging: Log password validation result

    if (!isPasswordValid) {
      console.log("Invalid password."); // Debugging: Log invalid password
      return res.render("login", { error: "Invalid email or password.", message: null });
    }

    // Generate JWT token
    const token = generateToken(user);
    console.log("Generated Token:", token); // Debugging: Log the generated token

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000,
    });

    console.log(`User logged in: ${user.username}`); // Debugging: Log successful login
    res.redirect('/dashboard');
    logEvent('Login', `User logged in: ${user.username}`);
  });
});


app.post("/upgrade", authenticateToken, (req, res) => {
  const { role } = req.body; // Get the role from the form
  console.log("Upgrade Request Body:", req.body); // Debugging: Log the request body

  // Verify the role
  if (role !== "free" && role !== "premium") {
    console.log("Invalid role selected:", role); // Debugging: Log invalid role
    return res.render("upgrade", {
      error: "Invalid role selected.",
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
    });
  }

  // Update the user's role in the database
  const updateQuery = "UPDATE users SET role = ? WHERE username = ?";
  db.query(updateQuery, [role, req.user.username], (err, result) => {
    if (err) {
      console.error("Error updating user role:", err); // Debugging: Log database error
      return res.render("upgrade", {
        error: "Could not update role.",
        username: req.user.username,
        role: req.user.role,
      });
    }

    console.log("Role updated successfully:", result); // Debugging: Log successful update

    // Regenerate the JWT token with the updated role
    const updatedUser = { username: req.user.username, role: role };
    const newToken = generateToken(updatedUser);
    console.log("New Token Generated:", newToken); // Debugging: Log the new token

    // Set the new token in the cookie
    res.cookie("token", newToken, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000,
    });

    logEvent("Role Change", `User ${req.user.username} changed role to ${role}.`);

    res.render("upgrade", {
      message: `Your role has been updated to ${role}.`,
      username: req.user.username,
      role: role, // Pass the updated role to the template
    });
  });
});

app.get('/download/secret', authenticateToken, (req, res) => {

  if (req.user.role === 'premium') {

    const filePath = path.join(__dirname,'/public/images/secret.pdf' );
    res.download(filePath, 'Exclusive-Content.pdf', (err) => {
  
    if (err) {
      console.error('Error sending file:', err);
      res.status(500).send('Could not download the file.');
    }
  });
  
  } else {
  res.status(403).send('Access denied: Premium members only.');
  }  
  //Premium Access
  logEvent('Premium Access', `Premium resource accessed by: ${req.user.username}`);
});



app.get('/dashboard', authenticateToken, (req, res) => {
  const findUserQuery = 'SELECT id, username, email, role, created_at FROM users WHERE username = ?';
  db.query(findUserQuery, [req.user.username], (err, results) => {
    if (err) {
      console.error('Error retrieving user:', err);
      return res.render('dashboard', { error: 'Database error.', username: req.user.username });
    }

    if (results.length === 0) {
      return res.render('dashboard', { error: 'User not found.', username: req.user.username });
    }

    const user = results[0];
    console.log("User data:", user); // Debugging: Log the retrieved user data

    res.render('dashboard', {
      username: user.username,
      role: user.role,
      userId: user.id,
      email: user.email,
      createdAt: user.created_at, // Assuming your database has a `created_at` field
    });
  });
});


app.get("/upgrade", authenticateToken, (req, res) => {
  res.render("upgrade", { username: req.user.username, role: req.user.role });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token"); // Remove the JWT cookie
  res.redirect("/login");
});

app.get('/signup', (req, res) =>{
    res.render('signup');
});









https.createServer(options, app).listen(PORT, () => {
  console.log('HTTPS Server running on https://localhost:' + PORT);
  console.log("Serving static files from: ${path.joiqn(__dirname, 'public')}");
  });

