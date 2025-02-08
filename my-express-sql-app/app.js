const { error } = require('console');
const express = require('express');
const path = require('path');
const escapeHTML = require("escape-html");

//Create the Express App
const app = express();
const PORT = 3000;

const { authenticateToken } = require("./middleware/authMiddleware");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser")
require("dotenv").config();


const rateLimit = require("express-rate-limit");
// Limit users to 5 signups per 15 minutes per IP
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 2, // Limit each IP to 5 signup attempts per windowMs
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


//Set our engine EJS
app.set('view engine', 'ejs');
app.set('views',path.join(__dirname, 'views'));

//Create our middleware
app.use(express.json());
app.use(express.urlencoded({extended: true}));


app.use(express.static(path.join(__dirname, 'public')));

function sanitizeInput(str) {
  return escapeHTML(str.trim());
}


app.use(cookieParser()); // Enable cookie parsing middleware
// Function to generate JWT token
function generateToken(user) {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
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
    const insertUserQuery = "INSERT INTO users (email, username, password) VALUES (?, ?, ?)";
    db.query(insertUserQuery, [email, username, hashedPassword], (err, result) => {
    
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
  
});


app.post('/login', (req, res) => {
  let { email, username, password } = req.body;

  identifier = sanitizeInput(username || email);
  password = sanitizeInput(password);
  
  const findUserQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';

  db.query(findUserQuery, [ identifier, identifier], async (err, results) => {

    if (err) {
      console.error('Error retrieving user:', err);
      return res.render('login', { error: 'Database error.' });
    }

    // If results array is empty, it means credentials are invalid
    if (results.length === 0) {
      return res.render('login', { error: 'Invalid username/email or password.' });
    }
  
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password); // Compare password
  
    if (!isPasswordValid) {
      return res.render("login", { error: "Invalid username/email or password." });
    }
      
    // Generate JWT token
    const token = generateToken(user);
      
    res.cookie("token", token, {
      httpOnly: true, // Prevents JavaScript from accessing the cookie
      secure: false,  // Set `true` if using HTTPS
      maxAge: 3600000, // 1 hour
    });
    // Otherwise, login is successful
    console.log(`User logged in: ${username}`);
    // Redirect them to a "dashboard" page
    res.redirect('/dashboard');
  });
});

app.get("/dashboard", authenticateToken, (req, res) => {
  res.render("dashboard", { username: req.user.username }); 
});

app.get("/logout", (req, res) => {
  res.clearCookie("token"); // Remove the JWT cookie
  res.redirect("/login");
});

app.get('/signup', (req, res) =>{
    res.render('signup');
});

app.get('/login', (req,res) => {
    res.render('login');
});

app.get('/dashboard', (req,res) => {
    res.render('dashboard');
});

// //Logic to start the server
// app.listen(PORT, () =>{
//     console.log('Server running on Localhost:' + PORT);
// });

https.createServer(options, app).listen(PORT, () => {
  console.log('HTTPS Server running on https://localhost:' + PORT);
  console.log("Serving static files from: ${path.joiqn(__dirname, 'public')}");
  });

