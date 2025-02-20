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


const axios = require("axios"); 

const crypto = require('crypto');

// Encryption key (store this securely in environment variables)
const encryptionKey = process.env.ENCRYPTION_KEY || 'your-encryption-key-32-bytes-long'; // Must be 32 bytes for AES-256
const algorithm = 'aes-256-cbc';

// Function to encrypt data
function encrypt(text) {
  const iv = crypto.randomBytes(16); // Generate a random initialization vector
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(encryptionKey), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`; // Return IV and encrypted data
}

// Function to decrypt data
function decrypt(text) {
  if (!text || !text.includes(':')) return text;
  
  try {
    const [ivHex, encryptedData] = text.split(':');
    
    // Validate IV and encrypted data format
    if (!ivHex || !encryptedData) {
      return text;
    }

    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    // Silent error handling - just return original text
    // Only log if it's not the common IV or decrypt errors
    if (!error.code?.includes('ERR_CRYPTO_INVALID_IV') && 
        !error.code?.includes('ERR_OSSL_BAD_DECRYPT')) {
      console.error('Unexpected decryption error:', error);
    }
    return text;
  }
}

// Optional: Add a debug version of decrypt for development
function decryptWithLogging(text) {
  if (process.env.NODE_ENV === 'development') {
    console.log('Attempting to decrypt:', text);
  }
  return decrypt(text);
}


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

    // Encrypt sensitive data
    const encryptedEmail = encrypt(email);
    const encryptedUsername = encrypt(username);
    const encryptedRole = encrypt('free'); // Default role is 'free'

    // Insert user into the database
    const insertUserQuery = "INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)";
    db.query(insertUserQuery, [encryptedEmail, encryptedUsername, hashedPassword, encryptedRole], (err, result) => {
      if (err) {
        console.error("Error inserting user:", err);
        return res.render("signup", { error: "Could not sign up user." });
      }
      res.redirect("/login"); // Redirect after successful signup
    });

  } catch (err) {
    console.error("Error during signup:", err);
    res.render("signup", { error: "Something went wrong. Try again." });
  }

  logEvent('Signup', `New user signed up: ${username}`);
});



app.get('/login', (req, res) => {
  // Render the login page with empty error and message
  res.render('login', { error: null, message: null });
});

app.post('/login', async (req, res) => {
  try {
    // Destructure and rename the recaptcha response from the request body
    const { username, email, password, 'g-recaptcha-response': recaptchaToken } = req.body;

    
    // console.log('Request body:', req.body);
    // console.log('Recaptcha token:', recaptchaToken);

    // Check if recaptcha token exists
    if (!recaptchaToken) {
      console.log('No CAPTCHA token provided');
      return res.render('login', { 
        error: 'Please complete the CAPTCHA verification.', 
        message: null 
      });
    }

    // Verify reCAPTCHA
    try {
      const recaptchaVerification = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        null,
        {
          params: {
            secret: process.env.RECAPTCHA_SECRET_KEY,
            response: recaptchaToken
          }
        }
      );

      // console.log('CAPTCHA verification response:', recaptchaVerification.data);

      if (!recaptchaVerification.data.success) {
        return res.render('login', { 
          error: 'CAPTCHA verification failed. Please try again.', 
          message: null 
        });
      }
    } catch (captchaError) {
      console.error('CAPTCHA verification error:', captchaError);
      return res.render('login', { 
        error: 'Error verifying CAPTCHA. Please try again.', 
        message: null 
      });
    }

    // Proceed with login after CAPTCHA verification
    const identifier = sanitizeInput(username || email || "");
    const sanitizedPassword = sanitizeInput(password || "");

    // Find user in database
    const findUserQuery = 'SELECT * FROM users';
    db.query(findUserQuery, [], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.render('login', { error: 'Database error.', message: null });
      }

      // Find user by decrypting and comparing values
      let user = null;
      for (const result of results) {
        try {
          const decryptedUsername = decrypt(result.username);
          const decryptedEmail = decrypt(result.email);
          
          if (decryptedUsername === identifier || decryptedEmail === identifier) {
            user = result;
            break;
          }
        } catch (e) {
          console.error('Decryption error during search:', e);
          continue;
        }
      }

      if (!user) {
        return res.render('login', { error: 'Invalid credentials.', message: null });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(sanitizedPassword, user.password);
      if (!isPasswordValid) {
        return res.render('login', { error: 'Invalid credentials.', message: null });
      }

      // Create token with decrypted data
      const decryptedUser = {
        username: decrypt(user.username),
        role: decrypt(user.role)
      };

      const token = generateToken(decryptedUser);

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 3600000
      });

      logEvent('Login', `User logged in: ${decryptedUser.username}`);

      return res.redirect('/dashboard');
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.render('login', { error: 'An error occurred during login.', message: null });
  }
});


app.post("/upgrade", authenticateToken, (req, res) => {
  const { role } = req.body;
  // console.log("Upgrade Request Body:", req.body);

  // Verify the role is valid
  if (role !== "free" && role !== "premium") {
    return res.render("upgrade", {
      error: "Invalid role selected.",
      username: req.user.username,
      role: req.user.role,
      message: null
    });
  }

  // Find the user first
  const findUserQuery = 'SELECT * FROM users';
  db.query(findUserQuery, [], async (err, results) => {
    if (err) {
      console.error('Error finding user:', err);
      return res.render("upgrade", {
        error: "Database error.",
        username: req.user.username,
        role: req.user.role,
        message: null
      });
    }

    // Find user by decrypting usernames
    let user = null;
    for (const result of results) {
      try {
        const decryptedUsername = decrypt(result.username);
        if (decryptedUsername === req.user.username) {
          user = result;
          break;
        }
      } catch (e) {
        console.error('Error decrypting username during search:', e);
        continue;
      }
    }

    if (!user) {
      return res.render("upgrade", {
        error: "User not found.",
        username: req.user.username,
        role: req.user.role,
        message: null
      });
    }

    try {
      // Encrypt the new role
      const encryptedRole = encrypt(role);

      // Update the user's role
      const updateQuery = "UPDATE users SET role = ? WHERE id = ?";
      db.query(updateQuery, [encryptedRole, user.id], (updateErr, result) => {
        if (updateErr) {
          console.error("Error updating user role:", updateErr);
          return res.render("upgrade", {
            error: "Could not update role.",
            username: req.user.username,
            role: req.user.role,
            message: null
          });
        }

        // Generate new token with updated role
        const updatedUser = { 
          username: req.user.username, 
          role: role 
        };
        const newToken = generateToken(updatedUser);

        // Set the new token in the cookie
        res.cookie("token", newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 3600000
        });

        logEvent("Role Change", `User ${req.user.username} changed role to ${role}.`);

        return res.render("upgrade", {
          message: `Your role has been updated to ${role}.`,
          username: req.user.username,
          role: role,
          error: null
        });
      });
    } catch (error) {
      console.error("Error during role update:", error);
      return res.render("upgrade", {
        error: "Error updating role.",
        username: req.user.username,
        role: req.user.role,
        message: null
      });
    }
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
  // Get all users and find the matching one after decryption
  const findUserQuery = 'SELECT * FROM users';
  db.query(findUserQuery, [], (err, results) => {
    if (err) {
      console.error('Error retrieving users:', err);
      return res.render('dashboard', { 
        error: 'Database error.', 
        username: req.user.username,
        role: 'unknown',
        email: '',
        userId: '',
        createdAt: '',
        message: null
      });
    }

    // Find user by decrypting usernames
    let user = null;
    for (const result of results) {
      try {
        const decryptedUsername = decrypt(result.username);
        if (decryptedUsername === req.user.username) {
          user = result;
          break;
        }
      } catch (e) {
        console.error('Error decrypting username during search:', e);
        continue;
      }
    }

    if (!user) {
      return res.render('dashboard', { 
        error: 'User not found.', 
        username: req.user.username,
        role: 'unknown',
        email: '',
        userId: '',
        createdAt: '',
        message: null
      });
    }

    try {
      // Decrypt user data
      const decryptedUser = {
        id: user.id,
        username: decrypt(user.username),
        email: decrypt(user.email),
        role: decrypt(user.role),
        created_at: user.created_at
      };

      return res.render('dashboard', {
        username: decryptedUser.username,
        role: decryptedUser.role,
        userId: decryptedUser.id,
        email: decryptedUser.email,
        createdAt: decryptedUser.created_at,
        error: null,
        message: null
      });

    } catch (error) {
      console.error('Error processing user data:', error);
      return res.render('dashboard', { 
        error: 'Error loading user data', 
        username: req.user.username,
        role: 'unknown',
        email: '',
        userId: '',
        createdAt: '',
        message: null
      });
    }
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
  console.log(`Serving static files from: ${path.join(__dirname, 'public')}`);

});

