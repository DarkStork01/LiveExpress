const { error } = require('console');
const express = require('express');
const path = require('path');

//Create the Express App
const app = express();
const PORT = 3000;

const mysql = require('mysql2');
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'myappdb'

});

//adas
//ddsdsdsds
//asdsadasdasdasddsa asdasdasd
//sdasdas 
//Set our engine EJS
app.set('view engine', 'ejs');
app.set('views',path.join(__dirname, 'views'));

//Create our middleware
app.use(express.json());
app.use(express.urlencoded({extended: true}));

//Database/Storage
const users = [];

db.connect((err) =>{
    if(err){
        console.error('Database connection failed' + err.stack);
        return;
    }
    console.log('Connected to my Database! ')
});


//Getting Data from signup
app.post('/signup', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.render('signup', { error: 'Please fill in all fields.' });
    }

    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';

    db.query(checkUserQuery, [username], (err, result) => {
        if (err) {
            console.error('Error checking user in database:', err);
            return res.render('signup', { error: 'Database error. Please try again.' });
        }

        // Check if user exists
        if (result.length > 0) {
            return res.render('signup', { error: 'Username already taken.' });
        }

        // Insert new user into the database
        const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(insertUserQuery, [username, password], (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.render('signup', { error: 'Could not sign up user. Please try again.' });
            }

            console.log(`User created: ${username}`);
            res.redirect('/login');
        });
    });
});


app.post('/login', (req, res) =>{
    const { username, password} = req.body;

    const findUserQuery = 'SELECT * FROM users WHERE username = ? AND password = ?';

    db.query(findUserQuery, [username, password], (err, results) => {
    if (err) {
      console.error('Error retrieving user:', err);
      return res.render('login', { error: 'Database error.' });
    }

    // If results array is empty, it means credentials are invalid
    if (results.length === 0) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    console.log('User logged in: ${username}');
    res.redirect('/dashboard');
    });
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

//Logic to start the server
app.listen(PORT, () =>{
    console.log('Server running on Localhost:' + PORT);
});