const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    console.log("No token found."); // Debugging: Log missing token
    return res.status(401).redirect('/login');
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Invalid token:", err); // Debugging: Log invalid token
      return res.status(403).redirect('/login');
    }

    console.log("Token verified. User:", user); // Debugging: Log verified user
    req.user = user;
    next();
  });
}

module.exports = { authenticateToken }; 
