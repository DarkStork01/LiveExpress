const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    res.clearCookie('token');
    return res.redirect('/login');
  }
};

module.exports = { authenticateToken };