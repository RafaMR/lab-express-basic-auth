const User = require('../models/user');

const deserializeUser = (req, res, next) => {
  const userId = req.session.userId;
  if (userId) {
    console.log(userId);
    User.findById(userId)
      .then((user) => {
        req.user = user;
        res.locals.user = user;
        next();
      })
      .catch((error) => {
        next(error);
      });
  } else {
    next();
  }
};

module.exports = deserializeUser;
