const routeGuard = (req, res, next) => {
  if (req.user) {
    next();
  } else {
    next(new Error('User is not authenticated.'));
  }
};

module.exports = routeGuard;
