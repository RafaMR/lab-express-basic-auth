const express = require('express');
const router = new express.Router();
const User = require('../models/user');
const bcryptjs = require('bcryptjs');
const routeGuard = require('../middlewares/route-guard');

router.get('/', (req, res, next) => {
  res.render('index');
});

///////******** ITERATION 1 *************////////

router.get('/signup', (req, res) => {
  res.render('signup_page');
});

//---------------------------
router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;

  if (password.length === 0 || username.length === 0) {
    return next(new Error('Please fill in all the fields'));
  }

  bcryptjs
    .hash(password, 10)
    .then((passwordHashAndSalt) => {
      return User.create({
        username,
        passwordHashAndSalt
      });
    })
    .then((user) => {
      req.session.userId = user._id;
      res.redirect('/');
    })
    .catch((error) => {
      next(error);
    });
});

//////*******  ITERATION 2 ********////////
router.get('/login', (req, res, next) => {
  res.render('login');
});
//------------------------
router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (password.length === 0 || username.length === 0) {
    return next(new Error('Please fill in all the fields'));
  }
  //make query to DB to get details of the user
  let user;
  User.findOne({ username })
    .then((doc) => {
      user = doc;
      if (user === null) {
        throw new Error('This username does not exist');
      } else {
        return bcryptjs.compare(password, user.passwordHashAndSalt);
      }
    })
    .then((comparisonResult) => {
      if (comparisonResult) {
        req.session.userId = user._id;
        res.redirect('/private');
      } else {
        throw new Error('Wrong password');
      }
    })
    .catch((error) => {
      next(error);
    });
});

////////// ********** ITERATION 3 ************ ///////////

router.get('/main', routeGuard, (req, res, next) => {
  res.render('main');
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

//////// ITERATION 5 ////////////////
router.get('/profile', routeGuard, (req, res, next) => {
  res.render('profile');
});

/////////// ITERATION 6 ///////////////

router.get('/profile/edit', routeGuard, (req, res, next) => {
  res.render('edit');
});

router.post('/profile/edit', (req, res, next) => {
  const { name } = req.body;

  User.findByIdAndUpdate(req.user._id, { name })
    .then(() => {
      res.redirect('/profile');
    })
    .catch((error) => next(error));
});

////////////// LOG OUT ADDED AS EXTRA //////////////

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

module.exports = router;
