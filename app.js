'use strict';

const path = require('path');
const express = require('express');
const createError = require('http-errors');
const logger = require('morgan');
const sassMiddleware = require('node-sass-middleware');
const serveFavicon = require('serve-favicon');
const baseRouter = require('./routes/base');
const deserializeUser = require('./middlewares/deserialize-user');
const hbs = require('hbs');

/////// Added by me //////////
const User = require('./models/user');
const expressSession = require('express-session');
const MongoStore = require('connect-mongo');
hbs.registerPartials(__dirname + '/views/partials');
///////////////////////////////

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(serveFavicon(path.join(__dirname, 'public/images', 'favicon.ico')));
app.use(
  sassMiddleware({
    src: path.join(__dirname, 'public/styles'),
    dest: path.join(__dirname, 'public/styles'),
    prefix: '/styles',
    outputStyle:
      process.env.NODE_ENV === 'development' ? 'expanded' : 'compressed',
    force: process.env.NODE_ENV === 'development',
    sourceMap: process.env.NODE_ENV === 'development'
  })
);
app.use(express.static(path.join(__dirname, 'public')));
app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));

////////////// Code added by me ///////////////////////
app.use(
  expressSession({
    secret: 'abcafsdfagfsafads',
    saveUninitialized: false,
    resave: false,
    cookie: {
      maxAge: 15 * 24 * 60 * 60 * 1000 // 15 days
    },
    store: MongoStore.create({
      mongoUrl: 'mongodb://localhost:27017/node-basic-authentication',
      ttl: 60 * 60 // 60 minutes before connection is refreshed
    })
  })
);

app.use(deserializeUser);

////////////// ------------------- //////////

app.use('/', baseRouter);

// Catch missing routes and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// Catch all error handler
app.use((error, req, res, next) => {
  // Set error information, with stack only available in development
  res.locals.message = error.message;
  res.locals.error = req.app.get('env') === 'development' ? error : {};
  res.status(error.status || 500);
  res.render('error');
});

module.exports = app;
