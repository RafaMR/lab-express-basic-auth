const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  passwordHashAndSalt: {
    type: String,
    required: true
  },
  name: String
});

const User = mongoose.model('User', userSchema);

module.exports = User;
