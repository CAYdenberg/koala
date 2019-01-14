const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  twitter: Number,
  tokens: Array,
})

const User = mongoose.model('User', userSchema)

module.exports = User
