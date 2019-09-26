const passport = require('passport')
const TwitterStrategy = require('passport-twitter').Strategy
const User = require('../models/User')

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user)
  })
})

module.exports = (config) => {
  const {
    TWITTER_KEY,
    TWITTER_SECRET,
    KOALA_URI
  } = config

  if (TWITTER_KEY && TWITTER_SECRET) {
    passport.use(new TwitterStrategy({
      consumerKey: TWITTER_KEY,
      consumerSecret: TWITTER_SECRET,
      callbackURL: `${KOALA_URI}/auth/twitter/callback`,
      passReqToCallback: true
    }, (req, accessToken, tokenSecret, profile, done) => {
      if (req.user) {
        User.findOne({ twitter: profile.id }, (err, existingUser) => {
          if (err) { return done(err) }
          if (existingUser) {
            done(err, existingUser)
          } else {
            User.findById(req.user.id, (err, user) => {
              if (err) { return done(err) }
              user.twitter = profile.id
              user.tokens.push({ kind: 'twitter', accessToken, tokenSecret })
              user.save((err) => {
                done(err, user)
              })
            })
          }
        })
      } else {
        User.findOne({ twitter: profile.id }, (err, existingUser) => {
          if (err) { return done(err) }
          if (existingUser) {
            return done(null, existingUser)
          }
          const user = new User()
          user.twitter = profile.id
          user.username = `twitter-${profile.username.toLowerCase()}`
          user.tokens.push({ kind: 'twitter', accessToken, tokenSecret })
          user.save((err) => {
            done(err, user)
          })
        })
      }
    }))
  }
}
