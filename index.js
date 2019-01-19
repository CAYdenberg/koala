/* eslint-disable no-console */

const session = require('express-session')
const express = require('express')
const logger = require('morgan')
const errorHandler = require('errorhandler')
const mongoose = require('mongoose')
const passport = require('passport')
const popsicle = require('popsicle')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const httpProxy = require('http-proxy')
const apiProxy = httpProxy.createProxyServer()
const bodyParser = require('body-parser')

const {
  PORT,
  NODE_ENV,
  MONGO_URI,
  COUCH_URI,
  SESSION_SECRET,
  JWT_SECRET,
  DEFAULT_REDIRECT
} = process.env

/**
 * API keys and Passport configuration.
 */
require('./passport')

module.exports = function(apiDefinition) {
  /**
   * Create Express server.
   */
  const app = express()

  app.use(logger('dev'))
  app.use(cors())

  mongoose.connect(MONGO_URI)
  mongoose.connection.on('error', (err) => {
    console.error(err)
    console.log('%s MongoDB connection error. Please make sure MongoDB is running.')
    process.exit()
  })

  // we only use cookies/sessions for OAuth + passport - after that we are using JWTs
  app.use(session({
    saveUninitialized: false,
    resave: false,
    secret: SESSION_SECRET,
    cookie: {
      maxAge: 60 * 1000, // one minute
    }
  }))
  app.use(passport.initialize())
  app.use(passport.session())

  /**
  /* AUTHENTICATION::
  */

  // on all auth routes, save a way to redirect back to the original http
  // referrer
  app.all('/auth*', (req, res, next) => {
    const referrer = DEFAULT_REDIRECT
    res.redirectBack = (hashpoint) => {
      res.redirect(`${referrer}/#${hashpoint}`)
    }
    next()
  })

  /**
   * OAuth authentication routes. (Sign in)
   */
  app.get('/auth/twitter', passport.authenticate('twitter'))
  app.get('/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/auth/fail' }), (req, res, next) => {
    // create JSON web token for DB authentication later
    const payload = {
      username: req.user.username
    }
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' })

    // attempt to create a database
    // if they don't have already (PUT is successful) this is a "signup"
    // if they have one (PUT fails) then this is a "login"
    popsicle.request({
      method: 'PUT',
      url: `${COUCH_URI}/${req.user.username}`,
    }).then(result => {
      const { status, body } = result
      if (status === 200 || status === 201) {
        res.redirectBack(`action=signup&username=${req.user.username}&token=${token}`)
      } else if (status === 412) {
        res.redirectBack(`action=login&username=${req.user.username}&token=${token}`)
      } else {
        res.status(status).send(body)
      }
    }).catch(next)
  })

  app.get('/auth/fail', (req, res) => {
    res.redirectBack('action=fail')
  })

  app.get('/auth/logout', (req, res) => {
    req.logout()
    res.redirectBack('action=logout')
  })

  if (apiDefinition) {
    let router = express.Router()
    app.use('/api', bodyParser.json())
    app.use('/api', apiDefinition(router))
  }

  /**
   * COUCHDB endpoints:
   */

  // restrict all Couch endpoints to the user who owns the database
  app.all('/:db*', (req, res, next) => {
    let user
    try {
      const token = req.headers['x-jwt']
      user = jwt.verify(token, JWT_SECRET)
    } catch (e) {
      return res.status(401).send()
    }

    if (!user || !user.username) {
      res.status(401).send()
    } else if (user.username !== req.params.db) {
      res.status(401).send()
    } else {
      next()
    }
  })

  app.all('*', (req, res) => {
    return apiProxy.web(req, res, { target: COUCH_URI })
  })

  /**
   * Error Handler.
   */
  if (NODE_ENV === 'development') {
    // only use in development
    app.use(errorHandler())
  } else {
    app.use((err, req, res, next) => {
      console.error(err)
      res.status(500).send('Server Error')
    })
  }

  /**
   * Start Express server.
   */
  app.listen(PORT, () => {
    console.log('App is running at http://localhost:%d in %s mode', PORT, NODE_ENV)
    console.log('  Press CTRL-C to stop\n')
  })
}
