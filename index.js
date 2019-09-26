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
const configurePassport = require('./passport')

/**
 * API keys and Passport configuration.
 */

module.exports = (config, apiDefinition) => {
  const {
    PORT,
    NODE_ENV,
    MONGO_URI,
    COUCH_URI,
    SESSION_SECRET,
    JWT_SECRET,
    APP_NAME,
    APP_ORIGIN,
    AUTH_PARTY,
  } = config

  /**
   * Create Express server.
   */
  const app = express()

  app.use(logger('dev'))
  app.use(cors({
    origin: APP_ORIGIN,
    credentials: true
  }))

  mongoose.connect(MONGO_URI)
  mongoose.connection.on('error', (err) => {
    console.error(err)
    console.log('%s MongoDB connection error. Please make sure MongoDB is running.')
    process.exit()
  })

  // set up passport/auth
  // we only use cookies/sessions for OAuth + passport - after that we are using JWTs
  configurePassport(config)
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
    const referrer = APP_ORIGIN
    res.redirectBack = (hashpoint) => {
      res.redirect(`${referrer}/#${hashpoint}`)
    }
    next()
  })

  /**
   * OAuth authentication routes. (Sign in)
   */
  const authCallback = (req, res, next) => {
    // create JSON web token for DB authentication later
    const dbName = `${APP_NAME}-${req.user.username}`
    const payload = {
      username: req.user.username,
      dbName
    }
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' })

    // attempt to create a database
    // if they don't have already (PUT is successful) this is a "signup"
    // if they have one (PUT fails) then this is a "login"
    popsicle.request({
      method: 'PUT',
      url: `${COUCH_URI}/${dbName}`,
    }).then(result => {
      const { status, body } = result
      if (status === 200 || status === 201) {
        res.redirectBack(`action=signup&username=${req.user.username}&token=${token}&dbName=${dbName}`)
      } else if (status === 412) {
        res.redirectBack(`action=login&username=${req.user.username}&token=${token}&dbName=${dbName}`)
      } else {
        res.status(status).send(body)
      }
    }).catch(next)
  }

  app.get('/auth/twitter', passport.authenticate('twitter'))
  app.get(
    '/auth/twitter/callback',
    passport.authenticate('twitter', { failureRedirect: '/auth/fail' }),
    authCallback
  )

  if (AUTH_PARTY) {
    app.get('/auth/party', (req, res, next) => {
      req.user = {
        username: 'authparty'
      }
      next()
    },
      authCallback
    )
  }

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
    } else if (user.dbName !== req.params.db) {
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
    console.log('Config: ', config)
    console.log('  Press CTRL-C to stop\n')
  })
}
