import login from './routes/login.js'
import invitation from './routes/invitation.js'
import forgotPassword from './routes/forgotPassword.js'
import account from './routes/accounts.js'
import users from './routes/users.js'
import systemAdmins from './routes/systemAdmins.js'
import systemStats from './routes/stats.js'
import captchaHandler from './helpers/captcha.js'
import captcha from './routes/captcha.js'
import turnstileHandler from './helpers/turnstile.js'
import turnstile from './routes/turnstile.js'

import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { Strategy as MicrosoftStrategy } from 'passport-microsoft'

import { Strategy as GitHubStrategy } from 'passport-github'

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.API_URL}v1/accounts/provider/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    const user = { id: profile.id, email: profile.emails[0].value, name: `${profile.name.givenName} ${profile.name.familyName}`, profilePicture: profile.photos[0].value }
    done(null, user)
  }))
}
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.API_URL}v1/accounts/provider/github/callback`,
    scope: ['user:email', 'read:user']
  }, (accessToken, refreshToken, profile, done) => {
    let user
    if (profile.emails) {
      user = { id: profile.id, email: profile.emails[0].value, name: profile.displayName, profilePicture: profile.photos[0].value }
    }
    done(null, user)
  }))
}
if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  passport.use(new MicrosoftStrategy({
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL: 'http://localhost:10002/v1/accounts/provider/microsoft/callback',
    scope: ['openid', 'profile', 'email', 'user.read']
  },
  (req, iss, sub, profile, accessToken, refreshToken, done) => {
    const user = { id: profile.id, email: profile.emails[0].value, name: profile.displayName, profilePicture: profile.photos[0].value }
    return done(null, user)
  }))
}

function validateModel (model, name, requiredPaths) {
  if (!model) {
    throw new Error(`mua-backend: ${name} is required but was not provided.`)
  }
  if (!model.schema) {
    throw new Error(`mua-backend: ${name} does not appear to be a valid Mongoose model.`)
  }
  for (const path of requiredPaths) {
    if (!model.schema.path(path)) {
      throw new Error(`mua-backend: ${name} is missing required schema field "${path}".`)
    }
  }
}

export default ({
  apiServer, UserModel, AccountModel, SystemAdminModel, ProjectModel, hooks =
  {
    checkEmail: async (params) => {},
    deleteAccount: { post: (params) => { } },
    createAccount: { post: (params) => { } },
    createNewUser: { post: (params) => { } },
    updateUserEmail: { post: (params) => { } }
  }
}) => {
  validateModel(AccountModel, 'AccountModel', ['name', 'urlFriendlyName', 'logo', 'deleted'])
  validateModel(UserModel, 'UserModel', ['email', 'password', 'role', 'accountId', 'verified', 'deleted', 'twoFactor.enabled', 'twoFactor.secret', 'twoFactor.recoverySecret'])
  validateModel(SystemAdminModel, 'SystemAdminModel', ['email', 'password', 'twoFactor.enabled', 'twoFactor.secret', 'twoFactor.recoverySecret'])

  systemAdmins({ apiServer, SystemAdminModel })
  users({ apiServer, UserModel, AccountModel, ProjectModel, hooks })
  login({ apiServer, UserModel, AccountModel, SystemAdminModel })
  invitation({ apiServer, UserModel, AccountModel, ProjectModel, SystemAdminModel, hooks })
  forgotPassword({ apiServer, UserModel, AccountModel, SystemAdminModel })
  account({ apiServer, UserModel, AccountModel, hooks })
  systemStats({ apiServer, UserModel, AccountModel })
  captcha({ apiServer })
  turnstile({ apiServer })
}

export { captchaHandler, turnstileHandler }
