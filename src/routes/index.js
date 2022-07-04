import createApiServer from 'express-async-api'

import login from './login.js'
import invitation from './invitation.js'
import forgotPassword from './forgotPassword.js'
import account from './accounts.js'
import users from './users.js'
import config from './config.js'

export default () => {
  function errorHandler (e) {
    return {
      status: e.status,
      error: {
        name: e.name,
        message: e.message
      }
    }
  }
  const apiServer = createApiServer(errorHandler, () => {})

  users(apiServer)
  config(apiServer)
  login(apiServer)
  invitation(apiServer)
  forgotPassword(apiServer)
  account(apiServer)

  return apiServer
}
