import createApiServer from 'express-async-api'

import login from './login.js'
import invitation from './invitation.js'
import forgotPassword from './forgotPassword.js'
import account from './accounts.js'
import users from './users.js'
import config from './config.js'

export default (connectors, maxFileSize) => {
  function errorHandler (e) {
    if (e.code === 'LIMIT_FILE_SIZE') {
      return {
        status: 413,
        error: {
          name: 'PAYLOAD_TOO_LARGE',
          message: 'File size limit exceeded. Maximum file size allowed is ' + (Number(maxFileSize) / (1024 * 1024)).toFixed(2) + 'mb'
        }
      }
    }
    return {
      status: e.status,
      error: {
        name: e.name,
        message: e.message
      }
    }
  }
  const apiServer = createApiServer(errorHandler, () => {})

  users(apiServer, maxFileSize)
  config(apiServer)
  login(apiServer)
  invitation(apiServer)
  forgotPassword(apiServer)
  account(apiServer, connectors, maxFileSize)

  return apiServer
}
