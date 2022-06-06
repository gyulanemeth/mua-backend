import createApiServer from 'express-async-api'

import admins from './admins.js'
import login from './login.js'
import invitation from './invitation.js'
import forgotPassword from './forgotPassword.js'

export default () => {
  const apiServer = createApiServer(() => {}, () => {})

  admins(apiServer)
  login(apiServer)
  invitation(apiServer)
  forgotPassword(apiServer)

  return apiServer
}
