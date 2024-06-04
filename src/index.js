import login from './routes/login.js'
import invitation from './routes/invitation.js'
import forgotPassword from './routes/forgotPassword.js'
import account from './routes/accounts.js'
import users from './routes/users.js'
import admins from './routes/admins.js'

export default ({
  apiServer, UserModel, AccountModel, AdminModel, hooks =
  {
    deleteAccount: { post: (params) => { } }
  }
}) => {
  admins({ apiServer, AdminModel })
  users({ apiServer, UserModel, AccountModel })
  login({ apiServer, UserModel, AccountModel, AdminModel })
  invitation({ apiServer, UserModel, AccountModel, AdminModel })
  forgotPassword({ apiServer, UserModel, AccountModel, AdminModel })
  account({ apiServer, UserModel, AccountModel, hooks })
}
