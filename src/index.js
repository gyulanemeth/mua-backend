import login from './routes/login.js'
import invitation from './routes/invitation.js'
import forgotPassword from './routes/forgotPassword.js'
import account from './routes/accounts.js'
import users from './routes/users.js'

export default ({
  apiServer, UserModel, AccountModel, hooks =
  {
    deleteAccount: { post: (params) => { } }
  }
}) => {
  users({ apiServer, UserModel, AccountModel })
  login({ apiServer, UserModel, AccountModel })
  invitation({ apiServer, UserModel, AccountModel })
  forgotPassword({ apiServer, UserModel, AccountModel })
  account({ apiServer, UserModel, AccountModel, deleteAccount: { post: (params) => { } } })
}
