import login from './routes/login.js'
import invitation from './routes/invitation.js'
import forgotPassword from './routes/forgotPassword.js'
import account from './routes/accounts.js'
import users from './routes/users.js'
import systemAdmins from './routes/systemAdmins.js'

export default ({
  apiServer, UserModel, AccountModel, SystemAdminModel, hooks =
  {
    deleteAccount: { post: (params) => { } },
    createAccount: { post: (params) => { } },
    createNewUser: { post: (params) => { } },
    updateUserEmail: { post: (params) => { } }
  }
}) => {
  systemAdmins({ apiServer, SystemAdminModel })
  users({ apiServer, UserModel, AccountModel, hooks })
  login({ apiServer, UserModel, AccountModel, SystemAdminModel })
  invitation({ apiServer, UserModel, AccountModel, SystemAdminModel, hooks })
  forgotPassword({ apiServer, UserModel, AccountModel, SystemAdminModel })
  account({ apiServer, UserModel, AccountModel, hooks })
}
