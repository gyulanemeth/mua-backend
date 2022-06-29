import { list, readOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'
import { AuthenticationError } from 'standard-api-errors'
import Email from '../helpers/Email.js'
import crypto from 'crypto'
import handlebars from 'handlebars'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const Login = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'login.html'), 'utf8')

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/accounts/:id/login', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'login' }])
    req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(UserModel, { email: data.user.email, accountId: req.params.id, password: req.body.password }, req.query)
    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid email or password')
    }
    const getAccount = await readOne(AccountModel, { id: req.params.id }, req.query)

    const payload = {
      type: 'login',
     user: {
        _id: findUser.result.items[0]._id,
        email: findUser.result.items[0].email
     },
     account:{
       _id:getAccount.result._id
     }
   }


    const token = jwt.sign(payload, secrets[0])
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    const findUserIds = await list(UserModel, { email: req.body.email }, {select:{ accountId: 1 }})
    if (findUserIds.result.count === 0) {
      throw new AuthenticationError('Invalid email')
    }

    var ids = findUserIds.result.items.map(item => item.accountId)
    const getAccounts = await list(AccountModel, { id: { $in: ids} }, req.query)

    const payload = {
      type: 'login',
      user:{
        email:req.body.email
      },
     accounts:
       getAccounts.result.items
     }
    const token = jwt.sign(payload, secrets[0])
    const template = handlebars.compile(Login)
    const html = template({ token })
    const info = await Email(req.body.email, 'Login link ', html)
    return {
      status: 201,
      result: {
        success: true,
        info: info.result.info
      }
    }
  })

}
