import crypto from 'crypto'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

import { list, readOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'
import allowAccessTo from 'bearer-jwt-auth'
import { AuthenticationError } from 'standard-api-errors'

import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'
import sendEmail from '../helpers/sendEmail.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const Login = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'login.html'), 'utf8')

const secrets = process.env.SECRETS.split(' ')

export default (apiServer) => {
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
      account: {
        _id: getAccount.result._id
      }
    }
    const token = jwt.sign(payload, secrets[0], {expiresIn: "24h"})
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    const findUserIds = await list(UserModel, { email: req.body.email }, { select: { accountId: 1 } })
    if (findUserIds.result.count === 0) {
      throw new AuthenticationError('Invalid email')
    }
    console.log(findUserIds);
    const ids = findUserIds.result.items.map(item => item.accountId.toString())
    console.log(ids);

    const getAccounts = await list(AccountModel, {}, {filter: {_id: { $in: ids }}})
    console.log(getAccounts);
    const payload = {
      type: 'login',
      user: {
        email: req.body.email
      },
      accounts:
       getAccounts.result.items
    }
    const token = jwt.sign(payload, secrets[0], {expiresIn: "24h"})
    const template = handlebars.compile(Login)
    const html = template({ href : `${process.env.APP_URL}loginSelect?token=${token}`})
    const info = await sendEmail(req.body.email, 'Login link ', html)
    return {
      status: 201,
      result: {
        success: true,
        info: info.result.info
      }
    }
  })
}
