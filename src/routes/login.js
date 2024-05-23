import crypto from 'crypto'

import { list, readOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import { AuthenticationError } from 'standard-api-errors'

const secrets = process.env.SECRETS.split(' ')
const loginSelectTemplate = process.env.ACCOUNT_BLUEFOX_LOGIN_SELECT_TEMPLATE

export default ({
  apiServer, UserModel, AccountModel, hooks =
  {
    login: { post: (params) => { } },
    loginUrlFriendlyName: { post: (params) => { } },
    getLoginAccounts: { post: (params) => { } }
  }
}) => {
  const sendLogin = async (email, token) => {
    const url = loginSelectTemplate
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.ACCOUNT_BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.ACCOUNT_APP_URL}login-select?token=${token}` }
      })
    })
    const res = await response.json()
    if (res.status !== 200) {
      const error = new Error(res.error.message)
      error.status = res.status
      error.name = res.error.name
      throw error
    }
    return res
  }

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
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    let postRes
    if (hooks.login?.post) {
      postRes = await hooks.login.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/:id/login/url-friendly-name', async req => {
    let getAccount
    let findUser
    try {
      req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
      getAccount = await list(AccountModel, { urlFriendlyName: req.params.id }, req.query)
      findUser = await list(UserModel, { email: req.body.email, accountId: getAccount.result.items[0]._id, password: req.body.password }, req.query)
      if (!getAccount.result.count || !findUser.result.count) {
        throw new Error()
      }
    } catch (error) {
      throw new AuthenticationError('Invalid urlFriendlyName, email or password ')
    }
    const payload = {
      type: 'login',
      user: {
        _id: findUser.result.items[0]._id,
        email: findUser.result.items[0].email
      },
      account: {
        _id: getAccount.result.items[0]._id
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    let postRes
    if (hooks.loginUrlFriendlyName?.post) {
      postRes = await hooks.loginUrlFriendlyName.post(req.params, req.body, token)
    }
    return postRes || {
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
    const ids = findUserIds.result.items.map(item => item.accountId.toString())

    const getAccounts = await list(AccountModel, {}, { filter: { _id: { $in: ids } } })
    const payload = {
      type: 'login',
      user: {
        email: req.body.email
      },
      accounts:
       getAccounts.result.items
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const info = await sendLogin(req.body.email, token)
    let postRes
    if (hooks.getLoginAccounts?.post) {
      postRes = await hooks.getLoginAccounts.post(req.params, req.body, info)
    }
    return postRes || {
      status: 201,
      result: {
        success: true,
        info: info.result.info
      }
    }
  })
}
