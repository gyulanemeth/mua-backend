import crypto from 'crypto'

import { list, readOne, patchOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import { AuthenticationError, MethodNotAllowedError, ValidationError } from 'standard-api-errors'
import passport from 'passport'

export default ({
  apiServer, UserModel, AccountModel, SystemAdminModel
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const sendLogin = async (email, transactionalId, data) => {
    const response = await fetch(process.env.BLUEFOX_TRANSACTIONAL_EMAIL_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        transactionalId,
        data
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

  const sendRegistration = async (email, transactionalId, token) => {
    const response = await fetch(process.env.BLUEFOX_TRANSACTIONAL_EMAIL_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        transactionalId,
        data: { link: `${process.env.APP_URL}accounts/finalize-registration?token=${token}` }
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

  async function providerLoginCallback (provider, user, data) {
    const userParams = {
      email: user.email,
      accountId: data.account._id
    }
    switch (provider) {
      case 'google':
        userParams.googleProfileId = user.id
        break
      case 'microsoft':
        userParams.microsoftProfileId = user.id
        break
      case 'github':
        userParams.githubProfileId = user.id
        break
    }
    try {
      const findUser = await list(UserModel, userParams)
      if (findUser.result.count !== 1) {
        throw new AuthenticationError('Authentication failed')
      }
      const token = jwt.sign({
        type: 'login',
        user: {
          _id: findUser.result.items[0]._id,
          email: findUser.result.items[0].email
        },
        account: {
          _id: data.account._id
        }
      }, secrets[0], { expiresIn: '24h' })
      return `${process.env.APP_URL}accounts/login/${data.account.urlFriendlyName}?loginToken=${token}`
    } catch (error) {
      return `${process.env.APP_URL}accounts/login/${data.account.urlFriendlyName}?failed=${error.name}`
    }
  }

  async function providerLinkCallback (provider, user, data) {
    const userBody = {}
    switch (provider) {
      case 'google':
        userBody.googleProfileId = user.id
        break
      case 'microsoft':
        userBody.microsoftProfileId = user.id
        break
      case 'github':
        userBody.githubProfileId = user.id
        break
    }
    try {
      await patchOne(UserModel, { id: data.user._id, accountId: data.account._id, email: user.email }, userBody)
      return `${process.env.APP_URL}accounts/${data.account.urlFriendlyName}/me?success=true`
    } catch (error) {
      return `${process.env.APP_URL}accounts/${data.account.urlFriendlyName}/me?failed=${error.name}`
    }
  }

  async function providerCreateCallback (provider, user, data) {
    let payload = {}
    try {
      if (data.user && data.account) {
        const userBody = {}
        switch (provider) {
          case 'google':
            userBody.googleProfileId = user.id
            break
          case 'microsoft':
            userBody.microsoftProfileId = user.id
            break
          case 'github':
            userBody.githubProfileId = user.id
            break
        }
        const userData = await patchOne(UserModel, { id: data.user._id, accountId: data.account._id, email: user.email }, { ...userBody, name: user.name, profilePicture: user.profilePicture, verified: true }) // solve static googleProfileId
        payload = {
          type: 'login',
          user: {
            _id: userData.result._id,
            email: userData.result.email
          },
          account: {
            _id: data.account._id
          }
        }
      } else {
        payload = {
          user
        }
      }
      const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
      return `${process.env.APP_URL}accounts/${payload.type ? data.account.urlFriendlyName + '/me?loginToken' : 'create-account?userData'}=${token}`
    } catch (error) {
      return `${process.env.APP_URL}accounts/login/${data.account.urlFriendlyName}?failed=${error.name}`
    }
  }

  async function providerCallback (req, provider) {
    let redirect
    try {
      await new Promise((resolve) => {
        passport.authenticate(provider, { session: false }, async (err, user) => {
          const state = req.query.state
          const data = JSON.parse(Buffer.from(state, 'base64').toString())
          if (err || !user) {
            redirect = `${process.env.APP_URL}accounts/login/${data.account?.urlFriendlyName}?failed=AUTHENTICATION_ERROR`
            return resolve()
          }
          if (data.type === 'login') {
            redirect = await providerLoginCallback(provider, user, data)
          } else if (data.type === 'link') {
            redirect = await providerLinkCallback(provider, user, data)
          } else if (data.type === 'create') {
            redirect = await providerCreateCallback(provider, user, data)
          }
          resolve()
        })(req)
      })
      return { redirect }
    } catch (error) {
      redirect = `${process.env.APP_URL}accounts/login?failed=AUTHENTICATION_ERROR`
      return { redirect }
    }
  }

  apiServer.post('/v1/accounts/:id/login', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'login' }])
    req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(UserModel, { email: data.user.email, accountId: req.params.id, password: req.body.password }, req.query)
    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid email or password')
    }
    if (!findUser.result.items[0].verified) {
      const payload = {
        type: 'registration',
        user: {
          _id: findUser.result.items[0]._id,
          email: findUser.result.items[0].email
        },
        account: {
          _id: req.params.id
        }
      }
      const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
      await sendRegistration(findUser.result.items[0].email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION, token)
      throw new MethodNotAllowedError('Please verify your email')
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
    return {
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
    if (!findUser.result.items[0].verified) {
      const payload = {
        type: 'registration',
        user: {
          _id: findUser.result.items[0]._id,
          email: findUser.result.items[0].email
        },
        account: {
          _id: getAccount.result.items[0]._id
        }
      }
      const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
      await sendRegistration(findUser.result.items[0].email, token)
      throw new MethodNotAllowedError('Please verify your email')
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
    const info = await sendLogin(req.body.email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_LOGIN_SELECT, { link: `${process.env.APP_URL}accounts/login-select?token=${token}` })
    return {
      status: 201,
      result: {
        success: true,
        info: info.result.info
      }
    }
  })

  apiServer.post('/v1/system-admins/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(SystemAdminModel, { email: req.body.email, password: req.body.password }, { select: { password: 0 } })

    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid email or password')
    }

    const payload = {
      type: 'login',
      user: {
        _id: findUser.result.items[0]._id,
        email: findUser.result.items[0].email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/:id/login/provider/:provider', async req => {
    if (!['google', 'github', 'microsoft'].includes(req.params.provider)) {
      throw new ValidationError('Unsupported provider')
    }
    const getAccount = await readOne(AccountModel, { id: req.params.id })
    const state = Buffer.from(JSON.stringify({ type: 'login', account: getAccount.result })).toString('base64')
    let url
    const mockRes = {
      redirect: (value) => {
        url = value
      },
      statusCode: 200,
      setHeader: (header, value) => {
        if (header === 'Location') {
          url = value
        }
      },
      end: () => { }
    }
    passport.authenticate(req.params.provider, { scope: ['profile', 'email'], state })(req, mockRes, (ele) => { console.log(ele) })
    return {
      status: 200,
      result: {
        redirectUrl: url
      }
    }
  })

  apiServer.post('/v1/accounts/:accountId/users/:id/link/provider/:provider', async req => {
    const providers = []
    if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
      providers.push('google')
    }
    if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
      providers.push('github')
    }
    if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
      providers.push('microsoft')
    }
    if (!providers.includes(req.params.provider)) {
      throw new ValidationError('Unsupported provider')
    }
    const getAccount = await readOne(AccountModel, { id: req.params.accountId })
    const getUser = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    const state = Buffer.from(JSON.stringify({ type: 'link', account: getAccount.result, user: getUser.result })).toString('base64')
    let url
    const mockRes = {
      redirect: (value) => {
        url = value
      },
      statusCode: 200,
      setHeader: (header, value) => {
        if (header === 'Location') {
          url = value
        }
      },
      end: () => { }
    }
    passport.authenticate(req.params.provider, { scope: ['profile', 'email'], state })(req, mockRes, (ele) => { console.log(ele) })
    return {
      status: 200,
      result: {
        redirectUrl: url
      }
    }
  })

  apiServer.post('/v1/accounts/create-account/provider/:provider', async req => {
    const providers = []
    if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
      providers.push('google')
    }
    if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
      providers.push('github')
    }
    if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
      providers.push('microsoft')
    }
    if (!providers.includes(req.params.provider)) {
      throw new ValidationError('Unsupported provider')
    }
    const data = {
      type: 'create'
    }
    if (req.body.accountId && req.body.userId) {
      const getAccount = await readOne(AccountModel, { id: req.body.accountId })
      const getUser = await readOne(UserModel, { id: req.body.userId, accountId: req.body.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
      data.account = getAccount.result
      data.user = getUser.result
    }
    const state = Buffer.from(JSON.stringify(data)).toString('base64')
    let url
    const mockRes = {
      redirect: (value) => {
        url = value
      },
      statusCode: 200,
      setHeader: (header, value) => {
        if (header === 'Location') {
          url = value
        }
      },
      end: () => { }
    }
    passport.authenticate(req.params.provider, { scope: ['profile', 'email'], state })(req, mockRes, (ele) => { console.log(ele) })
    return {
      status: 200,
      result: {
        redirectUrl: url
      }
    }
  })

  apiServer.get('/v1/accounts/provider/google/callback', async req => {
    return providerCallback(req, 'google')
  })

  apiServer.get('/v1/accounts/provider/microsoft/callback', async req => {
    return providerCallback(req, 'microsoft')
  })

  apiServer.get('/v1/accounts/provider/github/callback', async req => {
    return providerCallback(req, 'github')
  })
}
