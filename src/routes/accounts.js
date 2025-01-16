import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import mime from 'mime-types'

import allowAccessTo from 'bearer-jwt-auth'
import { ConflictError, AuthenticationError, NotFoundError, ValidationError } from 'standard-api-errors'
import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'

import aws from '../helpers/awsBucket.js'

export default async ({
  apiServer, UserModel, AccountModel, hooks =
  {
    deleteAccount: { post: (params) => { } },
    createAccount: { post: (params) => { } },
    createNewUser: { post: (params) => { } }
  }
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const s3 = await aws()
  const sendRegistration = async (email, transactionalId, data) => {
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

  apiServer.get('/v1/accounts/check-availability', async req => {
    let available = false
    const response = await list(AccountModel, { urlFriendlyName: req.query.urlFriendlyName })
    if (response.result.count > 0) {
      available = true
    }
    return {
      status: 200,
      result: {
        available
      }
    }
  })

  apiServer.get('/v1/accounts/by-url-friendly-name/:urlFriendlyName', async req => {
    const response = await list(AccountModel, req.params, req.query)
    if (!response.result.count) {
      throw new NotFoundError('Account Not Found')
    }
    return {
      status: 200,
      result: response.result.items[0]
    }
  })

  apiServer.get('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AccountModel, req.params, req.query)
    return response
  })

  apiServer.post('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await createOne(AccountModel, req.params, req.body)
    let postRes
    if (hooks.createAccount?.post) {
      postRes = await hooks.createAccount.post(req.body, response.result)
    }
    return postRes || response
  })

  apiServer.get('/v1/accounts/:id', async req => { /// update user should be associated to account
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', account: { _id: req.params.id } }])
    const response = await readOne(AccountModel, { id: req.params.id }, req.query)
    return response
  })

  apiServer.patch('/v1/accounts/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { name: req.body.name })
    return response
  })

  apiServer.patch('/v1/accounts/:id/urlFriendlyName', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { urlFriendlyName: req.body.urlFriendlyName })
    return response
  })

  apiServer.delete('/v1/accounts/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    deleteMany(UserModel, { accountId: req.params.id })
    const deletedAccount = await deleteOne(AccountModel, { id: req.params.id })
    let postRes
    if (hooks.deleteAccount?.post) {
      postRes = await hooks.deleteAccount.post(req.params, req.body, deletedAccount.result)
    }
    return postRes || {
      status: 200,
      result: {
        deletedAccount: deletedAccount.result
      }
    }
  })

  apiServer.post('/v1/accounts/create', async req => {
    if (process.env.ALPHA_MODE === 'true') {
      try {
        allowAccessTo(req, secrets, [{ type: 'admin' }])
      } catch (error) {
        throw new AuthenticationError('NOT ALLOWED IN ALPHA MODE')
      }
    }
    const response = await list(AccountModel, { urlFriendlyName: req.body.account.urlFriendlyName }, req.query)
    if (response.result.count > 0) {
      throw new ConflictError('urlFriendlyName exist')
    }
    if (!req.body.user.password && !req.body.user.googleProfileId && !req.body.user.microsoftProfileId && !req.body.user.githubProfileId) {
      throw new ValidationError('Please provide password or create using Google, Microsoft or Github')
    }
    const newAccount = await createOne(AccountModel, req.params, { name: req.body.account.name, urlFriendlyName: req.body.account.urlFriendlyName })
    const userData = {
      name: req.body.user.name,
      email: req.body.user.email,
      accountId: newAccount.result._id
    }
    if (req.body.user.password) {
      const hash = crypto.createHash('md5').update(req.body.user.password).digest('hex')
      userData.password = hash
    } else {
      userData.googleProfileId = req.body.user.googleProfileId
      userData.microsoftProfileId = req.body.user.microsoftProfileId
      userData.githubProfileId = req.body.user.githubProfileId
      userData.profilePicture = req.body.user.profilePicture
      userData.role = 'admin'
      userData.verified = true
    }
    const newUser = await createOne(UserModel, req.params, userData)
    if (hooks.createNewUser?.post) {
      hooks.createNewUser.post({ accountId: newAccount.result._id, name: newUser.result.name, email: newUser.result.email })
    }
    let postRes
    if (hooks.createAccount?.post) {
      postRes = await hooks.createAccount.post(req.body, newAccount.result)
    }
    if (newUser.result.verified) {
      const payload = {
        type: 'login',
        user: {
          _id: newUser.result._id,
          email: newUser.result.email
        },
        account: {
          _id: newAccount.result._id
        }
      }
      const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
      return {
        status: 200,
        result: {
          loginToken: token
        }
      }
    }
    const payload = {
      type: 'registration',
      user: {
        _id: newUser.result._id,
        email: newUser.result.email
      },
      account: {
        _id: newAccount.result._id
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendRegistration(newUser.result.email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION, { link: `${process.env.APP_URL}accounts/finalize-registration?token=${token}`, name: newUser.result.name, user: { name: newUser.result.name, email: newUser.result.email, profilePicture: newUser.result.profilePicture } })
    return postRes || {
      status: 200,
      result: {
        newAccount: newAccount.result,
        newUser: newUser.result,
        info: mail.result.info
      }
    }
  })

  apiServer.postBinary('/v1/accounts/:id/logo', { mimeTypes: ['image/jpeg', 'image/png', 'image/gif'], fieldName: 'logo', maxFileSize: process.env.MAX_FILE_SIZE }, async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const uploadParams = {
      Bucket: process.env.AWS_BUCKET_NAME,
      Body: req.file.buffer,
      Key: `${process.env.AWS_FOLDER_NAME}/accounts/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }
    const result = await s3.upload(uploadParams).promise()
    await patchOne(AccountModel, { id: req.params.id }, { logo: process.env.CDN_BASE_URL + result.Key })
    return {
      status: 200,
      result: {
        logo: process.env.CDN_BASE_URL + result.Key
      }
    }
  })

  apiServer.delete('/v1/accounts/:id/logo', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const accountData = await readOne(AccountModel, { id: req.params.id }, req.query)
    const key = accountData.result.logo.substring(accountData.result.logo.lastIndexOf('/') + 1)

    await s3.deleteObject({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `${process.env.AWS_FOLDER_NAME}/accounts/${key}`
    }).promise()
    await patchOne(AccountModel, { id: req.params.id }, { logo: null })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
