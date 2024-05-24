import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import mime from 'mime-types'

import allowAccessTo from 'bearer-jwt-auth'
import { ConflictError, AuthenticationError, NotFoundError } from 'standard-api-errors'
import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'

import aws from '../helpers/awsBucket.js'

const bucketName = process.env.AWS_BUCKET_NAME
const folderName = process.env.AWS_FOLDER_NAME

const s3 = await aws()

const secrets = process.env.SECRETS.split(' ')
const finalizeRegistration = process.env.ACCOUNT_BLUEFOX_FINALIZE_REGISTRATION_TEMPLATE

export default ({
  apiServer, UserModel, AccountModel, hooks =
  {
    checkAvailability: { post: (params) => { } },
    readOneAccountByUrlFriendlyName: { post: (params) => { } },
    listAccount: { post: (params) => { } },
    createAccountByAdmin: { post: (params) => { } },
    readOneAccount: { post: (params) => { } },
    updateName: { post: (params) => { } },
    updateUrlFriendlyName: { post: (params) => { } },
    deleteAccount: { post: (params) => { } },
    createAccount: { post: (params) => { } },
    addLogo: { post: (params) => { } },
    deleteLogo: { post: (params) => { } }
  }
}) => {
  const sendRegistration = async (email, token) => {
    const url = finalizeRegistration
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.ACCOUNT_APP_URL}finalize-registration?token=${token}` }
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
    let postRes
    if (hooks.checkAvailability?.post) {
      postRes = await hooks.checkAvailability.post(req.params, req.body, response.result)
    }
    return postRes || {
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
    let postRes
    if (hooks.readOneAccountByUrlFriendlyName?.post) {
      postRes = await hooks.readOneAccountByUrlFriendlyName.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: response.result.items[0]
    }
  })

  apiServer.get('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AccountModel, req.params, req.query)
    let postRes
    if (hooks.listAccount?.post) {
      postRes = await hooks.listAccount.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.post('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await createOne(AccountModel, req.params, req.body)
    let postRes
    if (hooks.createAccountByAdmin?.post) {
      postRes = await hooks.createAccountByAdmin.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.get('/v1/accounts/:id', async req => { /// update user should be associated to account
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', account: { _id: req.params.id } }])
    const response = await readOne(AccountModel, { id: req.params.id }, req.query)
    let postRes
    if (hooks.readOneAccount?.post) {
      postRes = await hooks.readOneAccount.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.patch('/v1/accounts/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { name: req.body.name })
    let postRes
    if (hooks.updateName?.post) {
      postRes = await hooks.updateName.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.patch('/v1/accounts/:id/urlFriendlyName', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { urlFriendlyName: req.body.urlFriendlyName })
    let postRes
    if (hooks.updateUrlFriendlyName?.post) {
      postRes = await hooks.updateUrlFriendlyName.post(req.params, req.body, response.result)
    }
    return postRes || response
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
    const newAccount = await createOne(AccountModel, req.params, { name: req.body.account.name, urlFriendlyName: req.body.account.urlFriendlyName })
    const hash = crypto.createHash('md5').update(req.body.user.password).digest('hex')
    const newUser = await createOne(UserModel, req.params, { name: req.body.user.name, email: req.body.user.email, password: hash, accountId: newAccount.result._id })
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
    const mail = await sendRegistration(newUser.result.email, token)
    let postRes
    if (hooks.createAccount?.post) {
      postRes = await hooks.createAccount.post(req.params, req.body, mail)
    }
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
      Bucket: bucketName,
      Body: req.file.buffer,
      Key: `${folderName}/accounts/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }
    const result = await s3.upload(uploadParams).promise()
    const response = await patchOne(AccountModel, { id: req.params.id }, { logo: process.env.CDN_BASE_URL + result.Key })
    let postRes
    if (hooks.addLogo?.post) {
      postRes = await hooks.addLogo.post(req.params, req.body, response.result)
    }
    return postRes || {
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
      Bucket: bucketName,
      Key: `${folderName}/accounts/${key}`
    }).promise()
    const response = await patchOne(AccountModel, { id: req.params.id }, { logo: null })
    let postRes
    if (hooks.deleteLogo?.post) {
      postRes = await hooks.deleteLogo.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
