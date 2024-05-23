import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import mime from 'mime-types'

import { list, readOne, deleteOne, patchOne, createOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'

import aws from '../helpers/awsBucket.js'

const secrets = process.env.SECRETS.split(' ')
const bucketName = process.env.AWS_BUCKET_NAME
const folderName = process.env.AWS_FOLDER_NAME
const verifyEmailTamplate = process.env.ACCOUNT_BLUEFOX_VERIFY_EMAIL_TEMPLATE
const finalizeRegistrationTemplate = process.env.ACCOUNT_BLUEFOX_FINALIZE_REGISTRATION_TEMPLATE
const maxFileSize = process.env.MAX_FILE_SIZE

const s3 = await aws()

export default ({
  apiServer, UserModel, AccountModel, hooks =
  {
    updateName: { post: (params) => { } },
    updatePassword: { post: (params) => { } },
    updateRole: { post: (params) => { } },
    updateEmail: { post: (params) => { } },
    confirmEmail: { post: (params) => { } },
    deleteUser: { post: (params) => { } },
    permissionFor: { post: (params) => { } },
    accessToken: { post: (params) => { } },
    finalizeRegistration: { post: (params) => { } },
    listUsers: { post: (params) => { } },
    readOneUser: { post: (params) => { } },
    createUser: { post: (params) => { } },
    resendFinalizeRegistration: { post: (params) => { } },
    addProfilePicture: { post: (params) => { } },
    deleteProfilePicture: { post: (params) => { } }
  }
}) => {
  const sendUserEmail = async (email, href, templateUrl) => {
    const url = templateUrl
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href }
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

  apiServer.patch('/v1/accounts/:accountId/users/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { name: req.body.name }, { password: 0 })
    let postRes
    if (hooks.updateName?.post) {
      postRes = await hooks.updateName.post(req.params, req.body, user.result)
    }
    return postRes || user
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const oldHash = crypto.createHash('md5').update(req.body.oldPassword).digest('hex')
    const getUser = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query)
    if (oldHash !== getUser.result.password) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: hash }, { password: 0 })
    let postRes
    if (hooks.updatePassword?.post) {
      postRes = await hooks.updatePassword.post(req.params, req.body, user.result)
    }
    return postRes || user
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/role', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])

    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0 } })
    if (user.result.role === 'admin') {
      const admin = await list(UserModel, { role: 'admin' }, { select: { password: 0 } })
      if (admin.result.count < 2) {
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    const updatedUser = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { role: req.body.role }, { password: 0 })
    let postRes
    if (hooks.updateRole?.post) {
      postRes = await hooks.updateRole.post(req.params, req.body, updatedUser.result)
    }
    return postRes || updatedUser
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/email', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    if (req.body.newEmail !== req.body.newEmailAgain) {
      throw new ValidationError('Validation error email didn\'t match.')
    }
    const checkExist = await list(UserModel, { email: req.body.newEmail, accountId: req.params.accountId })
    if (checkExist.result.count > 0) {
      throw new MethodNotAllowedError('Email exist')
    }
    const response = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0, email: 0 } })
    const payload = {
      type: 'verfiy-email',
      user: response.result,
      newEmail: req.body.newEmail,
      account: {
        _id: req.params.accountId
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendUserEmail(req.body.newEmail, `${process.env.ACCOUNT_APP_URL}verify-email?token=${token}`, verifyEmailTamplate)
    let postRes
    if (hooks.updateEmail?.post) {
      postRes = await hooks.updateEmail.post(req.params, req.body, mail)
    }
    return postRes || {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/email-confirm', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'verfiy-email', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const response = await patchOne(UserModel, { id: req.params.id }, { email: data.newEmail })
    let postRes
    if (hooks.confirmEmail?.post) {
      postRes = await hooks.confirmEmail.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.delete('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    let user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    if (user.result.role === 'admin') {
      const admin = await list(UserModel, { role: 'admin' }, { select: { password: 0 } })
      if (admin.result.count < 2) {
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    user = await deleteOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: 0 })
    let postRes
    if (hooks.deleteUser?.post) {
      postRes = await hooks.deleteUser.post(req.params, req.body, user.result)
    }
    return postRes || user
  })

  apiServer.post('/v1/accounts/permission/:permissionFor', async req => {
    const tokenData = allowAccessTo(req, secrets, [{ type: 'user' }])
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(UserModel, { email: tokenData.user.email, password: hash })
    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid password')
    }
    const payload = {
      type: req.params.permissionFor,
      user: tokenData.user,
      account: tokenData.account,
      role: tokenData.role
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '5m' })
    let postRes
    if (hooks.permissionFor?.post) {
      postRes = await hooks.permissionFor.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        permissionToken: token
      }
    }
  })

  apiServer.get('/v1/accounts/:accountId/users/:id/access-token', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'login', user: { _id: req.params.id }, account: { _id: req.params.accountId } }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const findUser = await readOne(UserModel, { _id: req.params.id, accountId: req.params.accountId }, { select: { password: 0 } })
    const getAccount = await readOne(AccountModel, { _id: req.params.accountId }, req.query)

    const payload = {
      type: 'user',
      user: {
        _id: findUser.result._id,
        email: findUser.result.email
      },
      account: {
        _id: getAccount.result._id,
        urlFriendlyName: getAccount.result.urlFriendlyName
      },
      role: findUser.result.role
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })

    let postRes
    if (hooks.accessToken?.post) {
      postRes = await hooks.accessToken.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/:accountId/users/:id/finalize-registration', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'registration', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: data.user._id, accountId: req.params.accountId }, { role: 'admin' })
    const payload = {
      type: 'login',
      user: {
        _id: user.result._id,
        email: user.result.email
      },
      account: {
        _id: user.result.accountId
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    let postRes
    if (hooks.finalizeRegistration?.post) {
      postRes = await hooks.finalizeRegistration.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.get('/v1/accounts/:accountId/users', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)
    const userList = await list(UserModel, { accountId: req.params.accountId }, { ...req.query, select: { password: 0 } })
    let postRes
    if (hooks.listUsers?.post) {
      postRes = await hooks.listUsers.post(req.params, req.body, userList.result)
    }
    return postRes || userList
  })

  apiServer.post('/v1/accounts/:accountId/users', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)

    const checkUser = await list(UserModel, { email: req.body.email, accountId: req.params.accountId }, { select: { password: 0 } })
    if (checkUser.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const newUser = await createOne(UserModel, req.params, { name: req.body.name, email: req.body.email, password: hash, accountId: req.params.accountId })

    let postRes
    if (hooks.createUser?.post) {
      postRes = await hooks.createUser.post(req.params, req.body, newUser.result)
    }
    return postRes || newUser
  })

  apiServer.get('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0 } })
    let postRes
    if (hooks.readOneUser?.post) {
      postRes = await hooks.readOneUser.post(req.params, req.body, user.result)
    }
    return postRes || user
  })

  apiServer.postBinary('/v1/accounts/:accountId/users/:id/profile-picture', { mimeTypes: ['image/jpeg', 'image/png', 'image/gif'], fieldName: 'profilePicture', maxFileSize }, async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const uploadParams = {
      Bucket: bucketName,
      Body: req.file.buffer,
      Key: `${folderName}/users/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }

    const result = await s3.upload(uploadParams).promise()
    const response = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { profilePicture: process.env.CDN_BASE_URL + result.Key })
    let postRes
    if (hooks.addProfilePicture?.post) {
      postRes = await hooks.addProfilePicture.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: {
        profilePicture: process.env.CDN_BASE_URL + result.Key
      }
    }
  })
  apiServer.delete('/v1/accounts/:accountId/users/:id/profile-picture', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const userData = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0 } })
    const key = userData.result.profilePicture.substring(userData.result.profilePicture.lastIndexOf('/') + 1)
    await s3.deleteObject({
      Bucket: bucketName,
      Key: `${folderName}/users/${key}`
    }).promise()
    const response = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { profilePicture: null })
    let postRes
    if (hooks.deleteProfilePicture?.post) {
      postRes = await hooks.deleteProfilePicture.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.post('/v1/accounts/:accoutId/users/:userId/resend-finalize-registration', async req => {
    const getAccount = await readOne(AccountModel, { _id: req.params.accoutId }, req.query)
    const getUser = await readOne(UserModel, { _id: req.params.userId })
    const payload = {
      type: 'registration',
      user: {
        _id: getUser.result._id,
        email: getUser.result.email
      },
      account: {
        _id: getAccount.result._id
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendUserEmail(getUser.result.email, `${process.env.ACCOUNT_APP_URL}finalize-registration?token=${token}`, finalizeRegistrationTemplate)
    let postRes
    if (hooks.resendFinalizeRegistration?.post) {
      postRes = await hooks.resendFinalizeRegistration.post(req.params, req.body, mail)
    }
    return postRes || {
      status: 200,
      result: {
        newAccount: getAccount.result,
        newUser: getUser.result,
        info: mail.result.info
      }
    }
  })
}
