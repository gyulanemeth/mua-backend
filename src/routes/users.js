import bcrypt from 'bcrypt'

import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import mime from 'mime-types'
import { fileTypeFromBuffer } from 'file-type'

import { list, readOne, deleteOne, patchOne, createOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import verifyAndUpgradePassword from '../helpers/verifyAndUpgradePassword.js'
import { encrypt, decrypt } from '../helpers/decryptEncryptHandler.js'

import aws from '../helpers/awsBucket.js'
import mfa from '../helpers/mfa.js'

export default async ({
  apiServer, UserModel, AccountModel, ProjectModel, hooks = {
    checkEmail: async (params) => { },
    createNewUser: { post: () => { } },
    updateUserEmail: { post: () => { } }
  }
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const s3 = await aws()
  const sendUserEmail = async (email, transactionalId, data) => {
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

  apiServer.patch('/v1/accounts/:accountId/users/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { name: req.body.name }, { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 })
    return user
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/create-password', async req => {
    const tokenData = await allowAccessTo(req, secrets, [{ type: 'create-password', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const hash = await bcrypt.hash(tokenData.newPassword, 10)
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: hash }, { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 })
    const payload = {
      type: 'user',
      user: {
        _id: user.result._id,
        email: user.result.email
      },
      account: {
        _id: user.result.accountId
      },
      role: user.result.role
    }
    if (user.result.role === 'client') {
      payload.projectsAccess = {}
      user.result.projectsAccess.forEach(ele => {
        payload.projectsAccess[ele.projectId] = ele.permission
      })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        success: true,
        accessToken: token
      }
    }
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const getUser = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query)
    if (!getUser.result.password) {
      const getAccount = await readOne(AccountModel, { id: req.params.accountId })
      const payload = {
        type: 'create-password',
        user: {
          _id: getUser.result._id
        },
        newPassword: req.body.newPassword,
        account: {
          _id: getAccount.result._id
        }
      }
      if (getUser.result.role === 'client') {
        payload.projectsAccess = {}
        getUser.result.projectsAccess.forEach(ele => {
          payload.projectsAccess[ele.projectId] = ele.permission
        })
      }
      const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
      const mail = await sendUserEmail(getUser.result.email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_CREATE_PASSWORD, { link: `${process.env.APP_URL}accounts/create-password?token=${token}`, name: getUser.result.name, accountName: getAccount.result.name, account: { name: getAccount.result.name, urlFriendlyName: getAccount.result.urlFriendlyName, logo: getAccount.result.logo, url: `${process.env.APP_URL}accounts/${getAccount.result.urlFriendlyName}` }, user: { name: getUser.result.name, email: getUser.result.email, profilePicture: getUser.result.profilePicture } })
      return {
        status: 200,
        result: {
          success: true,
          info: mail.result.info
        }
      }
    }
    const checkPass = await verifyAndUpgradePassword(getUser.result, req.body.oldPassword, UserModel)
    if (!checkPass) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = await bcrypt.hash(req.body.newPassword, 10)
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: hash }, { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 })
    return user
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/role', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])

    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    if (user.result.role === 'admin') {
      const admin = await list(UserModel, { accountId: req.params.accountId, role: 'admin' }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
      if (admin.result.count < 2) {
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    if (req.body.role === 'client' && (!req.body.projectsAccess || !req.body.projectsAccess.length)) {
      throw new ValidationError('Missing client projectsAccess')
    }
    const updatedUser = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.body, { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 })
    return updatedUser
  })

  apiServer.get('/v1/accounts/:accountId/users/:id/mfa', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const response = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    if (response.result.twoFactor?.enabled) {
      return {
        status: 200,
        result: {
          enabled: true,
          recoverySecret: decrypt(response.result.twoFactor.recoverySecret)
        }
      }
    }
    const { secret, qrcode } = await mfa.generate({
      label: response.result.email,
      issuer: `${process.env.APP_NAME}-user-${response.result._id}-account-${response.result.accountId}`
    })

    /* c8 ignore next */
    await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { twoFactor: { ...response.result.twoFactor || {}, secret: encrypt(secret) } })
    return {
      status: 200,
      result: {
        qrcode,
        secret
      }
    }
  })

  apiServer.post('/v1/accounts/:accountId/users/:id/mfa', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    const ok = mfa.validate({ code: req.body.code, secret: decrypt(user.result.twoFactor?.secret), window: 1 })
    if (!ok) {
      throw new ValidationError('Invalid 2FA Code')
    }

    const { recoveryCode } = mfa.generateRecoveryCode()
    /* c8 ignore next */
    await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { twoFactor: { ...user.result.twoFactor || {}, enabled: true, recoverySecret: encrypt(recoveryCode) } })
    return {
      status: 200,
      result: {
        enabled: true,
        recoverySecret: recoveryCode
      }
    }
  })

  apiServer.delete('/v1/accounts/:accountId/users/:id/mfa', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    /* c8 ignore next */
    await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { twoFactor: { ...user.result.twoFactor || {}, enabled: false } })
    return {
      status: 200,
      result: {
        enabled: false
      }
    }
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
    const response = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { email: 0 } })
    if (!response.result.password) {
      throw new MethodNotAllowedError('Password is required to change the email for this account. Please set a password to proceed.')
    }
    delete response.result.password
    const payload = {
      type: 'verfiy-email',
      user: response.result,
      newEmail: req.body.newEmail,
      account: {
        _id: req.params.accountId
      }
    }
    if (response.result.role === 'client') {
      payload.projectsAccess = {}
      response.result.projectsAccess.forEach(ele => {
        payload.projectsAccess[ele.projectId] = ele.permission
      })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendUserEmail(req.body.newEmail, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_VERIFY_EMAIL, { link: `${process.env.APP_URL}accounts/verify-email?token=${token}`, name: response.result.name, user: { name: response.result.name, email: response.result.email, profilePicture: response.result.profilePicture } })
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/email-confirm', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'verfiy-email', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const getUserData = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    await hooks?.checkEmail(data.newEmail)
    const user = await patchOne(UserModel, { id: req.params.id }, { email: data.newEmail, googleProfileId: null, microsoftProfileId: null, githubProfileId: null })
    hooks?.updateUserEmail?.post({ accountId: req.params.accountId, oldEmail: getUserData.result.email, newEmail: data.newEmail })
    const payload = {
      type: 'user',
      user: {
        _id: user.result._id,
        email: user.result.email
      },
      account: {
        _id: user.result.accountId
      },
      role: user.result.role
    }
    if (user.result.role === 'client') {
      payload.projectsAccess = {}
      user.result.projectsAccess.forEach(ele => {
        payload.projectsAccess[ele.projectId] = ele.permission
      })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })

    return {
      status: 200,
      result: {
        success: true,
        accessToken: token
      }
    }
  })

  apiServer.delete('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    let user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    if (user.result.role === 'admin') {
      const admin = await list(UserModel, { accountId: req.params.accountId, role: 'admin' }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
      if (admin.result.count < 2) {
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    user = await deleteOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 })
    return user
  })

  apiServer.post('/v1/accounts/permission/:permissionFor', async req => {
    const tokenData = allowAccessTo(req, secrets, [{ type: 'user' }])
    const findUser = await list(UserModel, { email: tokenData.user.email })
    const checkPass = await verifyAndUpgradePassword(findUser.result.items[0], req.body.password, UserModel)
    if (!checkPass) {
      throw new AuthenticationError('Invalid password')
    }
    const payload = {
      type: req.params.permissionFor,
      user: tokenData.user,
      account: tokenData.account,
      project: tokenData.project,
      role: tokenData.role
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '5m' })
    return {
      status: 200,
      result: {
        permissionToken: token
      }
    }
  })

  apiServer.get('/v1/accounts/:accountId/users/:id/access-token', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'login', user: { _id: req.params.id }, account: { _id: req.params.accountId } }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const findUser = await readOne(UserModel, { _id: req.params.id, accountId: req.params.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
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
    if (findUser.result.role === 'client') {
      payload.projectsAccess = {}
      findUser.result.projectsAccess.forEach(ele => {
        payload.projectsAccess[ele.projectId] = ele.permission
      })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })

    return {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/:accountId/users/:id/finalize-registration', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'registration', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: data.user._id, accountId: req.params.accountId }, { role: 'admin', verified: true })
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
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })

  apiServer.get('/v1/accounts/:accountId/projects-for-access', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'user' }, { type: 'user', role: 'admin' }])
    if (!ProjectModel) {
      return {
        status: 200,
        result: {
          disabled: true
        }
      }
    }
    const projects = await list(ProjectModel, { accountId: req.params.accountId }, { ...req.query, select: { name: 1 } })
    return {
      status: 200,
      result: projects.result.items
    }
  })

  apiServer.get('/v1/accounts/:accountId/users', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'user' }, { type: 'user', role: 'admin' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)
    const userList = await list(UserModel, { accountId: req.params.accountId }, { ...req.query, select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    return userList
  })

  apiServer.post('/v1/accounts/:accountId/users', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'user' }, { type: 'user', role: 'admin' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)
    const isClient = req.body.role === 'client'
    const checkUser = await list(UserModel, { email: req.body.email, accountId: req.params.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    if (checkUser.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const hash = await bcrypt.hash(req.body.password, 10)
    await hooks?.checkEmail(req.body.email)
    const newUser = await createOne(UserModel, req.params, { ...req.body, password: hash, verified: true })
    if (!isClient) {
      hooks?.createNewUser?.post({ accountId: req.params.accountId, name: newUser.result.name, email: newUser.result.email })
    }
    return newUser
  })

  apiServer.get('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    user.result.password = !!user.result.password
    user.result.googleProfileId = !!user.result.googleProfileId
    user.result.microsoftProfileId = !!user.result.microsoftProfileId
    user.result.githubProfileId = !!user.result.githubProfileId
    return user
  })

  apiServer.postBinary('/v1/accounts/:accountId/users/:id/profile-picture', { mimeTypes: ['image/jpeg', 'image/png', 'image/gif'], fieldName: 'profilePicture', maxFileSize: process.env.MAX_FILE_SIZE }, async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const type = await fileTypeFromBuffer(req.file.buffer)
    const uploadParams = {
      Bucket: process.env.AWS_BUCKET_NAME,
      Body: req.file.buffer,
      ACL: 'public-read',
      ContentType: type.mime,
      Key: `${process.env.AWS_FOLDER_NAME}/users/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }

    const result = await s3.upload(uploadParams).promise()
    await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { profilePicture: process.env.CDN_BASE_URL + result.Key })
    return {
      status: 200,
      result: {
        profilePicture: process.env.CDN_BASE_URL + result.Key
      }
    }
  })
  apiServer.delete('/v1/accounts/:accountId/users/:id/profile-picture', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const userData = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    const key = userData.result.profilePicture.substring(userData.result.profilePicture.lastIndexOf('/') + 1)
    await s3.deleteObject({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `${process.env.AWS_FOLDER_NAME}/users/${key}`
    }).promise()
    await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { profilePicture: null })
    return {
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
    if (getUser.result.role === 'client') {
      payload.projectsAccess = {}
      getUser.result.projectsAccess.forEach(ele => {
        payload.projectsAccess[ele.projectId] = ele.permission
      })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendUserEmail(getUser.result.email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION, { link: `${process.env.APP_URL}accounts/finalize-registration?token=${token}` })
    return {
      status: 200,
      result: {
        newAccount: getAccount.result,
        newUser: getUser.result,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/accounts/:accountId/users/:id/provider/:provider', async req => {
    allowAccessTo(req, secrets, [{ type: 'disconnect' }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    switch (req.params.provider) {
      case 'google':
        user.result.googleProfileId = null
        break
      case 'microsoft':
        user.result.microsoftProfileId = null
        break
      case 'github':
        user.result.githubProfileId = null
        break
    }
    if (!user.result.password && !user.result.googleProfileId && !user.result.microsoftProfileId && !user.result.githubProfileId) {
      throw new MethodNotAllowedError('Password is required')
    }
    const updatedUser = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { ...user.result })
    updatedUser.result.password = !!updatedUser.result.password
    updatedUser.result.googleProfileId = !!updatedUser.result.googleProfileId
    updatedUser.result.microsoftProfileId = !!updatedUser.result.microsoftProfileId
    updatedUser.result.githubProfileId = !!updatedUser.result.githubProfileId
    return updatedUser
  })
}
