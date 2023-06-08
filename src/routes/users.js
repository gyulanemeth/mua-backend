import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import crypto from 'crypto'
import handlebars from 'handlebars'

import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'

import { list, readOne, deleteOne, patchOne, createOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'

import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'
import sendEmail from 'aws-ses-send-email'

const secrets = process.env.SECRETS.split(' ')

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const VerifyEmail = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'verifyEmail.html'), 'utf8')

export default (apiServer) => {
  apiServer.patch('/v1/accounts/:accountId/users/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { name: req.body.name })
    return user
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
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: hash })
    return user
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
    const updatedUser = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { role: req.body.role })
    return updatedUser
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
    const template = handlebars.compile(VerifyEmail)
    const html = template({ href: `${process.env.APP_URL}verify-email?token=${token}` })
    const mail = await sendEmail({ to: req.body.newEmail, subject: 'verify email link ', html })

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
    await patchOne(UserModel, { id: req.params.id }, { email: data.newEmail })
    return {
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
    user = await deleteOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query)
    return user
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
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
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

    return {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.post('/v1/accounts/:accountId/users/:id/finalize-registration', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'registration', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await patchOne(UserModel, { id: data.user._id, accountId: req.params.accountId }, { role: 'admin' })
    return user
  })

  apiServer.get('/v1/accounts/:accountId/users', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)
    const userList = await list(UserModel, { accountId: req.params.accountId }, { ...req.query, select: { password: 0 } })
    return userList
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

    return newUser
  })

  apiServer.get('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id }, account: { _id: req.params.accountId } }])
    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { select: { password: 0 } })
    return user
  })
}
