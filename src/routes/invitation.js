import crypto from 'crypto'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import { list, readOne, patchOne, createOne, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const Invitation = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'invitation.html'), 'utf8')

const secrets = process.env.SECRETS.split(' ')

export default (apiServer, sendEmail) => {
  apiServer.post('/v1/accounts/:id/invitation/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const checkAccount = await readOne(AccountModel, { id: req.params.id }, req.query)

    const checkUser = await list(UserModel, { email: req.body.email, accountId: req.params.id }, req.query)
    if (checkUser.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const newUser = await createOne(UserModel, req.params, { email: req.body.email, accountId: req.params.id })
    const payload = {
      type: 'invitation',
      user: {
        _id: newUser.result._id,
        email: newUser.result.email
      },
      account: {
        _id: checkAccount.result._id,
        urlFriendlyName: checkAccount.result.urlFriendlyName
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(Invitation)
    const html = template({ href: `${process.env.APP_URL}invitation/accept?token=${token}` })
    let mail
    try {
      mail = await sendEmail({ to: newUser.result.email, subject: 'invitation link ', html })
    } catch (e) {
      await deleteOne(UserModel, { id: newUser.result._id, accountId: checkAccount.result._id })
      throw e
    }

    return {
      status: 201,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/accounts/:id/invitation/resend', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const getAccount = await readOne(AccountModel, { id: req.params.id }, req.query)

    const getUser = await list(UserModel, { email: req.body.email, accountId: req.params.id }, req.query)
    if (getUser.result.count === 0) {
      throw new MethodNotAllowedError("User dosen't exist")
    }

    if (getUser.result.items[0].name) {
      throw new MethodNotAllowedError('User already verified')
    }

    const payload = {
      type: 'invitation',
      user: {
        _id: getUser.result.items[0]._id,
        email: getUser.result.items[0].email
      },
      account: {
        _id: getAccount.result._id,
        urlFriendlyName: getAccount.result.urlFriendlyName
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(Invitation)
    const html = template({ href: `${process.env.APP_URL}invitation/accept?token=${token}` })
    const mail = await sendEmail({ to: getUser.result.items[0].email, subject: 'invitation link ', html })

    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/accounts/:id/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation', account: { _id: req.params.id } }])

    const user = await readOne(UserModel, { id: data.user._id, email: data.user.email, accountId: req.params.id }, req.query)

    if (user.result.password) { // check if user accepted the invitation before and completed the necessary data.
      throw new MethodNotAllowedError('Token already used, user exists')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const updatedUser = await patchOne(UserModel, { id: data.user._id }, { password: hash, name: req.body.name })
    const payload = {
      type: 'login',
      user: {
        _id: updatedUser.result._id,
        email: updatedUser.result.email
      },
      account: {
        _id: updatedUser.result.accountId
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
}
