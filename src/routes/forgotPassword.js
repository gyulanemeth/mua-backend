import { list, patchOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import UserModel from '../models/User.js'
import { ValidationError, AuthenticationError } from 'standard-api-errors'
import Email from '../helpers/Email.js'
import crypto from 'crypto'

import fs from 'fs'
import handlebars from 'handlebars'
import path from 'path'
import { fileURLToPath } from 'url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const forgotPassword = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'forgot-password.html'), 'utf8')

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/accounts/:id/forgot-password/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await list(UserModel, { email: req.body.email, accountId: req.params.id }, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Email Authentication Error ')
    }
    const payload = {
      type: 'forgot-password',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }

    const token = jwt.sign(payload, secrets[0])
    const template = handlebars.compile(forgotPassword)
    const html = template({ token })
    const mail = await Email(response.result.items[0].email, 'forget password link', html)

    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/accounts/:id/forgot-password/reset', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'forgot-password' }])
    const response = await list(UserModel, { email: data.user.email, accountId: req.params.id }, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Email Authentication Error ')
    }
    if (req.body.password !== req.body.passwordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const updatedUser = await patchOne(UserModel, { id: data.user._id }, { password: hash })
    const payload = {
      type: 'login',
      user: {
        _id: updatedUser.result._id,
        email: updatedUser.result.email
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
}
