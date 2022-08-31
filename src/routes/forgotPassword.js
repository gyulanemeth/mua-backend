import crypto from 'crypto'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import { list, patchOne, readOne } from 'mongoose-crudl'
import allowAccessTo from 'bearer-jwt-auth'
import { ValidationError, AuthenticationError } from 'standard-api-errors'

import UserModel from '../models/User.js'
import AccountModel from '../models/Account.js'
import sendEmail from 'aws-ses-send-email'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const forgotPassword = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'forgot-password.html'), 'utf8')

const secrets = process.env.SECRETS.split(' ')

export default (apiServer) => {
  apiServer.post('/v1/accounts/:id/forgot-password/send', async req => {
    const response = await list(UserModel, { email: req.body.email, accountId: req.params.id }, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Email Authentication Error ')
    }
    const getAccount = await readOne(AccountModel, { id: req.params.id }, req.query)
    const payload = {
      type: 'forgot-password',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      },
      account: {
        _id: response.result.items[0].accountId,
        name: getAccount.result.name
      }
    }

    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(forgotPassword)
    const html = template({ href: `${process.env.APP_URL}forgot-password/reset?token=${token}` })
    const mail = await sendEmail({ to: response.result.items[0].email, subject: 'forget password link', html })

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
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const updatedUser = await patchOne(UserModel, { id: data.user._id }, { password: hash })
    const payload = {
      type: 'login',
      user: {
        _id: updatedUser.result._id,
        email: updatedUser.result.email
      },
      account: {
        _id: response.result.items[0].accountId
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
