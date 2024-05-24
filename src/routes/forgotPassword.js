import crypto from 'crypto'

import jwt from 'jsonwebtoken'

import { list, patchOne, readOne } from 'mongoose-crudl'
import allowAccessTo from 'bearer-jwt-auth'
import { ValidationError, AuthenticationError } from 'standard-api-errors'

export default ({ apiServer, UserModel, AccountModel }) => {
  const sendForgotPassword = async (email, token) => {
    const url = process.env.ACCOUNT_BLUEFOX_FORGOT_PASSWORD_TEMPLATE
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.ACCOUNT_APP_URL}forgot-password/reset?token=${token}` }
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

    const token = jwt.sign(payload, process.env.SECRETS.split(' ')[0], { expiresIn: '24h' })
    const mail = await sendForgotPassword(response.result.items[0].email, token)
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/accounts/:id/forgot-password/reset', async req => {
    const data = allowAccessTo(req, process.env.SECRETS.split(' '), [{ type: 'forgot-password' }])
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
    const token = jwt.sign(payload, process.env.SECRETS.split(' ')[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
