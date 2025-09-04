import bcrypt from 'bcrypt'

import jwt from 'jsonwebtoken'

import { list, patchOne, readOne } from 'mongoose-crudl'
import allowAccessTo from 'bearer-jwt-auth'
import { ValidationError, AuthenticationError } from 'standard-api-errors'
import captcha from '../helpers/captcha.js'

export default ({ apiServer, UserModel, SystemAdminModel, AccountModel }) => {
  const secrets = process.env.SECRETS.split(' ')
  const sendForgotPassword = async (email, transactionalId, data) => {
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

  apiServer.post('/v1/accounts/:id/forgot-password/send', async req => {
    const validationResult = await captcha.validate(secrets, { text: req.body.captchaText, probe: req.body.captchaProbe })
    if (!validationResult) {
      throw new ValidationError('Invalid CAPTCHA. Please try again.')
    }
    const response = await list(UserModel, { email: req.body.email, accountId: req.params.id }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
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
    const mail = await sendForgotPassword(response.result.items[0].email, process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FORGOT_PASSWORD, { link: `${process.env.APP_URL}accounts/forgot-password/reset?token=${token}`, name: response.result.items[0].name, user: { name: response.result.items[0].name, email: response.result.items[0].email, profilePicture: response.result.items[0].profilePicture } })
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/system-admins/forgot-password/send', async req => {
    const validationResult = await captcha.validate(secrets, { text: req.body.captchaText, probe: req.body.captchaProbe })
    if (!validationResult) {
      throw new ValidationError('Invalid CAPTCHA. Please try again.')
    }
    const response = await list(SystemAdminModel, req.body, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    const payload = {
      type: 'forgot-password',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendForgotPassword(response.result.items[0].email, process.env.BLUEFOX_TEMPLATE_ID_ADMIN_FORGOT_PASSWORD, { link: `${process.env.APP_URL}system-admins/forgot-password/reset?token=${token}`, name: response.result.items[0].name, user: { name: response.result.items[0].name, email: response.result.items[0].email, profilePicture: response.result.items[0].profilePicture } })
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
    const response = await list(UserModel, { email: data.user.email, accountId: req.params.id }, { select: { password: 0, googleProfileId: 0, microsoftProfileId: 0, githubProfileId: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Email Authentication Error ')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = await bcrypt.hash(req.body.newPassword, 10)
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

  apiServer.post('/v1/system-admins/forgot-password/reset', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'forgot-password' }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = await bcrypt.hash(req.body.newPassword, 10)
    const updatedAdmin = await patchOne(SystemAdminModel, { id: data.user._id, email: data.user.email }, { password: hash })
    const payload = {
      type: 'login',
      user: {
        _id: updatedAdmin.result._id,
        email: updatedAdmin.result.email
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
