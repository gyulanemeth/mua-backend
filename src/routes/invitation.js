import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import { list, readOne, patchOne, createOne, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

export default ({
  apiServer, UserModel, AccountModel, SystemAdminModel, hooks = {
    createNewUser: { post: (params) => { } }
  }
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const sendInvitation = async (url, email, data) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
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

  apiServer.post('/v1/accounts/:id/invitation/send', async req => {
    const tokenData = await allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const checkAccount = await readOne(AccountModel, { id: req.params.id }, req.query)

    const checkUser = await list(UserModel, { email: req.body.email, accountId: req.params.id }, req.query)
    if (checkUser.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const newUser = await createOne(UserModel, req.params, { email: req.body.email, accountId: req.params.id, verified: true })
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
    let inviterData
    if (tokenData.type === 'user') {
      inviterData = await readOne(UserModel, { id: tokenData.user._id })
    } else {
      inviterData = await readOne(SystemAdminModel, { id: tokenData.user._id })
    }
    let mail
    try {
      mail = await sendInvitation(process.env.BLUEFOX_TEMPLATE_ACCOUNT_INVITATION, newUser.result.email, { link: `${process.env.APP_URL}accounts/invitation/accept?token=${token}`, inviter: inviterData.result.name, accountName: checkAccount.result.name })
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

  apiServer.post('/v1/system-admins/invitation/send', async req => {
    const tokenData = await allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(SystemAdminModel, req.body, { select: { password: 0 } })
    if (response.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const newAdmin = await createOne(SystemAdminModel, req.body, req.query)
    const inviterData = await readOne(SystemAdminModel, { id: tokenData.user._id })

    const payload = {
      type: 'invitation',
      user: {
        _id: newAdmin.result._id,
        email: newAdmin.result.email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    let mail
    try {
      mail = await sendInvitation(process.env.BLUEFOX_TEMPLATE_ADMIN_INVITATION, newAdmin.result.email, { link: `${process.env.APP_URL}system-admins/invitation/accept?token=${token}`, inviter: inviterData.result.name })
    } catch (e) {
      await deleteOne(SystemAdminModel, { id: newAdmin.result._id })
      throw e
    }
    return {
      status: 201,
      result: {
        success: true,
        info: { mail: mail.result.info, admin: newAdmin.result }
      }
    }
  })

  apiServer.post('/v1/accounts/:id/invitation/resend', async req => {
    const tokenData = await allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
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
    let inviterData
    if (tokenData.type === 'user') {
      inviterData = await readOne(UserModel, { id: tokenData.user._id })
    } else {
      inviterData = await readOne(SystemAdminModel, { id: tokenData.user._id })
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendInvitation(process.env.BLUEFOX_TEMPLATE_ACCOUNT_INVITATION, getUser.result.items[0].email, { link: `${process.env.APP_URL}accounts/invitation/accept?token=${token}`, inviter: inviterData.result.name, accountName: getAccount.result.name })
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/system-admins/invitation/resend', async req => {
    const tokenData = await allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(SystemAdminModel, req.body, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new MethodNotAllowedError("User dosen't exist")
    }
    if (response.result.items[0].name) {
      throw new MethodNotAllowedError('User already verified')
    }
    const payload = {
      type: 'invitation',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }

    const inviterData = await readOne(SystemAdminModel, { id: tokenData.user._id })
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendInvitation(process.env.BLUEFOX_TEMPLATE_ADMIN_INVITATION, response.result.items[0].email, { link: `${process.env.APP_URL}system-admins/invitation/accept?token=${token}`, inviter: inviterData.result.name })
    return {
      status: 201,
      result: {
        success: true,
        info: { mail: mail.result.info, admin: response.result.items[0] }
      }
    }
  })

  apiServer.post('/v1/accounts/:id/invitation/accept', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'invitation', account: { _id: req.params.id } }])

    const user = await readOne(UserModel, { id: data.user._id, email: data.user.email, accountId: req.params.id }, req.query)

    if (user.result.password) { // check if user accepted the invitation before and completed the necessary data.
      throw new MethodNotAllowedError('Token already used, user exists')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const updatedUser = await patchOne(UserModel, { id: data.user._id }, { password: hash, name: req.body.name })
    hooks.createNewUser.post({ accountId: req.params.id, name: updatedUser.result.name, email: updatedUser.result.email })

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

  apiServer.post('/v1/system-admins/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation' }])
    const response = await list(SystemAdminModel, { id: data.user._id, email: data.user.email }, req.query)
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    if (response.result.items[0].password) { // check if user accepted the invitation before and completed the necessary data.
      throw new MethodNotAllowedError('Token already used, user exists')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }

    const hash = crypto.createHash('md5').update(req.body.newPasswordAgain).digest('hex')
    const updatedAdmin = await patchOne(SystemAdminModel, { id: data.user._id }, { password: hash, name: req.body.name })
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
