import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import { list, readOne, patchOne, createOne, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

export default ({
  apiServer, UserModel, AccountModel
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const sendInvitation = async (email, token) => {
    const url = process.env.ACCOUNT_BLUEFOX_INVITATION_TEMPLATE
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.APP_URL}system-accounts-invitation/accept?token=${token}` }
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
    let mail
    try {
      mail = await sendInvitation(newUser.result.email, token)
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
    const mail = await sendInvitation(getUser.result.items[0].email, token)
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
