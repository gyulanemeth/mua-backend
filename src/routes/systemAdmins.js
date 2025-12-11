import bcrypt from 'bcrypt'

import jwt from 'jsonwebtoken'
import mime from 'mime-types'
import { fileTypeFromBuffer } from 'file-type'

import { list, readOne, deleteOne, patchOne } from 'mongoose-crudl'
import { AuthorizationError, MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'
import verifyAndUpgradePassword from '../helpers/verifyAndUpgradePassword.js'

import aws from '../helpers/awsBucket.js'

export default async ({
  apiServer, SystemAdminModel
}) => {
  const secrets = process.env.SECRETS.split(' ')
  const s3 = await aws()
  const sendVerifyEmail = async (email, transactionalId, data) => {
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
      throw res
    }
    return res
  }

  apiServer.get('/v1/system-admins/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(SystemAdminModel, req.params, req.query)
    response.result.items = response.result.items.map(user => {
      user.invitationAccepted = !!user.password
      delete user.password
      return user
    })
    return response
  })

  apiServer.get('/v1/system-admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await readOne(SystemAdminModel, { id: req.params.id }, { ...req.query, select: { password: 0 } })
    return response
  })

  apiServer.delete('/v1/system-admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    const adminCount = await SystemAdminModel.count({})
    if (adminCount === 1) {
      throw new MethodNotAllowedError('Removing the last admin is not allowed')
    }
    const response = await deleteOne(SystemAdminModel, { id: req.params.id }, { password: 0 })
    return response
  })

  apiServer.post('/v1/system-admins/permission/:permissionFor', async req => {
    const tokenData = allowAccessTo(req, secrets, [{ type: 'admin' }])
    const findUser = await list(SystemAdminModel, { email: tokenData.user.email })
    const checkPass = await verifyAndUpgradePassword(findUser.result.items[0], req.body.password, SystemAdminModel)
    if (!checkPass) {
      throw new AuthenticationError('Invalid password')
    }
    const payload = {
      type: req.params.permissionFor,
      user: tokenData.user
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '5m' })
    return {
      status: 200,
      result: {
        permissionToken: token
      }
    }
  })

  apiServer.get('/v1/system-admins/:id/access-token', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }, { type: 'login', user: { _id: req.params.id } }])
    const response = await readOne(SystemAdminModel, { id: req.params.id }, { select: { password: 0 } })
    const payload = {
      type: 'admin',
      user: {
        _id: response.result._id,
        email: response.result.email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.patch('/v1/system-admins/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    await patchOne(SystemAdminModel, { id: req.params.id }, { name: req.body.name })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/system-admins/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError('Validation error passwords didn\'t match.')
    }
    const getAdmin = await readOne(SystemAdminModel, { id: req.params.id }, req.query)
    const checkPass = await verifyAndUpgradePassword(getAdmin.result, req.body.oldPassword, SystemAdminModel)
    if (!checkPass) {
      throw new AuthorizationError('Wrong password.')
    }
    const hash = await bcrypt.hash(req.body.newPassword, 10)
    await patchOne(SystemAdminModel, { id: req.params.id }, { password: hash })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/system-admins/:id/email', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    if (req.body.newEmail !== req.body.newEmailAgain) {
      throw new ValidationError('Validation error email didn\'t match.')
    }
    const checkExist = await list(SystemAdminModel, { email: req.body.newEmail })
    if (checkExist.result.count > 0) {
      throw new MethodNotAllowedError('Email exist')
    }
    const response = await readOne(SystemAdminModel, { id: req.params.id }, { select: { password: 0, email: 0 } })
    const payload = {
      type: 'verfiy-email',
      user: response.result,
      newEmail: req.body.newEmail
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendVerifyEmail(req.body.newEmail, process.env.BLUEFOX_TEMPLATE_ID_ADMIN_VERIFY_EMAIL, { link: `${process.env.APP_URL}system-admins/verify-email?token=${token}`, name: response.result.name, user: { name: response.result.name, email: response.result.email, profilePicture: response.result.profilePicture } })
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/system-admins/:id/email-confirm', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'verfiy-email', user: { _id: req.params.id } }])
    await patchOne(SystemAdminModel, { id: req.params.id }, { email: data.newEmail })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.postBinary('/v1/system-admins/:id/profile-picture', { mimeTypes: ['image/jpeg', 'image/png', 'image/gif'], fieldName: 'profilePicture', maxFileSize: process.env.MAX_FILE_SIZE }, async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    const type = await fileTypeFromBuffer(req.file.buffer)
    const uploadParams = {
      Bucket: process.env.AWS_BUCKET_NAME,
      Body: req.file.buffer,
      ACL: 'public-read',
      ContentType: type.mime,
      Key: `${process.env.AWS_FOLDER_NAME}/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }

    const result = await s3.upload(uploadParams).promise()
    await patchOne(SystemAdminModel, { id: req.params.id }, { profilePicture: process.env.CDN_BASE_URL + result.Key })
    return {
      status: 200,
      result: {
        profilePicture: process.env.CDN_BASE_URL + result.Key
      }
    }
  })

  apiServer.delete('/v1/system-admins/:id/profile-picture', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    const userData = await readOne(SystemAdminModel, { id: req.params.id }, { select: { password: 0, email: 0 } })
    const key = userData.result.profilePicture.substring(userData.result.profilePicture.lastIndexOf('/') + 1)

    await s3.deleteObject({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `${process.env.AWS_FOLDER_NAME}/${key}`
    }).promise()
    await patchOne(SystemAdminModel, { id: req.params.id }, { profilePicture: null })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/system-admins/:id/provider/google', async req => {
    allowAccessTo(req, secrets, [{ type: 'disconnect' }])
    const updatedUser = await patchOne(SystemAdminModel, { id: req.params.id }, { googleProfileId: null })
    updatedUser.result.password = !!updatedUser.result.password
    updatedUser.result.googleProfileId = !!updatedUser.result.googleProfileId
    return updatedUser
  })
}
