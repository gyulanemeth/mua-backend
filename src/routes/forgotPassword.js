import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'
//import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import AccounModel from '../models/Account.js'
import UserModel from '../models/User.js'
import { MethodNotAllowedError, ValidationError, NotFoundError } from 'standard-api-errors'

import allowAccessTo from 'bearer-jwt-auth'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')




      apiServer.post('/v1/accounts/:accountId/forgot-password/send', async req => {
        await readOne(AccountModel, { id: req.params.accountId }, req.query)

        const response = await readOne(UserModel, { email:req.body.email, accountId: req.params.accountId }, req.query)
        const payload = {
          type: 'forgot-password',
          user: {
            _id: response.result._id,
            email: response.result.email
          }
        }
        const token = jwt.sign(payload, secrets[0])
        /*const template = handlebars.compile(forgetPassword)
        const html = template({ token })
        Email('example@example.com', 'forget password link', html)
        */
        return {
          status: 200,
          result: {
            success: true
          }
        }

        })

      apiServer.post('/v1/accounts/:accountId/forgot-password/reset', async req => {
        const data = allowAccessTo(req, secrets, [{ type: 'forgot-password' }])
        await readOne(AccountModel, { id: req.params.accountId }, req.query)

        if (req.body.password !== req.body.passwordAgain) {
          throw new ValidationError("Validation error passwords didn't match ")
        }
        const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
        const updatedAdmin = await patchOne(UserModel, { id: data.user._id }, { password: hash })
        const payload = {
          type: 'login',
          user: {
            _id: updatedAdmin.result._id,
            email: updatedAdmin.result.email
          }
        }
        const token = 'Bearer ' + jwt.sign(payload, secrets[0])
        return {
          status: 200,
          result: {
            loginToken: token
          }
        }
        })


}
