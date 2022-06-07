import { list, readOne, patchOne, createOne } from 'mongoose-crudl'
import allowAccessTo from 'bearer-jwt-auth'
import AccounModel from '../models/Account.js'
import UserModel from '../models/User.js'
import { MethodNotAllowedError, ValidationError, NotFoundError } from 'standard-api-errors'

import allowAccessTo from 'bearer-jwt-auth'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/accounts/:accountId/invitation/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)
    const checkUser = await list(UserModel, { email: req.body.user.email, accountId:req.params.accountId }, req.query)
    if(checkUser.result.count !== 0){
      throw new MethodNotAllowedError('User exist')
    }
    const newUser = await createOne(UserModel, { email:req.body.email, accountId: req.params.accountId }, req.query)

    const payload = {
      type: 'invitation',
      user: {
        _id: newUser.result._id,
        email: newUser.result.email,
      }
    }
    const token = jwt.sign(payload, secrets[0])
    /*const template = handlebars.compile(Invitation)
    const html = template({ token })
    Email('example@example.com', 'invitation link ', html)
*/
    return {
      status: 201,
      result: {
        success: true
      }
    }


    })

  apiServer.post('/v1/accounts/:accountId/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation' }])
    await readOne(AccountModel, { id: req.params.accountId }, req.query)

    const user = await readOne(UserModel, { id: data.user._id, email: data.user.email, accountId:re.params.accountId }, req.query)

    if (user.result.password) {
      throw new MethodNotAllowedError('User already has a password')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }

    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const updatedUser = await patchOne(UserModel, { id: data.user._id }, { password: hash })
    const payload = {
      type: 'login',
      user: {
        _id: updatedUser.result._id,
        email: updatedUser.result.email
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
