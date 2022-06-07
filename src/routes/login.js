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





}
