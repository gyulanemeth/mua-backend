import crypto from 'crypto'
import bcrypt from 'bcrypt'

import { patchOne } from 'mongoose-crudl'

export default async (user, plainPassword, UserModel) => {
  if (!user) {
    return false
  }
  const stored = user.password
  const isBcrypt = stored && stored.startsWith('$2')

  if (isBcrypt) {
    return bcrypt.compare(plainPassword, stored)
  }

  const md5 = crypto.createHash('md5').update(plainPassword).digest('hex')
  if (md5 === stored) {
    const newHash = await bcrypt.hash(plainPassword, 10)
    await patchOne(UserModel, { id: user._id }, { password: newHash })
    return true
  }

  return false
}
