import crypto from 'crypto'
import { generateSecret, verify } from '2fa-util'

export default {
  generate: async ({ label, issuer }) => {
    const { secret, qrcode } = await generateSecret(label, issuer)
    return { secret, qrcode }
  },

  validate: ({ code, secret, window = 1 }) => {
    if (!code || !secret) {
      return false
    }
    return verify(String(code), secret, { window })
  },

  generateRecoveryCode: () => {
    const recoveryCode = crypto.randomBytes(10).toString('hex').toUpperCase()
    return {
      recoveryCode
    }
  }
}
