import crypto from 'crypto'

function encrypt (data) {
  const key = process.env.ENCRYPTION_SECRET_KEY
  if (data) {
    const encryptKey = key.repeat(32).substr(0, 32)
    const iv = key.repeat(16).substr(0, 16)
    const cipher = crypto.createCipheriv('aes-256-ctr', encryptKey, iv)
    const encrypted = cipher.update(data, 'utf8', 'hex')
    return encrypted + cipher.final('hex')
  }
}

function decrypt (data) {
  const key = process.env.ENCRYPTION_SECRET_KEY
  if (data) {
    const encryptKey = key.repeat(32).substr(0, 32)
    const iv = key.repeat(16).substr(0, 16)
    const decipher = crypto.createDecipheriv('aes-256-ctr', encryptKey, iv)
    const decrypted = decipher.update(data, 'hex', 'utf8')
    return decrypted + decipher.final('utf8')
  }
}

export {
  encrypt,
  decrypt
}
