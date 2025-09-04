import bcrypt from 'bcrypt'

import jwt from 'jsonwebtoken'
import svgCaptcha from 'svg-captcha'

export default {
  generate: async (secrets, expiresIn = 60) => {
    const captcha = svgCaptcha.create()

    const hash = await bcrypt.hash(captcha.text, 10)

    const probe = jwt.sign({ hash }, secrets[0], { expiresIn })

    return {
      text: captcha.text,
      data: captcha.data,
      probe
    }
  },
  validate: async (secrets, { text, probe }) => {
    let probeData = null
    for (let idx = 0; idx < secrets.length; idx += 1) {
      try {
        probeData = jwt.verify(probe, secrets[idx])
      } catch (e) {}
    }

    if (!probeData) {
      return false
    }
    const hash = await bcrypt.compare(text, probeData.hash)
    return hash
  }
}
