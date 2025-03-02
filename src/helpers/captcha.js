import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import svgCaptcha from 'svg-captcha'

export default {
  generate: (secrets, expiresIn = 60) => {
    const captcha = svgCaptcha.create()

    const hash = crypto.createHash('md5').update(captcha.text).digest('hex')

    const probe = jwt.sign({ hash }, secrets[0], { expiresIn })

    return {
      text: captcha.text,
      data: captcha.data,
      probe
    }
  },
  validate: (secrets, { text, probe }) => {
    let probeData = null
    for (let idx = 0; idx < secrets.length; idx += 1) {
      try {
        probeData = jwt.verify(probe, secrets[idx])
      } catch (e) {}
    }

    if (!probeData) {
      return false
    }

    const hash = crypto.createHash('md5').update(text).digest('hex')

    return hash === probeData.hash
  }
}
