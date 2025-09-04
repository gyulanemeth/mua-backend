import captcha from '../helpers/captcha.js'

export default async ({ apiServer }) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.get('/v1/captcha', async req => {
    const res = await captcha.generate(secrets)
    return {
      status: 200,
      result: {
        probe: res.probe,
        data: res.data
      }
    }
  })
}
