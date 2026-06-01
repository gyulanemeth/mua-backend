export default ({ apiServer }) => {
  apiServer.get('/v1/turnstile', async req => {
    return {
      status: 200,
      result: { siteKey: process.env.TURNSTILE_SITE_KEY }
    }
  })
}
