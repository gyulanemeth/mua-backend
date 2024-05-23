import allowAccessTo from 'bearer-jwt-auth'

const secrets = process.env.SECRETS.split(' ')

export default ({ apiServer }) => {
  apiServer.get('/v1/config', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    return {
      status: 200,
      result: {
        appUrl: process.env.ACCOUNT_APP_URL,
        role: ['admin', 'user']
      }
    }
  })
}
