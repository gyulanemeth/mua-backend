import allowAccessTo from 'bearer-jwt-auth'
import { list } from 'mongoose-crudl'

export default async ({ apiServer, UserModel, AccountModel }) => {
  const secrets = process.env.SECRETS.split(' ')
  apiServer.get('/v1/statistics/accounts/', async req => {
    await allowAccessTo(req, secrets, [{ type: 'admin' }])
    return list(AccountModel, null, { ...req.query, select: { createdAt: 1, deleted: 1 } })
  })

  apiServer.get('/v1/statistics/users/', async req => {
    await allowAccessTo(req, secrets, [{ type: 'admin' }])
    return list(UserModel, null, { ...req.query, select: { createdAt: 1, deleted: 1 } })
  })
}
