import allowAccessTo from 'bearer-jwt-auth'
import { list } from 'mongoose-crudl'
import { MethodNotAllowedError } from 'standard-api-errors'

const formatDate = (updatedAt, type, timeZone) => {
  const date = new Date(new Date(updatedAt).toLocaleString('en-US', { timeZone: timeZone || 'UTC' }))
  switch (type) {
    case 'hourly':
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`
    case 'daily':
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
    case 'weekly': {
      const start = new Date(date)
      start.setDate(start.getDate() - start.getDay()) // Sunday of the same week
      start.setHours(0, 0, 0, 0)
      const end = new Date(start)
      end.setDate(end.getDate() + 6) // Saturday of the same week
      end.setHours(23, 59, 59, 999)
      return `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')} to ${end.getFullYear()}-${String(end.getMonth() + 1).padStart(2, '0')}-${String(end.getDate()).padStart(2, '0')}`
    }
    case 'monthly':
    default:
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
  }
}

function getStartDate (filter, type) {
  if (filter.startDate) {
    const date = new Date(filter.startDate)
    date.setUTCHours(0, 0, 0, 0)
    return new Date(date)
  }
  if (type !== 'hourly') {
    const date = new Date()
    date.setUTCMonth(date.getMonth() - 1)
    date.setUTCHours(0, 0, 0, 0)
    return new Date(date)
  }
  return new Date(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).setUTCHours(0, 0, 0, 0))
}

function getEndDate (filter) {
  if (filter.endDate) {
    const date = new Date(filter.endDate)
    date.setUTCHours(23, 59, 59, 999)
    return new Date(date)
  }
  const date = new Date()
  date.setUTCHours(23, 59, 59, 999)
  return new Date(date)
}

export default async ({ apiServer, UserModel, AccountModel }) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.get('/v1/statistics/overall/', async req => {
    await allowAccessTo(req, secrets, [{ type: 'admin' }])
    const filter = req.query.filter || {}
    const activeUsers = await UserModel.count({ ...filter, deleted: { $ne: true } })
    const deletedUsers = await UserModel.count({ ...filter, deleted: true })
    const activeAccounts = await AccountModel.count({ ...filter, deleted: { $ne: true } })
    const deletedAccounts = await AccountModel.count({ ...filter, deleted: true })
    return {
      status: 200,
      result: {
        activeAccounts,
        deletedAccounts,
        activeUsers,
        deletedUsers
      }
    }
  })

  apiServer.get('/v1/statistics/accounts/', async req => {
    await allowAccessTo(req, secrets, [{ type: 'admin' }])
    const filter = req.query.filter || {}
    const type = filter.type || 'monthly'
    const startDate = getStartDate(filter, type)
    const endDate = getEndDate(filter, type)
    const accounts = {}
    let createdAt
    const maxRange = type === 'hourly' ? 8 * 24 * 60 * 60 * 1000 : 365 * 24 * 60 * 60 * 1000
    const validRange = (endDate - startDate) <= maxRange
    if (!validRange) {
      throw new MethodNotAllowedError(`Date range exceeds the maximum allowed: ${type === 'hourly' ? '7 days' : '12 months'}.`)
    }
    delete filter.startDate
    delete filter.endDate
    delete filter.type
    let accumulatedAccounts = await AccountModel.count({ ...filter, deleted: { $ne: true }, createdAt: { $lt: startDate } })
    let accumulatedDeletedAccounts = await AccountModel.count({ ...filter, deleted: true, createdAt: { $lt: startDate } })
    const accountsList = await list(AccountModel, req.params, { filter: { ...filter, createdAt: { $gte: startDate, $lte: endDate } }, sort: { createdAt: 1 }, limit: 'unlimited' })
    for (const element of accountsList.result.items) {
      createdAt = formatDate(element.createdAt, type, req.query.timeZone)
      if (!accounts[createdAt]) {
        accounts[createdAt] = { accounts: 0, deleted: 0 }
      }
      if (element.deleted) {
        accounts[createdAt].deleted = accounts[createdAt].deleted + 1
      } else {
        accounts[createdAt].accounts = accounts[createdAt].accounts + 1
      }
    }
    const sortedAccounts = Object.fromEntries(
      Object.entries(accounts).sort(([a], [b]) => new Date(a) - new Date(b))
    )
    for (const [key] of Object.entries(sortedAccounts)) {
      accumulatedAccounts = accumulatedAccounts + sortedAccounts[key].accounts
      sortedAccounts[key].accumulatedAccounts = accumulatedAccounts
      accumulatedDeletedAccounts = accumulatedDeletedAccounts + sortedAccounts[key].deleted
      sortedAccounts[key].accumulatedDeletedAccounts = accumulatedDeletedAccounts
    }
    return {
      status: 200,
      result: {
        ...accounts
      }
    }
  })

  apiServer.get('/v1/statistics/users/', async req => {
    await allowAccessTo(req, secrets, [{ type: 'admin' }])
    const filter = req.query.filter || {}
    const type = filter.type || 'monthly'
    const startDate = getStartDate(filter, type)
    const endDate = getEndDate(filter, type)
    const users = {}
    let createdAt
    const maxRange = type === 'hourly' ? 8 * 24 * 60 * 60 * 1000 : 365 * 24 * 60 * 60 * 1000
    const validRange = (endDate - startDate) <= maxRange
    if (!validRange) {
      throw new MethodNotAllowedError(`Date range exceeds the maximum allowed: ${type === 'hourly' ? '7 days' : '12 months'}.`)
    }
    delete filter.startDate
    delete filter.endDate
    delete filter.type
    let accumulatedUsers = await UserModel.count({ ...filter, deleted: { $ne: true }, createdAt: { $lt: startDate } })
    let accumulatedDeletedUsers = await UserModel.count({ ...filter, deleted: true, createdAt: { $lt: startDate } })
    const usersList = await list(UserModel, req.params, { filter: { ...filter, createdAt: { $gte: startDate, $lte: endDate } }, sort: { createdAt: 1 }, limit: 'unlimited' })
    for (const element of usersList.result.items) {
      createdAt = formatDate(element.createdAt, type, req.query.timeZone)
      if (!users[createdAt]) {
        users[createdAt] = { users: 0, deleted: 0 }
      }
      if (element.deleted) {
        users[createdAt].deleted = users[createdAt].deleted + 1
      } else {
        users[createdAt].users = users[createdAt].users + 1
      }
    }
    const sortedUsers = Object.fromEntries(
      Object.entries(users).sort(([a], [b]) => new Date(a) - new Date(b))
    )
    for (const [key] of Object.entries(sortedUsers)) {
      accumulatedUsers = accumulatedUsers + sortedUsers[key].users
      sortedUsers[key].accumulatedUsers = accumulatedUsers
      accumulatedDeletedUsers = accumulatedDeletedUsers + sortedUsers[key].deleted
      sortedUsers[key].accumulatedDeletedUsers = accumulatedDeletedUsers
    }
    return {
      status: 200,
      result: {
        ...users
      }
    }
  })
}
