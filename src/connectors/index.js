import jwt from 'jsonwebtoken'

import { createDeleteConnector } from 'standard-json-api-connectors'
import { ValidationError } from 'standard-api-errors'

const secrets = process.env.SECRETS.split(' ')
const apiUrl = process.env.EMAILFOX_API_URL

export default () => {
  const generateAdditionalHeaders = (params) => {
    const token = jwt.sign({ type: 'account-backend' }, secrets[0])
    return { Authorization: `Bearer ${token}` }
  }

  const generateDeleteAccountRoute = (params) => {
    return `/v1/accounts/${params.id}`
  }

  const deletAccountRoute = createDeleteConnector(fetch, apiUrl, generateDeleteAccountRoute, generateAdditionalHeaders)

  const deleteAccount = async function (param) {
    if (!param || !param.id) {
      throw new ValidationError('Id Is Required')
    }
    const res = await deletAccountRoute(param)
    return res
  }

  return {
    deleteAccount
  }
}
