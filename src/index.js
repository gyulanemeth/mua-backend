import mongoose from 'mongoose'

import User from './models/User.js'
import Account from './models/Account.js'

import crypto from 'crypto'
import routes from './routes/index.js'
import dotenv from 'dotenv'
dotenv.config({ path: '../.env' })
const api = routes()

await mongoose.connect('mongodb://0.0.0.0:27017/mua-system-accounts').catch(e => console.error(e))
/*
const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
await account1.save()

const account2 = new Account({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })
await account2.save()

const account3 = new Account({ name: 'accountExample3', urlFriendlyName: 'urlFriendlyNameExample3' })
await account3.save()

const account4 = new Account({ name: 'accountExample4', urlFriendlyName: 'urlFriendlyNameExample4' })
await account4.save()

const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
await user1.save()

const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
await user2.save()


const hash3 = crypto.createHash('md5').update('user3Password').digest('hex')
const user3 = new User({ email: 'user3@gmail.com', name: 'user3', password: hash3, accountId: account2._id })
await user3.save()

const hash4 = crypto.createHash('md5').update('user4Password').digest('hex')
const user4 = new User({ email: 'user4@gmail.com', name: 'user4', password: hash4, accountId: account3._id })
await user4.save()
*/


api.listen(process.env.PORT, () => {
  console.log(`MUA Accounts API is listening on ${process.env.PORT}`)
})
