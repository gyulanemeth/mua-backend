import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import mongoose from 'mongoose'
import { verifyAndUpgradePassword } from './verifyAndUpgradePassword.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const SystemAdminTestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('verifyAndUpgradePassword', () => {
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('check and update password', async () => {
    const hash1 = crypto.createHash('md5').update('testPassword').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const checkPass = await verifyAndUpgradePassword(user1, 'testPassword', SystemAdminTestModel)
    const adminData = await SystemAdminTestModel.findOne({ _id: user1._id })
    expect(checkPass).toBe(true)
    expect(adminData.password).toContain('$2')
  })

  test('error check password not passing', async () => {
    const hash1 = crypto.createHash('md5').update('testPassword').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const checkPass = await verifyAndUpgradePassword(user1, 'test123Password', SystemAdminTestModel)

    expect(checkPass).toBe(false)
  })
})
