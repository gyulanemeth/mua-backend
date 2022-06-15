import mongoose from 'mongoose'

const AccountSchema = new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String }
})

export default mongoose.model('Account', AccountSchema)
