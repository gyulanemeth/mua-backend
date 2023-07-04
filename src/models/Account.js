import mongoose from 'mongoose'

const AccountSchema = new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String, unique: true },
  logoPath: { type: String }
}, { timestamps: true })
AccountSchema.index({ name: 'text', urlFriendlyName: 'text' })
export default mongoose.model('Account', AccountSchema)
