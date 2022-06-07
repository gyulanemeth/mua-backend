import mongoose from 'mongoose'
const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true},
  password: { type: String },
  role: { type: String, default: 'user' },
  accountId: {  type:  Schema.Types.ObjectId, ref: 'Account', required: true },
})

export default mongoose.model('User', UserSchema)
