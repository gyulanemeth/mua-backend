import mongoose from 'mongoose'

import routes from './routes/index.js'

const api = routes()

await mongoose.connect(process.env.MONGO_URL).catch(e => console.error(e))

api.listen(process.env.PORT, () => {
  console.log(`MUA Accounts API is listening on ${process.env.PORT}`)
})
