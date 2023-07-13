import mongoose from 'mongoose'
import sendEmail from 'aws-ses-send-email'

import routes from './routes/index.js'
import connectors from './connectors/index.js'

const api = routes(sendEmail, connectors(), process.env.MAX_FILE_SIZE)

await mongoose.connect(process.env.MONGO_URL).catch(e => console.error(e))

api.listen(process.env.PORT, () => {
  console.log(`MUA Accounts API is listening on ${process.env.PORT}`)
})
