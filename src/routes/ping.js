import mongoose from 'mongoose'

export default apiServer => {
  apiServer.get('/v1/ping', () => {
    return {
      status: 200,
      result: 'pong'
    }
  })

  apiServer.get('/v1/ping/mongo', async () => {
    if (mongoose.connection.readyState === 1) {
      return {
        status: 200,
        result: 'pong'
      }
    }
    
    return {
      status: 500,
      error: 'MongoDB connection is not ready'
    }
  })
}
