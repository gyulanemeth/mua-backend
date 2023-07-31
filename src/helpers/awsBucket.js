
import AWS from 'aws-sdk'
import AWSMock from 'mock-aws-s3'

import { InternalServerError } from 'standard-api-errors'

/*
  Add the following to your .env file:
    AWS_REGION
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
*/

export default async () => {
  let s3
  if (process.env.NODE_ENV === 'test' /* c8 ignore next */ || process.env.NODE_ENV === 'development') {
    /* c8 ignore next 3 */
    if (!process.env.AWS_BUCKET_NAME) {
      throw new InternalServerError('Missing environment variable: AWS_BUCKET_NAME')
    }
    AWSMock.config.basePath = process.env.AWS_BUCKET_PATH // Can configure a basePath for your local buckets
    s3 = AWSMock.S3({
      params: { Bucket: process.env.AWS_BUCKET_NAME }
    })
    await s3.createBucket({ Bucket: process.env.AWS_BUCKET_NAME }).promise()
    /* c8 ignore next 19 */
  } else {
    if (!process.env.AWS_REGION) {
      throw new InternalServerError('Missing environment variable: AWS_REGION')
    }
    if (!process.env.AWS_ACCESS_KEY_ID) {
      throw new InternalServerError('Missing environment variable: AWS_ACCESS_KEY_ID')
    }
    if (!process.env.AWS_SECRET_ACCESS_KEY) {
      throw new InternalServerError('Missing environment variable: AWS_SECRET_ACCESS_KEY')
    }
    const region = process.env.AWS_BUCKET_REGION
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY
    s3 = new AWS.S3({
      region,
      accessKeyId,
      secretAccessKey
    })
  }
  return s3
}
