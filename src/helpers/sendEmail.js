import nodemailer from 'nodemailer'
import aws from '@aws-sdk/client-ses'
import createTextVersion from 'textversionjs'

import { ValidationError } from 'standard-api-errors'

const accessKeyId = process.env.AWS_ACCESS_KEY_ID
const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY

const fromEmailAddress = process.env.FROM_EMAIL_ADDRESS

export default async (to, subject, html) => {
  try {
    let transporter
    /* istanbul ignore else */
    if (process.env.NODE_ENV === 'test') {
      const testAccount = await nodemailer.createTestAccount()
      transporter = await nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      })
    } else {
      const sesClient = new aws.SESClient({
        region: 'us-east-1',
        credentials: {
          accessKeyId,
          secretAccessKey
        }
      })
      transporter = nodemailer.createTransport({
        SES: { ses: sesClient, aws }
      })
    }

    const info = await transporter.sendMail({
      from: fromEmailAddress,
      to,
      subject,
      html,
      text: createTextVersion(html)
    }).then(res => res)
    return {
      status: 200,
      result: {
        info
      }
    }
  } catch (err) {
    return new ValidationError('Check your sending to field')
  }
}
