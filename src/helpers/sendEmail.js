import nodemailer from 'nodemailer'
import { ValidationError } from 'standard-api-errors'

const mailOptions = {
  from: 'testing@gmail.com',
  to: '',
  subject: '', // Subject line
  html: '' // html body
}

export default async (to, subject, template) => {
  try {
    let transporter
    if (process.env.NODE_ENV === 'production') {
      transporter = await nodemailer.createTransport(
        {
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: {
            user: 'email@gmail.com',
            pass: '123123123'
          }
        })
    } else {
      const testAccount = await nodemailer.createTestAccount()
      transporter = await nodemailer.createTransport(
        {
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: {
            user: testAccount.user,
            pass: testAccount.pass
          }
        })
    }
    mailOptions.to = to
    mailOptions.subject = subject
    mailOptions.html = template

    const info = await transporter.sendMail(mailOptions).then(res => res)
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
