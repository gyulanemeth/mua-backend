import nodemailer from 'nodemailer'
import { ValidationError } from 'standard-api-errors'

const transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  secure: false,
  requireTLS: true,
  auth: {
    user: 'maud.hudson78@ethereal.email',
    pass: process.env.Email_Pass
  }
})

const mailOptions = {
  from: 'testing@gmail.com',
  to: '',
  subject: '', // Subject line
  html: '' // html body
}

export default async (to, subject, template) => {
  mailOptions.to = to
  mailOptions.subject = subject
  mailOptions.html = template
  try {
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
