import nodemailer from 'nodemailer'
import { ValidationError } from 'standard-api-errors'

const transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  secure: false,
  auth: {
    user: 'jena.waelchi3@ethereal.email',
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
    await transporter.sendMail(mailOptions)
    return {
      status: 200,
      result: {
        success: true
      }
    }
  } catch (err) {
    return new ValidationError('Check your sending to field')
  }
}
