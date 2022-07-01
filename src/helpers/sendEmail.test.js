import nodemailer from 'nodemailer'
import sendEmail from './sendEmail.js'

describe('Email testing', () => {
  test('success Send Email ', async () => {
    const res = await sendEmail('example@example.com', 'send Email TEST ', '<h1>Email send successfully </h1>')
    expect(res.status).toBe(200)

    const messageUrl = nodemailer.getTestMessageUrl(res.result.info)
    const html = await fetch(messageUrl).then(response => response.text())
    const regex = /Email send successfully/g
    const found = html.match(regex)[0]
    expect(found).toBe('Email send successfully')
  })

  test('Send Email without to email Validation error   ', async () => {
    const res = await sendEmail('', 'send Email TEST', '<h1>Should Not Be Sent </h1>')
    expect(res.status).toBe(400)
  })
})
