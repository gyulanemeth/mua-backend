import Email from './Email.js'

describe('Email testing', () => {
  test('success Send Email ', async () => {
    const res = await Email('example@example.com', 'send Email TEST ', '<h1>Email send successfully </h1>')
    expect(res.status).toBe(200)
  })

  test('Send Email without to email Validation error   ', async () => {
    const res = await Email('', 'send Email TEST', '<h1>Should Not Be Sent </h1>')
    expect(res.status).toBe(400)
  })
})
