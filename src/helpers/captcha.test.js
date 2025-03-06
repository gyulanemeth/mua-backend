import { vi, describe, test, expect } from 'vitest'

import captcha from './captcha.js'

describe('captcha', () => {
  test('validation successful with the first secret', () => {
    const secrets = ['asdf1234', '4321fdsa']
    const captchaData = captcha.generate(secrets)

    const validationResult = captcha.validate(secrets, { text: captchaData.text, probe: captchaData.probe })

    expect(validationResult).toBe(true)
  })

  test('validation successful with the second secret', () => {
    const secrets = ['asdf1234', '4321fdsa']
    const captchaData = captcha.generate(secrets)

    secrets.unshift('aaaa1111')

    const validationResult = captcha.validate(secrets, { text: captchaData.text, probe: captchaData.probe })

    expect(validationResult).toBe(true)
  })

  test('validation unsuccessful: expired probe', () => {
    vi.useFakeTimers()
    const secrets = ['asdf1234', '4321fdsa']
    const captchaData = captcha.generate(secrets, 10)

    vi.advanceTimersByTime(20000)

    const validationResult = captcha.validate(secrets, { text: captchaData.text, probe: captchaData.probe })

    expect(validationResult).toBe(false)
    vi.useRealTimers()
  })

  test('validation unsuccessful: wrong text', () => {
    vi.useFakeTimers()
    const secrets = ['asdf1234', '4321fdsa']
    const captchaData = captcha.generate(secrets, 10)

    vi.advanceTimersByTime(20000)

    const validationResult = captcha.validate(secrets, { text: captchaData.text + 'something else', probe: captchaData.probe })

    expect(validationResult).toBe(false)
    vi.useRealTimers()
  })
})
