import { vi, describe, test, expect, afterEach } from 'vitest'
import turnstile from './turnstile.js'

describe('turnstile', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('validate returns true when Cloudflare responds with success', async () => {
    process.env.TURNSTILE_SECRET_KEY = 'test-secret-key'
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      json: () => Promise.resolve({ success: true })
    })

    const result = await turnstile.validate('valid-token')

    expect(result).toBe(true)
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ secret: 'test-secret-key', response: 'valid-token' })
      })
    )
  })

  test('validate returns false when Cloudflare responds with failure', async () => {
    process.env.TURNSTILE_SECRET_KEY = 'test-secret-key'
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      json: () => Promise.resolve({ success: false })
    })

    const result = await turnstile.validate('invalid-token')

    expect(result).toBe(false)
  })
})
