import { encrypt, decrypt, decodeKey } from './index'

describe('decodeKey = (key, keyEncoding)', function () {
  it('should convert a string key to a buffer', function () {
    const key = 'super secret key'
    expect(decodeKey(key) instanceof Buffer).toBeTruthy()
    const base64key = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
    expect(decodeKey(base64key, 'base64') instanceof Buffer).toBeTruthy()
    const hexKey = '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907'
    expect(decodeKey(hexKey, 'hex') instanceof Buffer).toBeTruthy()
  })

  it('should leave a buffer key intact', function () {
    const key = Buffer.from('super secret key', 'utf8')
    expect(decodeKey(key)).toBe(key)
    const base64key = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
    expect(decodeKey(base64key, 'base64') instanceof Buffer).toBeTruthy()
  })
})

describe('decrypt(cipherText, key, keyEncoding)', function () {
  describe('when cipher format is invalid', function () {
    it('should throw an invalid format error', function () {
      expect(function () {
        decrypt('foobar', 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=')
      }).toThrow(/Invalid cipher text format. Expected {24-character-iv}:{cipher-text}/)
    })
  })

  describe('when key is a string', function () {
    it('should decrypt cipher text', function () {
      const plainText = 'foobar'
      const cipherText = 'kI7KX7DpxGiQko4k2hPkaQ==:wN39aymkUhx8KVenmijULw=='
      const secret = 'super secret key'
      expect(decrypt(cipherText, secret)).toBe(plainText)
    })
  })

  describe('when key is a buffer', function () {
    it('should decrypt plain text', function () {
      const plainText = 'foobar'
      const cipher = 'kI7KX7DpxGiQko4k2hPkaQ==:wN39aymkUhx8KVenmijULw=='
      const secret = Buffer.from('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      expect(decrypt(cipher, secret)).toBe(plainText)
    })
  })
})

describe('encrypt(plainText, key, keyEncoding)', function () {
  describe('when key is a string', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      const secret = 'super secret key'
      const encrypted = encrypt(plainText, secret)
      expect(encrypted).not.toBe(plainText)
      expect(encrypted).toMatch(/^[A-Za-z0-9+/=]{24}:[A-Za-z0-9+/=]+$/)
      expect(decrypt(encrypted, secret)).toBe(plainText)
    })
  })

  describe('when key is in different encoding', function () {
    it('should encrypt with the specified key encoding', function (done) {
      const plainText = 'foobar'
      const base64Secret = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
      const encryptedWithBase64 = encrypt(plainText, base64Secret, 'base64')
      const encryptedWithUtf8 = encrypt(plainText, base64Secret, 'utf8')
      expect(decrypt(encryptedWithBase64, base64Secret, 'base64')).toBe(plainText)
      expect(function () {
        decrypt(encryptedWithUtf8, base64Secret, 'base64')
      }).toThrow(/bad decrypt/)
      expect(function () {
        decrypt(encryptedWithBase64, base64Secret, 'utf8')
      }).toThrow(/bad decrypt/)

      done()
    })
  })

  describe('when key is a buffer', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      let secretBuffer = Buffer.from('3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907', 'hex')
      let encrypted = encrypt(plainText, secretBuffer)
      expect(encrypted).not.toBe(plainText)
      expect(decrypt(encrypted, secretBuffer)).toBe(plainText)

      secretBuffer = Buffer.from('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      encrypted = encrypt(plainText, secretBuffer)
      expect(encrypted).not.toBe(plainText)
      expect(decrypt(encrypted, secretBuffer)).toBe(plainText)
    })
  })

  describe('when key is not exactly 256 bytes long', function () {
    it('should encrypt plain text with sha256 of key', function () {
      const plainText = 'foobar'
      const shortSecret = 'super secret key'
      const sha256Secret = Buffer.from('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      const encryptedWithShortSecret = encrypt(plainText, shortSecret)
      const encryptedWithSha256Secret = encrypt(plainText, sha256Secret)
      // Assert that the keys are interchangeable
      expect(decrypt(encryptedWithShortSecret, sha256Secret)).toBe(decrypt(encryptedWithSha256Secret, shortSecret))
    })
  })
})
