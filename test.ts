import { encrypt, decrypt } from './index'

describe('decrypt(cipherText, key, keyEncoding)', function () {
  describe('when cipher format is invalid', function () {
    it('should throw an invalid format error', function () {
      expect(function () {
        decrypt('foobar', '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907')
      }).toThrow(/Invalid cipher text format. Expected {32-character-iv}:{cipher-text}/)
    })
  })

  describe('when key is a string', function () {
    it('should decrypt cipher text', function () {
      const plainText = 'foobar'
      const cipherText = 'a88b5ae04927b9aec7c274ef0848a9ad:2b776d451f03dc478f8a3bb70b41ca3e'
      const secret = '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907'
      expect(decrypt(cipherText, secret)).toBe(plainText)
    })
  })

  describe('when key is a buffer', function () {
    it('should decrypt plain text', function () {
      const plainText = 'foobar'
      const cipher = 'cf20922dd618009f4ee9172ac746701f:c7e37061e6486e3f574aae8f110e8831'
      const secret = Buffer.from('3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907', 'hex')
      expect(decrypt(cipher, secret)).toBe(plainText)
    })
  })
})

describe('encrypt(plainText, key, keyEncoding)', function () {
  describe('when key is a string', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      const secret = '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907'
      const encrypted = encrypt(plainText, secret)
      expect(encrypted).not.toBe(plainText)
      expect(encrypted).toMatch(/^[0-9a-f]{32}:[0-9a-f]+$/)
      expect(decrypt(encrypted, secret)).toBe(plainText)
    })
  })

  describe('when key is in different encoding', function () {
    it('should encrypt with the specified key encoding', function (done) {
      const plainText = 'foobar'
      const hexSecret = '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907'
      const encryptedWithHex = encrypt(plainText, hexSecret, 'hex')
      const encryptedWithUtf8 = encrypt(plainText, hexSecret)
      expect(decrypt(encryptedWithHex, hexSecret, 'hex')).toBe(plainText)
      expect(function () {
        decrypt(encryptedWithUtf8, hexSecret, 'hex')
      }).toThrow(/bad decrypt/)

      done()
    })
  })

  describe('when key is a buffer', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      const secret = Buffer.from('3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907', 'hex')
      const encrypted = encrypt(plainText, secret)
      expect(encrypted).not.toBe(plainText)
      expect(decrypt(encrypted, secret)).toBe(plainText)
    })
  })

  describe('when key is not exactly 256 bytes long', function () {
    it('should encrypt plain text with sha256 of key', function () {
      const plainText = 'foobar'
      const shortSecret = 'super secret key'
      const sha256Secret = Buffer.from('3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907', 'hex')
      const encryptedWithShortSecret = encrypt(plainText, shortSecret)
      const encryptedWithSha256Secret = encrypt(plainText, sha256Secret)
      // Assert that the keys are interchangeable
      expect(decrypt(encryptedWithShortSecret, sha256Secret)).toBe(decrypt(encryptedWithSha256Secret, shortSecret))
    })
  })
})
