import assert from 'assert'
import { encrypt, decrypt, decodeKey } from './index'
import bufferFrom from 'buffer-from'

describe('decodeKey = (key, keyEncoding)', function () {
  it('should convert a string key to a buffer', function () {
    const key = 'super secret key'
    assert.ok(decodeKey(key) instanceof Buffer)
    const base64key = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
    assert.ok(decodeKey(base64key, 'base64') instanceof Buffer)
    const hexKey = '3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907'
    assert.ok(decodeKey(hexKey, 'hex') instanceof Buffer)
  })

  it('should leave a buffer key intact', function () {
    const key = bufferFrom('super secret key', 'utf8')
    assert.strictEqual(decodeKey(key), key)
    const base64key = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
    assert.ok(decodeKey(base64key, 'base64') instanceof Buffer)
  })
})

describe('decrypt(cipherText, key, keyEncoding)', function () {
  describe('when cipher format is invalid', function () {
    it('should throw an invalid format error', function () {
      assert.throws(function () {
        decrypt('foobar', 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=')
      }, /Invalid cipher text format. Expected {24-character-iv}:{cipher-text}/)
    })
  })

  describe('when key is a string', function () {
    it('should decrypt cipher text', function () {
      const plainText = 'foobar'
      const cipherText = 'kI7KX7DpxGiQko4k2hPkaQ==:wN39aymkUhx8KVenmijULw=='
      const secret = 'super secret key'
      assert.strictEqual(decrypt(cipherText, secret), plainText)
    })
  })

  describe('when key is a buffer', function () {
    it('should decrypt plain text', function () {
      const plainText = 'foobar'
      const cipher = 'kI7KX7DpxGiQko4k2hPkaQ==:wN39aymkUhx8KVenmijULw=='
      const secret = bufferFrom('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      assert.strictEqual(decrypt(cipher, secret), plainText)
    })
  })
})

describe('encrypt(plainText, key, keyEncoding)', function () {
  describe('when key is a string', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      const secret = 'super secret key'
      const encrypted = encrypt(plainText, secret)
      assert.notStrictEqual(encrypted, plainText)
      assert.match(encrypted, /^[A-Za-z0-9+/=]{24}:[A-Za-z0-9+/=]+$/)
      assert.strictEqual(decrypt(encrypted, secret), plainText)
    })
  })

  describe('when key is in different encoding', function () {
    it('should encrypt with the specified key encoding', function (done) {
      const plainText = 'foobar'
      const base64Secret = 'P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc='
      const encryptedWithBase64 = encrypt(plainText, base64Secret, 'base64')
      const encryptedWithUtf8 = encrypt(plainText, base64Secret, 'utf8')
      assert.strictEqual(decrypt(encryptedWithBase64, base64Secret, 'base64'), plainText)
      assert.throws(function () {
        decrypt(encryptedWithUtf8, base64Secret, 'base64')
      }, /bad decrypt/)
      assert.throws(function () {
        decrypt(encryptedWithBase64, base64Secret, 'utf8')
      }, /bad decrypt/)

      done()
    })
  })

  describe('when key is a buffer', function () {
    it('should encrypt plain text', function () {
      const plainText = 'foobar'
      let secretBuffer = bufferFrom('3fac1504251a027465981346fb5b0d57d398e4df4a03253a4c7d1926e40e9907', 'hex')
      let encrypted = encrypt(plainText, secretBuffer)
      assert.notStrictEqual(encrypted, plainText)
      assert.strictEqual(decrypt(encrypted, secretBuffer), plainText)

      secretBuffer = bufferFrom('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      encrypted = encrypt(plainText, secretBuffer)
      assert.notStrictEqual(encrypted, plainText)
      assert.strictEqual(decrypt(encrypted, secretBuffer), plainText)
    })
  })

  describe('when key is not exactly 256 bytes long', function () {
    it('should encrypt plain text with sha256 of key', function () {
      const plainText = 'foobar'
      const shortSecret = 'super secret key'
      const sha256Secret = bufferFrom('P6wVBCUaAnRlmBNG+1sNV9OY5N9KAyU6TH0ZJuQOmQc=', 'base64')
      const encryptedWithShortSecret = encrypt(plainText, shortSecret)
      const encryptedWithSha256Secret = encrypt(plainText, sha256Secret)
      // Assert that the keys are interchangeable
      assert.deepStrictEqual(decrypt(encryptedWithShortSecret, sha256Secret), decrypt(encryptedWithSha256Secret, shortSecret))
    })
  })
})
