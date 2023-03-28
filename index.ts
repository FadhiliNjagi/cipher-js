/**
 * cipher-js
 * Copyright (c) 2023 Fadhili Njagi
 * MIT licensed
*/
import crypto from 'crypto'

/**
 * Encrypt a string using AES-256-CBC algorithm
 *
 * @param plainText - string to encrypt
 * @param key - the encryption key
 * @param keyEncoding - the encryption key's encoding scheme (default: `utf8`)
 * @return the encrypted value
 * @api public
 */
export const encrypt = (plainText: string, key: string | Buffer, keyEncoding: BufferEncoding = 'utf8'): string => {
  if (!(key instanceof Buffer)) {
    key = Buffer.from(key, keyEncoding)
  }
  // If key is not exactly 256 bytes long, use sha256 of key instead
  if (key.byteLength !== 32) {
    key = crypto.createHash('sha256').update(key).digest()
  }
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = [iv.toString('hex'), ':', cipher.update(plainText, 'utf8', 'hex'), cipher.final('hex')].join('')
  return encrypted
}

/**
 * Decrypt a string using AES-256-CBC algorithm
 *
 * @param cipherText - cipher to decrypt
 * @param key - the encryption key
 * @param keyEncoding - the encryption key's encoding scheme (default: `utf8`)
 * @return the decrypted value
 * @api public
 */
export const decrypt = (cipherText: string, key: string | Buffer, keyEncoding: BufferEncoding = 'utf8'): string => {
  const textParts = cipherText.split(':')
  if (textParts[0] === undefined || textParts[1] === undefined) {
    throw new Error('Invalid cipher text format. Expected {32-character-iv}:{cipher-text}')
  }
  if (!(key instanceof Buffer)) {
    key = Buffer.from(key, keyEncoding)
  }
  // If key is not exactly 256 bytes long, use sha256 of key instead
  if (key.byteLength !== 32) {
    key = crypto.createHash('sha256').update(key).digest()
  }
  const iv = Buffer.from(textParts[0], 'hex')
  const encryptedText = Buffer.from(textParts[1], 'hex')
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()])
  return decrypted.toString()
}
