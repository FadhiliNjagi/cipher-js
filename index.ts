/**
 * cipher-js
 * Copyright (c) 2023 Fadhili Njagi
 * MIT licensed
*/
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import bufferFrom from 'buffer-from'

/**
 * Decodes a string to a Buffer Object. Leaves Buffer objects intact.
 *
 * @param key - the encryption key
 * @param keyEncoding - the encryption key's encoding scheme (default: `utf8`)
 * @return key
 * @api public
 */
export const decodeKey = (key: string | Buffer, keyEncoding: BufferEncoding = 'utf8'): Buffer => {
  if (!(key instanceof Buffer)) {
    key = bufferFrom(key, keyEncoding)
  }
  return key
}

/**
 * Adjusts keylength. If key is not exactly 256 bytes long, returns sha256 of key
 *
 * @param key - the encryption key
 * @return 256-bit key
 * @private
 */
const adjustKeyLength = (key: Buffer): Buffer => {
  if (key.byteLength !== 32) {
    key = createHash('sha256').update(key).digest()
  }
  return key
}

/**
 * Encrypts a string using AES-256-CBC algorithm
 *
 * @param plainText - string to encrypt
 * @param key - the encryption key
 * @param keyEncoding - the encryption key's encoding scheme (default: `utf8`)
 * @return the encrypted value
 * @api public
 */
export const encrypt = (plainText: string, key: string | Buffer, keyEncoding: BufferEncoding = 'utf8'): string => {
  key = decodeKey(key, keyEncoding)
  key = adjustKeyLength(key)
  const iv = randomBytes(16)
  const cipher = createCipheriv('aes-256-cbc', key, iv)
  const encrypted = [iv.toString('base64'), ':', cipher.update(plainText, 'utf8', 'base64'), cipher.final('base64')].join('')
  return encrypted
}

/**
 * Decrypts a string using AES-256-CBC algorithm
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
    throw new Error('Invalid cipher text format. Expected {24-character-iv}:{cipher-text}')
  }
  key = decodeKey(key, keyEncoding)
  key = adjustKeyLength(key)
  const iv = bufferFrom(textParts[0], 'base64')
  const encryptedText = bufferFrom(textParts[1], 'base64')
  const decipher = createDecipheriv('aes-256-cbc', key, iv)
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()])
  return decrypted.toString()
}
