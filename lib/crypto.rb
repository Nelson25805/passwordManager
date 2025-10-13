# lib/crypto.rb
require 'openssl'
require 'securerandom'
require 'base64'

module Crypto
  ITERATIONS = 200_000
  KEY_LEN = 32

  def self.generate_salt(len = 16)
    SecureRandom.random_bytes(len)
  end

  def self.b64(bin)
    Base64.strict_encode64(bin)
  end

  def self.unb64(str)
    return nil if str.nil?
    Base64.strict_decode64(str)
  end

  def self.derive_key(password, salt, iterations = ITERATIONS, key_len = KEY_LEN)
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, key_len, 'sha256')
  end

  # returns [encrypted_b64, iv_b64, tag_b64]
  def self.encrypt_binary(plain_bytes, key)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    cipher.auth_data = ''
    encrypted = cipher.update(plain_bytes) + cipher.final
    tag = cipher.auth_tag
    [b64(encrypted), b64(iv), b64(tag)]
  end

  # returns binary or nil
  def self.decrypt_binary(encrypted_b64, iv_b64, tag_b64, key)
    return nil if encrypted_b64.nil? || iv_b64.nil? || tag_b64.nil?
    encrypted = unb64(encrypted_b64)
    iv = unb64(iv_b64)
    tag = unb64(tag_b64)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    cipher.auth_tag = tag
    cipher.auth_data = ''
    cipher.update(encrypted) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    nil
  end
end
