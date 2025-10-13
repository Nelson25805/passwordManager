# lib/user.rb
require 'bcrypt'
require 'securerandom'
require 'date'
require_relative 'database'
require_relative 'crypto'

class User
  attr_reader :row

  def initialize(row)
    @row = row
  end

  def self.find_by_email(email)
    row = Database.db.get_first_row("SELECT * FROM users WHERE email = ?", [email])
    row && User.new(row)
  end

  # Create new user; returns [User instance, recovery_token]
  def self.create(email, password)
    password_hash = BCrypt::Password.create(password)
    enc_salt = Crypto.generate_salt
    data_key = SecureRandom.random_bytes(Crypto::KEY_LEN)

    # encrypt data key with master password-derived key
    master_key = Crypto.derive_key(password, enc_salt)
    edk_master_ct, edk_master_iv, edk_master_tag = Crypto.encrypt_binary(data_key, master_key)

    # create recovery token (user-visible) and encrypt EDK with it
    recovery_token = SecureRandom.urlsafe_base64(24)
    recovery_salt = Crypto.generate_salt
    recovery_key = Crypto.derive_key(recovery_token, recovery_salt)
    edk_recovery_ct, edk_recovery_iv, edk_recovery_tag = Crypto.encrypt_binary(data_key, recovery_key)

    Database.db.execute(
      "INSERT INTO users (email, password_hash, enc_salt, created_at, edk_master, edk_master_iv, edk_master_tag, recovery_salt, edk_recovery, edk_recovery_iv, edk_recovery_tag)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [email, password_hash, Crypto.b64(enc_salt), DateTime.now.to_s,
       edk_master_ct, edk_master_iv, edk_master_tag, Crypto.b64(recovery_salt), edk_recovery_ct, edk_recovery_iv, edk_recovery_tag]
    )

    row = Database.db.get_first_row("SELECT * FROM users WHERE email = ?", [email])
    [User.new(row), recovery_token]
  end

  def authenticate(password)
    return false unless @row
    BCrypt::Password.new(@row['password_hash']) == password
  end

  # derive the data key (binary) using the master password
  def derive_data_key_from_password(password)
    salt = Crypto.unb64(@row['enc_salt'])
    master_key = Crypto.derive_key(password, salt)
    Crypto.decrypt_binary(@row['edk_master'], @row['edk_master_iv'], @row['edk_master_tag'], master_key)
  end

  # derive data key using recovery token
  def derive_data_key_from_token(token)
    salt = Crypto.unb64(@row['recovery_salt'])
    return nil if salt.nil?
    key = Crypto.derive_key(token, salt)
    Crypto.decrypt_binary(@row['edk_recovery'], @row['edk_recovery_iv'], @row['edk_recovery_tag'], key)
  end

  # reencrypt EDK with new master password (when user changes master password)
  def reencrypt_edk_master!(data_key, new_password)
    new_salt = Crypto.generate_salt
    new_master_key = Crypto.derive_key(new_password, new_salt)
    edk_ct, edk_iv, edk_tag = Crypto.encrypt_binary(data_key, new_master_key)
    Database.db.execute("UPDATE users SET enc_salt = ?, edk_master = ?, edk_master_iv = ?, edk_master_tag = ?, password_hash = ? WHERE id = ?",
                        [Crypto.b64(new_salt), edk_ct, edk_iv, edk_tag, BCrypt::Password.create(new_password), @row['id']])
    @row = Database.db.get_first_row("SELECT * FROM users WHERE id = ?", [@row['id']])
  end

  # regenerate a new recovery token and return it
  def regenerate_recovery_token!(data_key)
    new_token = SecureRandom.urlsafe_base64(24)
    new_salt = Crypto.generate_salt
    recovery_key = Crypto.derive_key(new_token, new_salt)
    edk_recovery_ct, edk_recovery_iv, edk_recovery_tag = Crypto.encrypt_binary(data_key, recovery_key)
    Database.db.execute("UPDATE users SET recovery_salt = ?, edk_recovery = ?, edk_recovery_iv = ?, edk_recovery_tag = ? WHERE id = ?",
                        [Crypto.b64(new_salt), edk_recovery_ct, edk_recovery_iv, edk_recovery_tag, @row['id']])
    new_token
  end
end
