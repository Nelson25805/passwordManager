require 'bcrypt'
require 'securerandom'
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

  # New users creation
  def self.create(email, password)
    password_hash = BCrypt::Password.create(password)
    enc_salt = Crypto.generate_salt
    data_key = SecureRandom.random_bytes(Crypto::KEY_LEN)

    # Encrypt data_key with master key
    master_key = Crypto.derive_key(password, enc_salt)
    edk_master_ct, edk_master_iv, edk_master_tag = Crypto.encrypt_binary(data_key, master_key)

    # Create recovery token
    recovery_token = SecureRandom.urlsafe_base64(24)
    recovery_salt = Crypto.generate_salt
    recovery_key = Crypto.derive_key(recovery_token, recovery_salt)
    edk_recovery_ct, edk_recovery_iv, edk_recovery_tag = Crypto.encrypt_binary(data_key, recovery_key)

    # Insert user into DB
    Database.db.execute(
      "INSERT INTO users (email, password_hash, enc_salt, created_at, edk_master, edk_master_iv, edk_master_tag, recovery_salt, edk_recovery, edk_recovery_iv, edk_recovery_tag)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [email, password_hash, Crypto.b64(enc_salt), DateTime.now.to_s,
       edk_master_ct, edk_master_iv, edk_master_tag,
       Crypto.b64(recovery_salt), edk_recovery_ct, edk_recovery_iv, edk_recovery_tag]
    )

    user_row = Database.db.get_first_row("SELECT * FROM users WHERE email = ?", [email])
    [User.new(user_row), recovery_token]
  end

  def authenticate(password)
    return false unless @row
    BCrypt::Password.new(@row['password_hash']) == password
  end

  def derive_data_key_from_password(password)
    salt = Crypto.unb64(@row['enc_salt'])
    master_key = Crypto.derive_key(password, salt)
    Crypto.decrypt_binary(@row['edk_master'], @row['edk_master_iv'], @row['edk_master_tag'], master_key)
  end

  def regenerate_recovery_token!(data_key)
    new_token = SecureRandom.urlsafe_base64(24)
    new_salt = Crypto.generate_salt
    recovery_key = Crypto.derive_key(new_token, new_salt)
    edk_ct, edk_iv, edk_tag = Crypto.encrypt_binary(data_key, recovery_key)
    Database.db.execute(
      "UPDATE users SET recovery_salt = ?, edk_recovery = ?, edk_recovery_iv = ?, edk_recovery_tag = ? WHERE id = ?",
      [Crypto.b64(new_salt), edk_ct, edk_iv, edk_tag, @row['id']]
    )
    new_token
  end
end

