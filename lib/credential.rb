# lib/credential.rb
require_relative 'database'
require_relative 'crypto'
require 'date'

class Credential
  def self.create(user_id, category, site, username, plain_password, data_key)
    enc, iv, tag = Crypto.encrypt_binary(plain_password.encode('utf-8'), data_key)
    Database.db.execute(
      "INSERT INTO credentials (user_id, category, site_name, username, encrypted_password, iv, tag, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [user_id, category, site, username, enc, iv, tag, DateTime.now.to_s]
    )
  end

  def self.delete(id, user_id)
    Database.db.execute('DELETE FROM credentials WHERE id = ? AND user_id = ?', [id, user_id])
  end

  # Update an existing credential (re-encrypts the new password)
  def self.update(id, user_id, category, site, username, plain_password, data_key)
    enc, iv, tag = Crypto.encrypt_binary(plain_password.encode('utf-8'), data_key)
    Database.db.execute(
      'UPDATE credentials SET category = ?, site_name = ?, username = ?, encrypted_password = ?, iv = ?, tag = ? WHERE id = ? AND user_id = ?',
      [category, site, username, enc, iv, tag, id, user_id]
    )
  end

  # returns array of credential hashes with decrypted password
  def self.for_user(user_id, data_key)
    rows = Database.db.execute('SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at DESC', [user_id])
    rows.map do |r|
      pw_bin = Crypto.decrypt_binary(r['encrypted_password'], r['iv'], r['tag'], data_key)
      {
        id: r['id'],
        category: r['category'],
        site: r['site_name'],
        username: r['username'],
        password: pw_bin && pw_bin.force_encoding('utf-8')
      }
    end
  end

  def self.distinct_categories(user_id)
    rows = Database.db.execute('SELECT DISTINCT category FROM credentials WHERE user_id = ?', [user_id])
    rows.map { |r| r['category'] }
  end
end
