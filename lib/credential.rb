require_relative 'database'
require_relative 'crypto'

class Credential
  def self.create(user_id, category, site, username, password, data_key)
    encrypted_password, iv, tag = Crypto.encrypt_binary(password, data_key)
    Database.db.execute(
      "INSERT INTO credentials (user_id, category, site_name, username, encrypted_password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      [user_id, category, site, username, encrypted_password, Time.now.to_s]
    )
  end

  def self.delete(id, user_id)
    Database.db.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", [id, user_id])
  end

  def self.for_user(user_id, data_key)
    rows = Database.db.execute("SELECT * FROM credentials WHERE user_id = ?", [user_id])
    rows.map do |row|
      {
        id: row['id'],
        category: row['category'],
        site: row['site_name'],
        username: row['username'],
        password: Crypto.decrypt_binary(row['encrypted_password'], nil, nil, data_key) # Adjust if IV/tag stored
      }
    end
  end
end
