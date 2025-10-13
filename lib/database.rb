# lib/database.rb
require 'sqlite3'
require 'date'

class Database
  DB_PATH = File.expand_path("../../password_manager.db", __dir__)

  def self.db
    @db ||= begin
      db = SQLite3::Database.new(DB_PATH)
      db.results_as_hash = true
      migrate(db)
      db
    end
  end

  def self.migrate(db)
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT,
        enc_salt TEXT,
        edk_master TEXT,
        edk_master_iv TEXT,
        edk_master_tag TEXT,
        recovery_salt TEXT,
        edk_recovery TEXT,
        edk_recovery_iv TEXT,
        edk_recovery_tag TEXT,
        created_at TEXT
      );
    SQL

    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        category TEXT,
        site_name TEXT,
        username TEXT,
        encrypted_password TEXT,
        iv TEXT,
        tag TEXT,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
    SQL
  end
end
