require 'sqlite3'

class Database
  def self.db
    @db ||= begin
      db = SQLite3::Database.new("password_manager.db")
      db.results_as_hash = true

      # Create tables if they don't exist
      db.execute <<-SQL
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          email TEXT UNIQUE,
          password_hash TEXT,
          enc_salt TEXT,
          edk_master BLOB,
          edk_master_iv BLOB,
          edk_master_tag BLOB,
          recovery_salt TEXT,
          edk_recovery BLOB,
          edk_recovery_iv BLOB,
          edk_recovery_tag BLOB,
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
          encrypted_password BLOB,
          created_at TEXT
        );
      SQL

      db
    end
  end
end
