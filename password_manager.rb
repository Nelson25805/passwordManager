require 'sqlite3'
require 'bcrypt'
require 'date'

# Initialize the database
db = SQLite3::Database.new "password_manager.db"

# Create the users table if it doesn't exist
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME
  );
SQL

# --- Helper Methods ---

def create_user(db, email, password)
  password_hash = BCrypt::Password.create(password)
  db.execute("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
           [email, password_hash, DateTime.now.to_s])
end

def find_user(db, email)
  db.execute("SELECT * FROM users WHERE email = ?", [email]).first
end

def verify_password(stored_hash, password)
  BCrypt::Password.new(stored_hash) == password
end

# --- Login / Signup Flow ---

puts "=== Welcome to Password Manager ==="
print "Enter your email: "
email = gets.chomp

user = find_user(db, email)

if user.nil?
  # User does not exist → create account
  puts "No account found. Let's create one!"
  print "Enter master password: "
  password = gets.chomp
  print "Confirm master password: "
  password_confirm = gets.chomp

  if password != password_confirm
    puts "Passwords do not match. Exiting..."
    exit
  end

  create_user(db, email, password)
  puts "Account created successfully! You are now logged in."
else
  # User exists → login
  print "Enter master password: "
  password = gets.chomp

  if verify_password(user[2], password)
    puts "Login successful! Welcome back."
  else
    puts "Incorrect password. Exiting..."
    exit
  end
end
