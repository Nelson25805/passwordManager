# password_manager.rb
require 'sqlite3'
require 'bcrypt'
require 'openssl'
require 'securerandom'
require 'base64'
require 'date'

DB_FILE = "password_manager.db"

# --- Helpers: DB ---
db = SQLite3::Database.new(DB_FILE)
db.results_as_hash = true

# Create / migrate tables
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    enc_salt TEXT,
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

# --- Crypto helpers ---
ITERATIONS = 200_000
KEY_LEN = 32

def generate_salt(len = 16)
  SecureRandom.random_bytes(len)
end

def b64(x)
  Base64.strict_encode64(x)
end

def unb64(x)
  return nil if x.nil?
  Base64.strict_decode64(x)
end

def derive_key(master_password, salt, iterations = ITERATIONS, key_len = KEY_LEN)
  OpenSSL::PKCS5.pbkdf2_hmac(master_password, salt, iterations, key_len, 'sha256')
end

def encrypt_aes_gcm(plain_text, key)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  cipher.auth_data = ''
  encrypted = cipher.update(plain_text) + cipher.final
  tag = cipher.auth_tag
  [b64(encrypted), b64(iv), b64(tag)]
end

def decrypt_aes_gcm(encrypted_b64, iv_b64, tag_b64, key)
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
  plain = cipher.update(encrypted) + cipher.final
  plain.force_encoding('utf-8')
rescue OpenSSL::Cipher::CipherError
  nil
end

# --- DB helpers ---
def find_user(db, email)
  db.get_first_row("SELECT * FROM users WHERE email = ?", [email])
end

def create_user(db, email, password)
  password_hash = BCrypt::Password.create(password)
  salt = generate_salt
  db.execute("INSERT INTO users (email, password_hash, enc_salt, created_at) VALUES (?, ?, ?, ?)",
             [email, password_hash, b64(salt), DateTime.now.to_s])
  find_user(db, email)
end

def verify_password(stored_hash, password)
  BCrypt::Password.new(stored_hash) == password
end

# --- Credential CRUD ---
def add_credential(db, user_id, key)
  # Fetch existing categories for this user
  rows = db.execute("SELECT DISTINCT category FROM credentials WHERE user_id = ?", [user_id])
  categories = rows.map { |r| r['category'] }.compact.map(&:strip).reject(&:empty?).uniq.sort

  chosen_category = nil

  if categories.any?
    puts "\nExisting categories:"
    categories.each_with_index do |c, idx|
      puts "#{idx + 1}) #{c}"
    end
    puts "#{categories.size + 1}) Create a new category"
    puts "#{categories.size + 2}) Leave uncategorized"
    print "Choose a category number (or create/leave uncategorized): "
    sel = gets.chomp.to_i

    if sel >= 1 && sel <= categories.size
      chosen_category = categories[sel - 1]
    elsif sel == categories.size + 1
      print "Enter new category name (leave blank for uncategorized): "
      newcat = gets.chomp.strip
      chosen_category = newcat.empty? ? nil : newcat
    elsif sel == categories.size + 2
      chosen_category = nil
    else
      puts "Invalid selection — defaulting to uncategorized."
      chosen_category = nil
    end
  else
    # No existing categories: offer to enter one or leave blank
    print "No categories found. Enter a category name (or leave blank for uncategorized): "
    newcat = gets.chomp.strip
    chosen_category = newcat.empty? ? nil : newcat
  end

  # Prompt for required fields and enforce non-empty (site, username, password)
  site = ''
  loop do
    print "Site name (required): "
    site = gets.chomp.strip
    break unless site.empty?
    puts "Site name cannot be blank. Please enter a site name."
  end

  uname = ''
  loop do
    print "Username/email for site (required): "
    uname = gets.chomp.strip
    break unless uname.empty?
    puts "Username cannot be blank. Please enter a username or email."
  end

  pw = ''
  loop do
    print "Password to store (required): "
    pw = gets.chomp
    pw = pw.strip
    break unless pw.empty?
    puts "Password cannot be blank. Please enter the password to store."
  end

  encrypted, iv, tag = encrypt_aes_gcm(pw, key)
  db.execute("INSERT INTO credentials (user_id, category, site_name, username, encrypted_password, iv, tag, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             [user_id, chosen_category, site, uname, encrypted, iv, tag, DateTime.now.to_s])
  puts "Credential saved."
end

# New: show category list and let user pick by number, then list decrypted creds
def list_credentials_by_category(db, user_id, key)
  # fetch distinct categories for this user
  rows = db.execute("SELECT DISTINCT category FROM credentials WHERE user_id = ?", [user_id])
  categories = rows.map { |r| r['category'] } # may include nil or empty string
  # normalize display names and build menu
  display_cats = []
  # 'All' option
  display_cats << { key: :all, label: "All categories" }
  # 'Uncategorized' if present
  if categories.any? { |c| c.nil? || c.strip.empty? }
    display_cats << { key: :uncat, label: "(Uncategorized)" }
  end
  # add distinct non-empty categories sorted
  distinct_named = categories.compact.map(&:strip).reject(&:empty?).uniq.sort
  distinct_named.each { |c| display_cats << { key: c, label: c } }

  if display_cats.size <= 1
    puts "No credentials found."
    return
  end

  puts "\nChoose a category to list:"
  display_cats.each_with_index do |entry, idx|
    puts "#{idx + 1}) #{entry[:label]}"
  end
  print "Select number: "
  sel = gets.chomp.to_i
  if sel < 1 || sel > display_cats.size
    puts "Invalid selection."
    return
  end
  chosen = display_cats[sel - 1][:key]

  # Build query based on selection
  if chosen == :all
    creds = db.execute("SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at DESC", [user_id])
  elsif chosen == :uncat
    creds = db.execute("SELECT * FROM credentials WHERE user_id = ? AND (category IS NULL OR TRIM(category) = '') ORDER BY created_at DESC", [user_id])
  else
    creds = db.execute("SELECT * FROM credentials WHERE user_id = ? AND category = ? ORDER BY created_at DESC", [user_id, chosen])
  end

  if creds.empty?
    puts "No credentials found for that category."
    return
  end

  puts "-" * 120
  puts sprintf("%-3s| %-28s| %-26s| %-16s| %-20s| %s", "ID", "Site", "Username", "Category", "Created", "Password (decrypted)")
  puts "-" * 120
  creds.each do |r|
    plain = decrypt_aes_gcm(r['encrypted_password'], r['iv'], r['tag'], key)
    display_pw = plain.nil? ? "[unable to decrypt]" : plain
    category_display = (r['category'] && !r['category'].strip.empty?) ? r['category'] : "(Uncategorized)"
    puts sprintf("%-3s| %-28s| %-26s| %-16s| %-20s| %s",
                 r['id'],
                 (r['site_name'] || '')[0,28],
                 (r['username'] || '')[0,26],
                 category_display[0,16],
                 r['created_at'],
                 display_pw)
  end
  puts "-" * 120
end

def delete_credential(db, user_id)
  print "Enter credential ID to delete: "
  id = gets.chomp.to_i
  row = db.get_first_row("SELECT id, site_name FROM credentials WHERE id = ? AND user_id = ?", [id, user_id])
  if row.nil?
    puts "Credential not found."
    return
  end
  print "Confirm delete #{row['site_name']} (y/N): "
  confirm = gets.chomp.downcase
  if confirm == 'y'
    db.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", [id, user_id])
    puts "Deleted."
  else
    puts "Cancelled."
  end
end

# --- Login / Signup flow (with email validation + rate-limiting/lockout) ---
# Ensure the users table has columns for failed_attempts and locked_until (backwards-compatible)
begin
  db.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
rescue SQLite3::SQLException
  # column probably already exists; ignore
end

begin
  db.execute("ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL")
rescue SQLite3::SQLException
  # column probably already exists; ignore
end

puts "=== Welcome to Password Manager ==="

EMAIL_REGEX = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/
MAX_ATTEMPTS = 5         # number of allowed failed attempts before lockout
LOCKOUT_MINUTES = 15     # minutes to lock account after too many failures

email = ''
user = nil
loop do
  # Email input + validation (non-empty + format)
  loop do
    print "Enter your email: "
    email = gets.chomp.strip.downcase
    if email.empty?
      puts "Email cannot be blank. Please enter a valid email."
      next
    end
    unless email.match?(EMAIL_REGEX)
      puts "That doesn't look like a valid email address. Try again."
      next
    end
    break
  end

  user = find_user(db, email)
  if user
    # Check lockout
    if user['locked_until'] && !user['locked_until'].strip.empty?
      begin
        locked_until_time = DateTime.parse(user['locked_until'])
        if locked_until_time > DateTime.now
          remaining = ((locked_until_time - DateTime.now) * 24 * 60).to_i
          puts "This account is locked due to too many failed attempts. Try again in ~#{remaining} minutes."
          print "Do you want to enter a different email? (y/N): "
          alt = gets.chomp.strip.downcase
          if alt == 'y' || alt == 'yes'
            next
          else
            puts "Exiting..."
            exit
          end
        else
          # lock expired -> reset failed_attempts and locked_until
          db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [user['id']])
          user = find_user(db, email) # refresh
        end
      rescue ArgumentError
        # If parsing fails, clear the locked_until to be safe
        db.execute("UPDATE users SET locked_until = NULL WHERE id = ?", [user['id']])
        user = find_user(db, email)
      end
    end

    # Email exists — ask if they want to log in or use a different email
    puts "An account with that email exists."
    print "Do you want to log in with this email? (y/N): "
    answer = gets.chomp.strip.downcase
    if answer == 'y' || answer == 'yes'
      break
    else
      # let them enter a different email
      next
    end
  else
    # Email does not exist — proceed to create account
    break
  end
end

password = ''

if user.nil?
  # Create new account flow (enforce non-empty password + confirmation)
  puts "No account found. Let's create one!"

  loop do
    print "Enter master password (required): "
    password = gets.chomp
    if password.strip.empty?
      puts "Password cannot be blank."
      next
    end

    print "Confirm master password: "
    password_confirm = gets.chomp

    if password != password_confirm
      puts "Passwords do not match. Try again."
      next
    end

    # Attempt to create the user; handle unlikely race where email became taken between check and insert
    begin
      user = create_user(db, email, password)
      # Ensure failed_attempts and locked_until are initialized
      db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [user['id']])
      puts "Account created. You are logged in."
      break
    rescue SQLite3::ConstraintException
      puts "That email was registered just now by another process. Please choose a different email."
      # prompt for a new email before continuing
      loop do
        print "Enter a different email: "
        email = gets.chomp.strip.downcase
        break unless email.empty?
        puts "Email cannot be blank."
      end
      existing = find_user(db, email)
      if existing
        user = existing
        break
      else
        # try creation again in outer loop
        next
      end
    end
  end
else
  # Existing-user login flow with rate-limiting
  loop do
    print "Enter master password: "
    password = gets.chomp

    if verify_password(user['password_hash'], password)
      # Successful login: reset failed attempts & locked_until
      db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [user['id']])
      puts "Login successful. Welcome back!"
      break
    else
      # Failed attempt: increment counter
      fa = (user['failed_attempts'] || 0).to_i + 1
      if fa >= MAX_ATTEMPTS
        lock_until_time = DateTime.now + Rational(LOCKOUT_MINUTES, 24 * 60) # add minutes
        db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", [fa, lock_until_time.to_s, user['id']])
        puts "Too many failed attempts. Account locked for #{LOCKOUT_MINUTES} minutes."
        exit
      else
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", [fa, user['id']])
        # refresh user row so failed_attempts increments persist in loop
        user = find_user(db, email)
        remaining = MAX_ATTEMPTS - fa
        puts "Incorrect password. #{remaining} attempt(s) remaining before lockout."
        print "Try again? (y/N): "
        again = gets.chomp.strip.downcase
        if again == 'y' || again == 'yes'
          next
        else
          puts "Exiting..."
          exit
        end
      end
    end
  end
end


# Ensure enc_salt exists: if missing, generate and save (backwards compat)
salt_b64 = user['enc_salt']
if salt_b64.nil? || salt_b64.empty?
  new_salt = generate_salt
  salt_b64 = b64(new_salt)
  db.execute("UPDATE users SET enc_salt = ? WHERE id = ?", [salt_b64, user['id']])
  salt = new_salt
else
  salt = unb64(salt_b64)
end

if salt.nil?
  puts "Failed to obtain encryption salt. Exiting."
  exit
end

key = derive_key(password, salt)

# --- Main menu loop ---
loop do
  puts "\nMenu:"
  puts "1) Add new site credential"
  puts "2) List saved credentials (choose a category; passwords shown inline)"
  puts "3) Delete a credential by ID"
  puts "4) Logout / Exit"
  print "Choose: "
  choice = gets.chomp

  case choice
  when '1'
    add_credential(db, user['id'], key)
  when '2'
    list_credentials_by_category(db, user['id'], key)
  when '3'
    delete_credential(db, user['id'])
  when '4'
    puts "Goodbye."
    break
  else
    puts "Invalid choice."
  end
end
