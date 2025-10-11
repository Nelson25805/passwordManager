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

# Create / migrate tables (add columns used by recovery & encrypted data-key)
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    enc_salt TEXT,
    created_at TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    -- encrypted data-key (master)
    edk_master TEXT,
    edk_master_iv TEXT,
    edk_master_tag TEXT,
    -- recovery: salt and encrypted data-key for recovery token
    recovery_salt TEXT,
    edk_recovery TEXT,
    edk_recovery_iv TEXT,
    edk_recovery_tag TEXT
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

# PBKDF2 to derive a key from a password/token + salt
def derive_key(password, salt, iterations = ITERATIONS, key_len = KEY_LEN)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, key_len, 'sha256')
end

# AES-256-GCM encrypt/decrypt helpers (works on binary plaintext)
def encrypt_aes_gcm_binary(plain_bytes, key)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  cipher.auth_data = ''
  encrypted = cipher.update(plain_bytes) + cipher.final
  tag = cipher.auth_tag
  [b64(encrypted), b64(iv), b64(tag)]
end

def decrypt_aes_gcm_binary(encrypted_b64, iv_b64, tag_b64, key)
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
  plain # binary bytes
rescue OpenSSL::Cipher::CipherError
  nil
end

# wrappers for credentials encryption (credentials are text/utf-8)
def encrypt_aes_gcm_text(plain_text, key)
  e, iv, tag = encrypt_aes_gcm_binary(plain_text.encode('utf-8'), key)
  [e, iv, tag]
end

def decrypt_aes_gcm_text(encrypted_b64, iv_b64, tag_b64, key)
  bin = decrypt_aes_gcm_binary(encrypted_b64, iv_b64, tag_b64, key)
  return nil if bin.nil?
  bin.force_encoding('utf-8')
end

# --- DB helpers ---
def find_user(db, email)
  db.get_first_row("SELECT * FROM users WHERE email = ?", [email])
end

# create user: returns user row
# * generates per-user enc_salt
# * generates a random data_key used to encrypt credentials
# * encrypts data_key with master-key (derived from password) and with recovery-key (derived from recovery token)
def create_user(db, email, password)
  password_hash = BCrypt::Password.create(password)
  enc_salt = generate_salt
  data_key = SecureRandom.random_bytes(KEY_LEN) # 32 bytes data key

  master_key = derive_key(password, enc_salt)
  edk_master_ct, edk_master_iv, edk_master_tag = encrypt_aes_gcm_binary(data_key, master_key)

  # generate recovery token (show to user), and encrypt data_key with key derived from token
  recovery_token = SecureRandom.urlsafe_base64(24) # shown once to user
  recovery_salt = generate_salt
  recovery_key = derive_key(recovery_token, recovery_salt)
  edk_recovery_ct, edk_recovery_iv, edk_recovery_tag = encrypt_aes_gcm_binary(data_key, recovery_key)

  db.execute("INSERT INTO users (email, password_hash, enc_salt, created_at, edk_master, edk_master_iv, edk_master_tag, recovery_salt, edk_recovery, edk_recovery_iv, edk_recovery_tag)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
             [email, password_hash, b64(enc_salt), DateTime.now.to_s, edk_master_ct, edk_master_iv, edk_master_tag, b64(recovery_salt), edk_recovery_ct, edk_recovery_iv, edk_recovery_tag])

  user = find_user(db, email)
  # return both user row and plain-text recovery_token (caller must display & store it)
  [user, recovery_token]
end

def verify_password(stored_hash, password)
  BCrypt::Password.new(stored_hash) == password
end

# re-encrypt data_key for master-key (used when changing master password)
def reencrypt_edk_master(db, user_id, data_key, new_password)
  new_salt = generate_salt
  new_master_key = derive_key(new_password, new_salt)
  edk_ct, edk_iv, edk_tag = encrypt_aes_gcm_binary(data_key, new_master_key)
  db.execute("UPDATE users SET enc_salt = ?, edk_master = ?, edk_master_iv = ?, edk_master_tag = ? WHERE id = ?",
             [b64(new_salt), edk_ct, edk_iv, edk_tag, user_id])
end

# regenerate recovery token (called when logged in and user requests new token)
def regenerate_recovery_token(db, user_id, data_key)
  new_token = SecureRandom.urlsafe_base64(24)
  new_recovery_salt = generate_salt
  recovery_key = derive_key(new_token, new_recovery_salt)
  edk_recovery_ct, edk_recovery_iv, edk_recovery_tag = encrypt_aes_gcm_binary(data_key, recovery_key)
  db.execute("UPDATE users SET recovery_salt = ?, edk_recovery = ?, edk_recovery_iv = ?, edk_recovery_tag = ? WHERE id = ?",
             [b64(new_recovery_salt), edk_recovery_ct, edk_recovery_iv, edk_recovery_tag, user_id])
  new_token
end

# --- Credential CRUD (same as before, but uses data_key for encrypt/decrypt) ---
def add_credential(db, user_id, data_key)
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

  encrypted, iv, tag = encrypt_aes_gcm_text(pw, data_key)
  db.execute("INSERT INTO credentials (user_id, category, site_name, username, encrypted_password, iv, tag, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             [user_id, chosen_category, site, uname, encrypted, iv, tag, DateTime.now.to_s])
  puts "Credential saved."
end

# list credentials (category selection) using data_key for decryption
def list_credentials_by_category(db, user_id, data_key)
  rows = db.execute("SELECT DISTINCT category FROM credentials WHERE user_id = ?", [user_id])
  categories = rows.map { |r| r['category'] } # may include nil or empty string
  display_cats = []
  display_cats << { key: :all, label: "All categories" }
  if categories.any? { |c| c.nil? || c.strip.empty? }
    display_cats << { key: :uncat, label: "(Uncategorized)" }
  end
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
    plain = decrypt_aes_gcm_text(r['encrypted_password'], r['iv'], r['tag'], data_key)
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

# --- Login / Signup flow (with recovery token support) ---
EMAIL_REGEX = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

puts "=== Welcome to Password Manager ==="

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
          user = find_user(db, email)
        end
      rescue ArgumentError
        db.execute("UPDATE users SET locked_until = NULL WHERE id = ?", [user['id']])
        user = find_user(db, email)
      end
    end

    puts "An account with that email exists."
    puts "Options: [1] Log in  [2] Forgot master password (use recovery token)  [3] Change email"
    print "Choose 1/2/3: "
    opt = gets.chomp.strip
    if opt == '1'
      break
    elsif opt == '2'
      # Forgot flow: ask for recovery token, attempt to decrypt edk_recovery to obtain data_key
      print "Enter your recovery token: "
      token = gets.chomp.strip
      if token.empty?
        puts "No token entered. Returning to email prompt."
        next
      end
      # ensure recovery fields exist
      if user['recovery_salt'].nil? || user['edk_recovery'].nil?
        puts "No recovery setup for this account. Cannot recover."
        next
      end
      recovery_salt = unb64(user['recovery_salt'])
      recovery_key = derive_key(token, recovery_salt)
      data_key = decrypt_aes_gcm_binary(user['edk_recovery'], user['edk_recovery_iv'], user['edk_recovery_tag'], recovery_key)
      if data_key.nil?
        puts "Recovery token incorrect or corrupted. Returning to email prompt."
        next
      end

      # Got data_key — allow user to set a new master password and re-encrypt edk_master
      puts "Recovery token accepted. You may now set a new master password."
      new_password = ''
      loop do
        print "Enter new master password (required): "
        new_password = gets.chomp
        if new_password.strip.empty?
          puts "Password cannot be blank."
          next
        end
        print "Confirm new master password: "
        pc = gets.chomp
        if new_password != pc
          puts "Passwords do not match. Try again."
          next
        end
        break
      end

      # update password_hash and re-encrypt data_key with new master password (new salt)
      new_password_hash = BCrypt::Password.create(new_password)
      # re-encrypt edk_master with new salt & update password hash
      reencrypt_edk_master(db, user['id'], data_key, new_password)
      db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?", [new_password_hash, user['id']])
      user = find_user(db, email) # refresh
      puts "Master password reset successful. You are now logged in."
      password = new_password
      # set local variables for session below
      break
    elsif opt == '3'
      # let them re-enter email
      next
    else
      puts "Invalid option."
      next
    end
  else
    break
  end
end

# At this point: `email` is set and `user` is either a DB row (existing) or nil (new user)
password = ''

if user.nil?
  # Create new account: enforce non-empty password + confirmation
  puts "No account found. Let's create one!"
  created = nil
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

    begin
      user_and_token = create_user(db, email, password)
      user = user_and_token[0]
      recovery_token = user_and_token[1]
      # initialize failed_attempts/locked_until
      db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [user['id']])
      puts "Account created. IMPORTANT: Save this recovery token in a secure place (shown only once):"
      puts recovery_token
      puts "You can use this token to recover your account if you forget your master password."
      created = true
      break
    rescue SQLite3::ConstraintException
      puts "That email was registered just now. Please choose a different email."
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
      # normal login: derive master_key and decrypt edk_master to get data_key
      if user['enc_salt'] && user['edk_master']
        master_salt = unb64(user['enc_salt'])
        master_key = derive_key(password, master_salt)
        data_key = decrypt_aes_gcm_binary(user['edk_master'], user['edk_master_iv'], user['edk_master_tag'], master_key)
        if data_key.nil?
          # possible corruption or wrong key — fallback: attempt to treat master_key itself as data_key (old behavior)
          # but for simplicity, treat as login failure
          puts "Login failed to derive encryption key. Possible data corruption."
          exit
        end
      else
        puts "Account missing encryption metadata. Cannot continue."
        exit
      end

      # Successful login: reset failed attempts & locked_until
      db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [user['id']])
      puts "Login successful. Welcome back!"
      break
    else
      # Failed attempt: increment counter
      fa = (user['failed_attempts'] || 0).to_i + 1
      if fa >= MAX_ATTEMPTS
        lock_until_time = DateTime.now + Rational(LOCKOUT_MINUTES, 24 * 60)
        db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", [fa, lock_until_time.to_s, user['id']])
        puts "Too many failed attempts. Account locked for #{LOCKOUT_MINUTES} minutes."
        exit
      else
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", [fa, user['id']])
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

# At this point we must ensure we have the session's data_key variable.
# Cases:
# - New user: create_user returned user and we generated data_key inside create_user but didn't keep it in variable here.
#   For new user, re-derive data_key by decrypting edk_master using the password just set.
# - Existing user: 'data_key' computed in login path.

# If data_key is not set (new user path), derive now
if defined?(data_key).nil? || data_key.nil?
  # decrypt edk_master with master password
  user = find_user(db, email) if user.nil?
  master_salt = unb64(user['enc_salt'])
  master_key = derive_key(password, master_salt)
  data_key = decrypt_aes_gcm_binary(user['edk_master'], user['edk_master_iv'], user['edk_master_tag'], master_key)
  if data_key.nil?
    puts "Failed to obtain data encryption key for session. Exiting."
    exit
  end
end

# --- Main menu loop (adds regenerate recovery token option) ---
loop do
  puts "\nMenu:"
  puts "1) Add new site credential"
  puts "2) List saved credentials (choose a category; passwords shown inline)"
  puts "3) Delete a credential by ID"
  puts "4) Regenerate recovery token (prints new token; store it securely)"
  puts "5) Logout / Exit"
  print "Choose: "
  choice = gets.chomp

  case choice
  when '1'
    add_credential(db, user['id'], data_key)
  when '2'
    list_credentials_by_category(db, user['id'], data_key)
  when '3'
    delete_credential(db, user['id'])
  when '4'
    new_token = regenerate_recovery_token(db, user['id'], data_key)
    puts "New recovery token (shown once) — store securely:"
    puts new_token
  when '5'
    puts "Goodbye."
    break
  else
    puts "Invalid choice."
  end
end
