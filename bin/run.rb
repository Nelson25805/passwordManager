# TO RUN: ruby bin/run.rb

require 'gtk3'
require_relative '../lib/database'  
require_relative '../lib/helpers'
require_relative '../lib/user'
require_relative '../lib/credential'
require_relative '../app/ui'        
require 'securerandom'

# Ensure DB is initialized
Database.db

# GUI login + signup
class LoginWindow
  def initialize
    @window = Gtk::Window.new("Password Manager Login")
    @window.set_default_size(400, 200)

    grid = Gtk::Grid.new
    grid.set_row_spacing(6)
    grid.set_column_spacing(6)
    grid.margin = 12
    @window.add(grid)

    Gtk::Label.new("Email").tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @email_entry = Gtk::Entry.new
    grid.attach(@email_entry, 1, 0, 1, 1)

    Gtk::Label.new("Password").tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 1, 1, 1)

    login_btn = Gtk::Button.new(label: "Login")
    login_btn.signal_connect("clicked") { attempt_login }
    grid.attach(login_btn, 0, 2, 1, 1)

    create_btn = Gtk::Button.new(label: "Create Account")
    create_btn.signal_connect("clicked") { open_create_account }
    grid.attach(create_btn, 1, 2, 1, 1)

    @window.show_all
  end

  def attempt_login
    email = @email_entry.text.strip.downcase
    pw = @pw_entry.text.strip

    if email.empty? || pw.empty?
      Helpers.show_error(@window, "Email and password are required")
      return
    end

    user = User.find_by_email(email)
    if user && user.authenticate(pw)
      $session = { user: user, data_key: user.derive_data_key_from_password(pw) }
      # create main UI and keep a global reference so it is not GC'd
      $main_ui = PasswordManagerUI.new
      @window.destroy
    else
      Helpers.show_error(@window, "Invalid email or password")
    end
  end

  def open_create_account
    CreateAccountWindow.new(@window)
  end
end

class CreateAccountWindow
  def initialize(parent)
    @parent = parent
    @window = Gtk::Window.new("Create Account")
    @window.set_transient_for(parent)
    @window.set_default_size(420, 260)

    grid = Gtk::Grid.new
    grid.set_row_spacing(6)
    grid.set_column_spacing(6)
    grid.margin = 12
    @window.add(grid)

    Gtk::Label.new("Email").tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @email_entry = Gtk::Entry.new
    grid.attach(@email_entry, 1, 0, 1, 1)

    Gtk::Label.new("Password").tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 1, 1, 1)

    Gtk::Label.new("Confirm Password").tap { |l| grid.attach(l, 0, 2, 1, 1) }
    @pw_confirm_entry = Gtk::Entry.new
    @pw_confirm_entry.visibility = false
    grid.attach(@pw_confirm_entry, 1, 2, 1, 1)

    create_btn = Gtk::Button.new(label: "Create Account")
    create_btn.signal_connect("clicked") { create_account }
    grid.attach(create_btn, 1, 3, 1, 1)

    @window.show_all
  end

  def create_account
    email = @email_entry.text.strip.downcase
    pw = @pw_entry.text.strip
    pw_confirm = @pw_confirm_entry.text.strip

    if email.empty? || pw.empty? || pw_confirm.empty?
      Helpers.show_error(@window, "All fields are required")
      return
    end

    if pw != pw_confirm
      Helpers.show_error(@window, "Passwords do not match")
      return
    end

    if User.find_by_email(email)
      Helpers.show_error(@window, "Email already exists")
      return
    end

    user, recovery_token = User.create(email, pw)
    # set session & create main UI
    $session = { user: user, data_key: user.derive_data_key_from_password(pw) }
    $main_ui = PasswordManagerUI.new

    # destroy login and this create window
    @parent.destroy if @parent && @parent.respond_to?(:destroy)
    @window.destroy

    # show token dialog (with copy)
    Helpers.show_token_dialog($main_ui.window, recovery_token, title: "Recovery Token")
  end
end

# Start GUI
LoginWindow.new
Gtk.main