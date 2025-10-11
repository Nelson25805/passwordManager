require 'gtk3'
require_relative '../lib/user'
require_relative '../app/ui' # PasswordManagerUI
require 'securerandom'

class LoginWindow
  def initialize
    @window = Gtk::Window.new("Password Manager Login")
    @window.set_default_size(350, 200)
    @window.signal_connect("destroy") { @window.destroy }  # or simply remove this handler


    grid = Gtk::Grid.new
    grid.set_row_spacing(5)
    grid.set_column_spacing(5)
    grid.margin = 10
    @window.add(grid)

    # Email
    Gtk::Label.new("Email").tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @email_entry = Gtk::Entry.new
    grid.attach(@email_entry, 1, 0, 1, 1)

    # Password
    Gtk::Label.new("Password").tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 1, 1, 1)

    # Buttons
    login_btn = Gtk::Button.new(label: "Login")
    login_btn.signal_connect("clicked") { attempt_login }
    grid.attach(login_btn, 0, 2, 1, 1)

    create_btn = Gtk::Button.new(label: "Create Account")
    create_btn.signal_connect("clicked") { open_create_account }
    grid.attach(create_btn, 1, 2, 1, 1)

    @window.show_all
  end

  def attempt_login
  email = @email_entry.text.strip
  pw = @pw_entry.text.strip

  if email.empty? || pw.empty?
    show_error("Email and password are required")
    return
  end

  user = User.find_by_email(email)
  if user && user.authenticate(pw)
    $session = { user: user, data_key: user.derive_data_key_from_password(pw) }
    @window.destroy
    $main_ui = PasswordManagerUI.new   # KEEP reference
  else
    show_error("Invalid email or password")
  end
end


  def open_create_account
    CreateAccountWindow.new(@window)
  end

  def show_error(msg)
    dialog = Gtk::MessageDialog.new(
      parent: @window,
      flags: :modal,
      type: :error,
      buttons: :ok,
      message: msg
    )
    dialog.run
    dialog.destroy
  end
end

# Signup window
class CreateAccountWindow
  def initialize(parent)
    @parent = parent   # keep reference to login window
    @window = Gtk::Window.new("Create Account")
    @window.set_transient_for(parent)
    @window.set_default_size(350, 250)

    grid = Gtk::Grid.new
    grid.set_row_spacing(5)
    grid.set_column_spacing(5)
    grid.margin = 10
    @window.add(grid)

    # Email
    Gtk::Label.new("Email").tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @email_entry = Gtk::Entry.new
    grid.attach(@email_entry, 1, 0, 1, 1)

    # Password
    Gtk::Label.new("Password").tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 1, 1, 1)

    # Confirm Password
    Gtk::Label.new("Confirm Password").tap { |l| grid.attach(l, 0, 2, 1, 1) }
    @pw_confirm_entry = Gtk::Entry.new
    @pw_confirm_entry.visibility = false
    grid.attach(@pw_confirm_entry, 1, 2, 1, 1)

    # Create Button
    create_btn = Gtk::Button.new(label: "Create Account")
    create_btn.signal_connect("clicked") { create_account }
    grid.attach(create_btn, 1, 3, 1, 1)

    @window.show_all
  end

  def create_account
    email = @email_entry.text.strip
    pw = @pw_entry.text.strip
    pw_confirm = @pw_confirm_entry.text.strip

    if email.empty? || pw.empty? || pw_confirm.empty?
      show_error("All fields are required")
      return
    end

    if pw != pw_confirm
      show_error("Passwords do not match")
      return
    end

    if User.find_by_email(email)
      show_error("Email already exists")
      return
    end

    # Create the user (returns [user, recovery_token])
    user, recovery_token = User.create(email, pw)

    # Initialize session and main UI; keep global reference so it isn't GC'd
    $session = { user: user, data_key: user.derive_data_key_from_password(pw) }
    $main_ui = PasswordManagerUI.new

    # destroy the login window (parent) and this create-account window
    @parent.destroy if @parent && !@parent.destroyed?
    @window.destroy

    # Optionally show the recovery token to the user
    dialog = Gtk::MessageDialog.new(
      parent: $main_ui.instance_variable_get(:@window),
      flags: :modal,
      type: :info,
      buttons: :ok,
      message: "Account created. Save this recovery token (shown once):\n\n#{recovery_token}"
    )
    dialog.run
    dialog.destroy
  end

  def show_error(msg)
    dialog = Gtk::MessageDialog.new(
      parent: @window,
      flags: :modal,
      type: :error,
      buttons: :ok,
      message: msg
    )
    dialog.run
    dialog.destroy
  end
end

# Start the GTK login
LoginWindow.new
Gtk.main
