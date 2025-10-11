require 'gtk3'
require_relative '../lib/credential'
require_relative '../lib/user'

class PasswordManagerUI
  def initialize
    @window = Gtk::Window.new("Password Manager")
    @window.set_default_size(600, 400)
    @window.signal_connect("destroy") { Gtk.main_quit }

    vbox = Gtk::Box.new(:vertical, 5)
    @window.add(vbox)

    # List store
    @list_store = Gtk::ListStore.new(String, String, String, String) # ID, Category, Site, Username
    @tree_view = Gtk::TreeView.new(@list_store)

    ['ID', 'Category', 'Site', 'Username'].each_with_index do |title, i|
      renderer = Gtk::CellRendererText.new
      column = Gtk::TreeViewColumn.new(title, renderer, text: i)
      @tree_view.append_column(column)
    end

    scrolled_window = Gtk::ScrolledWindow.new
    scrolled_window.set_policy(:automatic, :automatic)
    scrolled_window.add(@tree_view)
    vbox.pack_start(scrolled_window, expand: true, fill: true, padding: 5)

    # Buttons
    button_box = Gtk::Box.new(:horizontal, 5)
    vbox.pack_start(button_box, expand: false, fill: false, padding: 5)

    add_button = Gtk::Button.new(label: "Add")
    add_button.signal_connect("clicked") { open_add_window }
    button_box.pack_start(add_button, expand: false, fill: false, padding: 5)

    delete_button = Gtk::Button.new(label: "Delete")
    delete_button.signal_connect("clicked") { delete_selected }
    button_box.pack_start(delete_button, expand: false, fill: false, padding: 5)

    regen_button = Gtk::Button.new(label: "Regenerate Recovery Token")
    regen_button.signal_connect("clicked") { regenerate_token }
    button_box.pack_start(regen_button, expand: false, fill: false, padding: 5)

    refresh_list
    @window.show_all
  end

  def refresh_list
    return unless $session[:user] && $session[:data_key]

    @list_store.clear
    credentials = Credential.for_user($session[:user].row['id'], $session[:data_key])
    credentials.each do |c|
      iter = @list_store.append
      iter[0] = c[:id].to_s
      iter[1] = c[:category] || ""
      iter[2] = c[:site]
      iter[3] = c[:username]
    end
  end

  def open_add_window
    AddCredentialWindow.new($session[:user].row['id'], $session[:data_key], self)
  end

  def delete_selected
    selection = @tree_view.selection.selected
    if selection.nil?
      info_message("Select an item first")
      return
    end
    id = selection[0].to_i
    Credential.delete(id, $session[:user].row['id'])
    refresh_list
  end

  def regenerate_token
    token = $session[:user].regenerate_recovery_token!($session[:data_key])
    info_message("New recovery token (store it now):\n\n#{token}")
  end

  def info_message(msg)
    dialog = Gtk::MessageDialog.new(
      parent: @window,
      flags: :modal,
      type: :info,
      buttons: :ok,
      message: msg
    )
    dialog.run
    dialog.destroy
  end
end

class AddCredentialWindow
  def initialize(user_id, data_key, main_ui)
    @user_id = user_id
    @data_key = data_key
    @main_ui = main_ui

    @window = Gtk::Window.new("Add Credential")
    @window.set_default_size(400, 250)

    grid = Gtk::Grid.new
    grid.set_row_spacing(5)
    grid.set_column_spacing(5)
    grid.margin = 10
    @window.add(grid)

    Gtk::Label.new("Category (optional)").tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @cat_entry = Gtk::Entry.new
    grid.attach(@cat_entry, 1, 0, 1, 1)

    Gtk::Label.new("Site (required)").tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @site_entry = Gtk::Entry.new
    grid.attach(@site_entry, 1, 1, 1, 1)

    Gtk::Label.new("Username (required)").tap { |l| grid.attach(l, 0, 2, 1, 1) }
    @uname_entry = Gtk::Entry.new
    grid.attach(@uname_entry, 1, 2, 1, 1)

    Gtk::Label.new("Password (required)").tap { |l| grid.attach(l, 0, 3, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 3, 1, 1)

    save_button = Gtk::Button.new(label: "Save")
    save_button.signal_connect("clicked") { save_and_close }
    grid.attach(save_button, 1, 4, 1, 1)

    @window.show_all
  end

  def save_and_close
    cat = @cat_entry.text.strip
    cat = nil if cat.empty?
    site = @site_entry.text.strip
    uname = @uname_entry.text.strip
    pw = @pw_entry.text.strip

    if site.empty? || uname.empty? || pw.empty?
      dialog = Gtk::MessageDialog.new(
        parent: @window,
        flags: :modal,
        type: :error,
        buttons: :ok,
        message: "Site, username, and password are required"
      )
      dialog.run
      dialog.destroy
      return
    end

    Credential.create(@user_id, cat, site, uname, pw, @data_key)
    @main_ui.refresh_list
    @window.destroy
  end
end
