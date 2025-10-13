# app/ui.rb
require 'gtk3'
require_relative '../lib/credential'
require_relative '../lib/user'
require_relative '../lib/helpers'

class PasswordManagerUI
  def initialize
    @window = Gtk::Window.new("Password Manager")
    @window.set_default_size(800, 480)
    @window.signal_connect("destroy") { Gtk.main_quit }

    vbox = Gtk::Box.new(:vertical, 6)
    @window.add(vbox)

    # Top: category selection + refresh
    top_box = Gtk::Box.new(:horizontal, 6)
    vbox.pack_start(top_box, expand: false, fill: false, padding: 6)

    @category_combo = Gtk::ComboBoxText.new
    @category_combo.signal_connect("changed") { refresh_list }
    top_box.pack_start(Gtk::Label.new("Category:"), expand: false, fill: false, padding: 6)
    top_box.pack_start(@category_combo, expand: false, fill: false, padding: 6)

    refresh_cats_btn = Gtk::Button.new(label: "Refresh Categories")
    refresh_cats_btn.signal_connect("clicked") { refresh_categories; refresh_list }
    top_box.pack_start(refresh_cats_btn, expand: false, fill: false, padding: 6)

    # List store and tree view: ID, Category, Site, Username, Password
    @list_store = Gtk::ListStore.new(String, String, String, String, String)
    @tree_view = Gtk::TreeView.new(@list_store)

    ['ID', 'Category', 'Site', 'Username', 'Password'].each_with_index do |title, i|
      renderer = Gtk::CellRendererText.new
      column = Gtk::TreeViewColumn.new(title, renderer, text: i)
      column.resizable = true
      @tree_view.append_column(column)
    end

    scrolled = Gtk::ScrolledWindow.new
    scrolled.set_policy(:automatic, :automatic)
    scrolled.add(@tree_view)
    vbox.pack_start(scrolled, expand: true, fill: true, padding: 6)

    # Button box
    button_box = Gtk::Box.new(:horizontal, 6)
    vbox.pack_start(button_box, expand: false, fill: false, padding: 6)

    add_btn = Gtk::Button.new(label: "Add")
    add_btn.signal_connect("clicked") { open_add_window }
    button_box.pack_start(add_btn, expand: false, fill: false, padding: 6)

    delete_btn = Gtk::Button.new(label: "Delete")
    delete_btn.signal_connect("clicked") { delete_selected }
    button_box.pack_start(delete_btn, expand: false, fill: false, padding: 6)

    regen_btn = Gtk::Button.new(label: "Regenerate Recovery Token")
    regen_btn.signal_connect("clicked") { regenerate_token }
    button_box.pack_start(regen_btn, expand: false, fill: false, padding: 6)

    refresh_categories
    refresh_list
    @window.show_all
  end

  # expose window for helpers
  def window
    @window
  end

  def refresh_categories
    @category_combo.remove_all
    return unless $session && $session[:user]
    cats = Credential.distinct_categories($session[:user].row['id']).compact.map(&:strip).reject(&:empty?).uniq.sort
    @category_combo.append_text("All")
    cats.each { |c| @category_combo.append_text(c) }
    @category_combo.append_text("(Uncategorized)")
    @category_combo.active = 0
  end

  def refresh_list
    @list_store.clear
    return unless $session && $session[:user] && $session[:data_key]

    selected = @category_combo.active_text rescue "All"

    rows = case selected
           when nil, "All"
             Credential.for_user($session[:user].row['id'], $session[:data_key])
           when "(Uncategorized)"
             Credential.for_user($session[:user].row['id'], $session[:data_key]).select { |r| r[:category].nil? || r[:category].strip.empty? }
           else
             Credential.for_user($session[:user].row['id'], $session[:data_key]).select { |r| r[:category] == selected }
           end

    rows.each do |c|
      iter = @list_store.append
      iter[0] = c[:id].to_s
      iter[1] = c[:category] || ""
      iter[2] = c[:site]
      iter[3] = c[:username]
      iter[4] = c[:password] || "[unable to decrypt]"
    end
  end

  def open_add_window
    AddCredentialWindow.new($session[:user].row['id'], $session[:data_key], self)
  end

  def delete_selected
    selection = @tree_view.selection.selected
    if selection.nil?
      Helpers.show_info(@window, "Select an item first")
      return
    end
    id = selection[0].to_i
    Credential.delete(id, $session[:user].row['id'])
    refresh_list
  end

  def regenerate_token
    token = $session[:user].regenerate_recovery_token!($session[:data_key])
    Helpers.show_token_dialog(@window, token, title: "New Recovery Token")
  end

  def info_message(msg)
    Helpers.show_info(@window, msg)
  end
end

class AddCredentialWindow
  def initialize(user_id, data_key, main_ui)
    @user_id = user_id
    @data_key = data_key
    @main_ui = main_ui

    @window = Gtk::Window.new("Add Credential")
    @window.set_default_size(420, 260)

    grid = Gtk::Grid.new
    grid.set_row_spacing(6)
    grid.set_column_spacing(6)
    grid.margin = 12
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
      Helpers.show_error(@window, "Site, username, and password are required")
      return
    end

    Credential.create(@user_id, cat, site, uname, pw, @data_key)
    @main_ui.refresh_categories
    @main_ui.refresh_list
    @window.destroy
  end
end
