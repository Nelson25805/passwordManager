require 'gtk3'
require_relative '../lib/credential'
require_relative '../lib/user'
require_relative '../lib/helpers'

class PasswordManagerUI
  def initialize
    @window = Gtk::Window.new('Password Manager')
    @window.set_default_size(900, 480)
    @window.signal_connect('destroy') { Gtk.main_quit }

    vbox = Gtk::Box.new(:vertical, 6)
    @window.add(vbox)

    # Top: category selection + refresh
    top_box = Gtk::Box.new(:horizontal, 6)
    vbox.pack_start(top_box, expand: false, fill: false, padding: 6)

    @category_combo = Gtk::ComboBoxText.new
    @category_combo.signal_connect('changed') { refresh_list }
    top_box.pack_start(Gtk::Label.new('Category:'), expand: false, fill: false, padding: 6)
    top_box.pack_start(@category_combo, expand: false, fill: false, padding: 6)

    refresh_cats_btn = Gtk::Button.new(label: 'Refresh Categories')
    refresh_cats_btn.signal_connect('clicked') do
      refresh_categories
      refresh_list
    end
    top_box.pack_start(refresh_cats_btn, expand: false, fill: false, padding: 6)

    # model columns:
    # 0 = id (hidden)
    # 1 = category (visible)
    # 2 = site (visible)
    # 3 = username (visible)
    # 4 = password_display (visible)  <-- masked or real depending on per-row flag
    # 5 = password_real (hidden)       <-- stores the real decrypted password
    # 6 = action_text (visible)        <-- "Show" / "Hide" clickable action
    @list_store = Gtk::ListStore.new(String, String, String, String, String, String, String)
    @tree_view = Gtk::TreeView.new(@list_store)

    # Visible columns: Category (1), Site (2), Username (3), Password (4), Action (6)
    visible_headers = ['Category', 'Site', 'Username', 'Password', 'Show / Hide Password']
    visible_indices = [1, 2, 3, 4, 6]
    visible_headers.each_with_index do |title, idx|
      renderer = Gtk::CellRendererText.new
      if idx == visible_headers.length - 1
        # Action column style: look like a button by using markup or making it bold
        renderer.mode = :activatable
      end
      column = Gtk::TreeViewColumn.new(title, renderer, text: visible_indices[idx])
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

    add_btn = Gtk::Button.new(label: 'Add')
    add_btn.signal_connect('clicked') { open_add_window }
    button_box.pack_start(add_btn, expand: false, fill: false, padding: 6)

    edit_btn = Gtk::Button.new(label: 'Edit')
    edit_btn.signal_connect('clicked') { open_edit_window }
    button_box.pack_start(edit_btn, expand: false, fill: false, padding: 6)

    delete_btn = Gtk::Button.new(label: 'Delete')
    delete_btn.signal_connect('clicked') { delete_selected }
    button_box.pack_start(delete_btn, expand: false, fill: false, padding: 6)

    regen_btn = Gtk::Button.new(label: 'Regenerate Recovery Token')
    regen_btn.signal_connect('clicked') { regenerate_token }
    button_box.pack_start(regen_btn, expand: false, fill: false, padding: 6)

    # State: per-row show/hide flags (credential id => boolean)
    @row_shown = {}

    # Handle clicks on the TreeView to detect when the Action column is clicked
    @tree_view.signal_connect('button-press-event') do |tv, event|
      # only handle left-clicks
      if event.event_type == Gdk::EventType::BUTTON_PRESS && event.button == 1
        at = tv.get_path_at_pos(event.x.to_i, event.y.to_i)
        if at # returns [path, column, cell_x, cell_y]
          path, column, = at
          col_index = tv.columns.index(column)
          # action column is the last visible index (6 in model)
          # find index of the column object to compare
          if col_index && tv.columns[col_index] && tv.columns[col_index].title == 'Show / Hide Password'
            iter = @list_store.get_iter(path)
            id = iter[0].to_i
            # toggle flag
            @row_shown[id] = !@row_shown.fetch(id, false)
            # update displayed password and action label
            real_pw = iter[5] # password_real
            if @row_shown[id]
              iter[4] = real_pw || '[unable to decrypt]'
              iter[6] = 'Hide Password'
            else
              iter[4] = real_pw ? '********' : '[unable to decrypt]'
              iter[6] = 'Show Password'
            end
            true
          else
            false
          end
        else
          false
        end
      else
        false
      end
    end

    refresh_categories
    refresh_list
    @window.show_all
  end

  # expose window for helpers
  attr_reader :window

  def refresh_categories
    @category_combo.remove_all
    return unless $session && $session[:user]

    cats = Credential.distinct_categories($session[:user].row['id']).compact.map(&:strip).reject(&:empty?).uniq.sort
    @category_combo.append_text('All')
    cats.each { |c| @category_combo.append_text(c) }
    @category_combo.append_text('(Uncategorized)')
    @category_combo.active = 0
  end

  def refresh_list
    @list_store.clear
    return unless $session && $session[:user] && $session[:data_key]

    selected = begin
      @category_combo.active_text
    rescue StandardError
      'All'
    end

    rows = case selected
           when nil, 'All'
             Credential.for_user($session[:user].row['id'], $session[:data_key])
           when '(Uncategorized)'
             Credential.for_user($session[:user].row['id'], $session[:data_key]).select do |r|
               r[:category].nil? || r[:category].strip.empty?
             end
           else
             Credential.for_user($session[:user].row['id'], $session[:data_key]).select { |r| r[:category] == selected }
           end

    rows.each do |c|
      iter = @list_store.append
      iter[0] = c[:id].to_s
      iter[1] = c[:category] || ''
      iter[2] = c[:site]
      iter[3] = c[:username]
      # store the real password in a hidden column (5)
      iter[5] = c[:password] || nil
      # determine whether this row is currently shown
      shown = @row_shown.fetch(c[:id], false)
      iter[4] = if shown
                  c[:password] || '[unable to decrypt]'
                else
                  c[:password] ? '********' : '[unable to decrypt]'
                end
      iter[6] = shown ? 'Hide Password' : 'Show Password'
    end
  end

  def open_add_window
    AddCredentialWindow.new($session[:user].row['id'], $session[:data_key], self)
  end

  def open_edit_window
    selection = @tree_view.selection.selected
    if selection.nil?
      Helpers.show_info(@window, 'Select an item first')
      return
    end

    id = selection[0].to_i

    # Fetch the real credential by id so we always get the decrypted password,
    # even if the list shows masked values.
    creds = Credential.for_user($session[:user].row['id'], $session[:data_key])
    cred = creds.find { |r| r[:id] == id }
    unless cred
      Helpers.show_error(@window, 'Could not find the selected credential')
      return
    end

    EditCredentialWindow.new($session[:user].row['id'], $session[:data_key], self, cred[:id], cred[:category],
                             cred[:site], cred[:username], cred[:password])
  end

  def delete_selected
    selection = @tree_view.selection.selected
    if selection.nil?
      Helpers.show_info(@window, 'Select an item first')
      return
    end

    id = selection[0].to_i
    site = selection[2] || '[unknown site]'

    # Confirm deletion with the user including the site name
    msg = "Are you sure you'd like to delete '#{site}' password?"
    return unless Helpers.confirm(@window, msg, title: 'Confirm Delete')

    Credential.delete(id, $session[:user].row['id'])
    refresh_list
    Helpers.show_info(@window, "Deleted '#{site}'")
  end

  def regenerate_token
    token = $session[:user].regenerate_recovery_token!($session[:data_key])
    Helpers.show_token_dialog(@window, token, title: 'New Recovery Token')
  end

  def info_message(msg)
    Helpers.show_info(@window, msg)
  end
end

# ---------- AddCredentialWindow (unchanged) ----------
class AddCredentialWindow
  def initialize(user_id, data_key, main_ui)
    @user_id = user_id
    @data_key = data_key
    @main_ui = main_ui

    @window = Gtk::Window.new('Add Credential')
    @window.set_default_size(420, 260)

    grid = Gtk::Grid.new
    grid.set_row_spacing(6)
    grid.set_column_spacing(6)
    grid.margin = 12
    @window.add(grid)

    Gtk::Label.new('Category (optional)').tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @cat_entry = Gtk::Entry.new
    grid.attach(@cat_entry, 1, 0, 1, 1)

    Gtk::Label.new('Site (required)').tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @site_entry = Gtk::Entry.new
    grid.attach(@site_entry, 1, 1, 1, 1)

    Gtk::Label.new('Username (required)').tap { |l| grid.attach(l, 0, 2, 1, 1) }
    @uname_entry = Gtk::Entry.new
    grid.attach(@uname_entry, 1, 2, 1, 1)

    Gtk::Label.new('Password (required)').tap { |l| grid.attach(l, 0, 3, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    grid.attach(@pw_entry, 1, 3, 1, 1)

    save_button = Gtk::Button.new(label: 'Save')
    save_button.signal_connect('clicked') { save_and_close }
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
      Helpers.show_error(@window, 'Site, username, and password are required')
      return
    end

    # Check duplicate site before creating
    if Credential.exists_for_site?($session[:user].row['id'], site)
      Helpers.show_error(@window,
                         "A credential for '#{site}' already exists. Please edit or delete the existing record.")
      return
    end

    begin
      Credential.create(@user_id, cat, site, uname, pw, @data_key)
    rescue StandardError => e
      Helpers.show_error(@window, e.message)
      return
    end

    @main_ui.refresh_categories
    @main_ui.refresh_list
    @window.destroy
  end
end

# ---------- EditCredentialWindow (unchanged) ----------
class EditCredentialWindow
  def initialize(user_id, data_key, main_ui, id, category, site, username, password)
    @user_id = user_id
    @data_key = data_key
    @main_ui = main_ui
    @cred_id = id

    @window = Gtk::Window.new('Edit Credential')
    @window.set_default_size(420, 260)

    grid = Gtk::Grid.new
    grid.set_row_spacing(6)
    grid.set_column_spacing(6)
    grid.margin = 12
    @window.add(grid)

    Gtk::Label.new('Category (optional)').tap { |l| grid.attach(l, 0, 0, 1, 1) }
    @cat_entry = Gtk::Entry.new
    @cat_entry.text = category || ''
    grid.attach(@cat_entry, 1, 0, 1, 1)

    Gtk::Label.new('Site (required)').tap { |l| grid.attach(l, 0, 1, 1, 1) }
    @site_entry = Gtk::Entry.new
    @site_entry.text = site
    grid.attach(@site_entry, 1, 1, 1, 1)

    Gtk::Label.new('Username (required)').tap { |l| grid.attach(l, 0, 2, 1, 1) }
    @uname_entry = Gtk::Entry.new
    @uname_entry.text = username
    grid.attach(@uname_entry, 1, 2, 1, 1)

    Gtk::Label.new('Password (required)').tap { |l| grid.attach(l, 0, 3, 1, 1) }
    @pw_entry = Gtk::Entry.new
    @pw_entry.visibility = false
    @pw_entry.text = password || ''
    grid.attach(@pw_entry, 1, 3, 1, 1)

    save_button = Gtk::Button.new(label: 'Save Changes')
    save_button.signal_connect('clicked') { save_and_close }
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
      Helpers.show_error(@window, 'Site, username, and password are required')
      return
    end

    # Check duplicate (excluding the current record)
    if Credential.exists_for_site_excluding?($session[:user].row['id'], site, @cred_id)
      Helpers.show_error(@window,
                         "Another credential for '#{site}' already exists. Please edit that entry or choose a different site.")
      return
    end

    begin
      Credential.update(@cred_id, @user_id, cat, site, uname, pw, @data_key)
    rescue StandardError => e
      Helpers.show_error(@window, e.message)
      return
    end

    @main_ui.refresh_categories
    @main_ui.refresh_list
    @window.destroy
  end
end
