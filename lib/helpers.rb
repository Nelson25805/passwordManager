# lib/helpers.rb
require 'gtk3'

module Helpers
  module_function

  def copy_to_clipboard(token)
    # Try GTK clipboard
    begin
      clipboard = Gtk::Clipboard.get(Gdk::Atom.intern("CLIPBOARD"))
      clipboard.set_text(token)
      return true
    rescue
      # fall through to command-line fallbacks
    end

    begin
      if Gem.win_platform?
        IO.popen('clip', 'w') { |f| f << token }
        return true
      elsif system('which pbcopy > /dev/null 2>&1')
        IO.popen('pbcopy', 'w') { |f| f << token }
        return true
      elsif system('which wl-copy > /dev/null 2>&1')
        IO.popen('wl-copy', 'w') { |f| f << token }
        return true
      elsif system('which xclip > /dev/null 2>&1')
        IO.popen('xclip -selection clipboard', 'w') { |f| f << token }
        return true
      else
        return false
      end
    rescue
      return false
    end
  end

  # lib/helpers.rb (replace show_token_dialog with this implementation)
def show_token_dialog(parent_window, token, title: "Recovery Token")
  dlg = Gtk::Dialog.new(title: title, parent: parent_window, flags: :modal)

  # OK will close the dialog (response)
  dlg.add_button("OK", Gtk::ResponseType::OK)

  # Create a Copy button as a regular button (not a response) so it won't close the dialog
  copy_btn = Gtk::Button.new(label: "Copy")
  # pack into the action area (dialog.action_area is a Box)
  dlg.action_area.pack_start(copy_btn, expand: false, fill: false, padding: 6)

  content = dlg.child

  label = Gtk::Label.new("Save this recovery token (shown only once):")
  label.wrap = true
  label.halign = :start
  content.pack_start(label, expand: false, fill: false, padding: 6)

  token_entry = Gtk::Entry.new
  token_entry.text = token
  token_entry.editable = false
  token_entry.halign = :fill
  token_entry.width_chars = [token.length, 40].min
  content.pack_start(token_entry, expand: false, fill: true, padding: 6)

  # Handler for the copy button: copy & show small info dialog, but DO NOT close dlg
  copy_btn.signal_connect("clicked") do
    copied = copy_to_clipboard(token)
    token_entry.select_region(0, token.length) if token_entry.respond_to?(:select_region)
    info = copied ? "Copied to clipboard." : "Could not copy to clipboard; please save token manually."
    notice = Gtk::MessageDialog.new(parent: dlg, flags: :modal, type: :info, buttons: :ok, message: info)
    notice.run
    notice.destroy
  end

  dlg.show_all
  # Run the dialog; only OK will end the run loop
  dlg.run
  dlg.destroy
end

# Asks the user a yes/no question. Returns true if they clicked "Yes".
  def confirm(parent, message, title: "Confirm")
  dlg = Gtk::MessageDialog.new(
    parent: parent,
    flags: :modal,
    type: :question,
    buttons: :yes_no,
    message: message,
    title: title
  )
  resp = dlg.run
  dlg.destroy
  resp == Gtk::ResponseType::YES
  end


  def show_info(parent, message)
    dialog = Gtk::MessageDialog.new(parent: parent, flags: :modal, type: :info, buttons: :ok, message: message)
    dialog.run
    dialog.destroy
  end

  def show_error(parent, message)
    dialog = Gtk::MessageDialog.new(parent: parent, flags: :modal, type: :error, buttons: :ok, message: message)
    dialog.run
    dialog.destroy
  end
end
