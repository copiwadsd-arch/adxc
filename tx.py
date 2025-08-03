import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import json
import os
import paramiko
import threading
import time
import base64
import socket
import pyte  # Terminal emulator

CONFIG_FILE = 'config.json'
APP_NAME = "NexusTerm"
DEFAULT_GEOMETRY = "1200x800"

class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, prompt_text):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x180")
        self.transient(parent)
        self.grab_set()
        self.result = None
        ctk.CTkLabel(self, text=prompt_text, wraplength=320).pack(padx=20, pady=10, expand=True)
        self.pass_entry = ctk.CTkEntry(self, show="*")
        self.pass_entry.pack(padx=20, pady=5, fill="x")
        self.pass_entry.focus()
        self.pass_entry.bind("<Return>", self.on_ok)
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=20)
        ctk.CTkButton(button_frame, text="OK", command=self.on_ok, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Cancel", command=self.on_cancel, width=100, fg_color="#D32F2F", hover_color="#B71C1C").pack(side="left", padx=10)
        self.wait_window(self)
    def on_ok(self, event=None):
        self.result = self.pass_entry.get()
        self.destroy()
    def on_cancel(self):
        self.result = None
        self.destroy()

class NexusTermApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry(DEFAULT_GEOMETRY)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.sessions = {}
        self.command_snippets = []
        self.ssh_sessions = {}
        self.load_config()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.top_frame = ctk.CTkFrame(self, height=40, corner_radius=0)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.top_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self.top_frame, text="Quick Connect:").grid(row=0, column=0, padx=10, pady=10)
        self.quick_connect_entry = ctk.CTkEntry(self, placeholder_text="user@hostname:port")
        self.quick_connect_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.quick_connect_entry.bind("<Return>", self.handle_quick_connect)
        ctk.CTkButton(self.top_frame, text="Connect", command=self.handle_quick_connect).grid(row=0, column=2, padx=10, pady=10)
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar_frame.grid(row=1, column=0, sticky="nsw")
        self.sidebar_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkButton(self.sidebar_frame, text="Add New Session", command=self.add_or_edit_session).grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.session_tree = tk.Listbox(self.sidebar_frame, bg="#2B2B2B", fg="white", borderwidth=0, highlightthickness=0, selectbackground="#1F6AA5")
        self.session_tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.session_tree.bind("<Double-1>", self.on_session_double_click)
        self.session_tree.bind("<Button-3>", self.show_session_context_menu)
        ctk.CTkButton(self.sidebar_frame, text="Close All Tabs", command=self.close_all_tabs, fg_color="#D32F2F", hover_color="#B71C1C").grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.tab_view = ctk.CTkTabview(self, corner_radius=8)
        self.tab_view.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        self.after(10, lambda: self.tab_view.add("Welcome"))
        self.after(100, self.setup_welcome_tab)
        self.update_session_list()

    def setup_welcome_tab(self):
        try:
            welcome_tab = self.tab_view.tab("Welcome")
            welcome_label = ctk.CTkLabel(welcome_tab, text="Welcome to NexusTerm!\n\nDouble-click a session on the left to connect.", font=ctk.CTkFont(size=16))
            welcome_label.pack(expand=True, padx=20, pady=20)
        except KeyError:
            pass

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.sessions = config.get('sessions', {})
                    self.command_snippets = config.get('command_snippets', [])
            except json.JSONDecodeError:
                messagebox.showerror("Config Error", f"Could not read {CONFIG_FILE}. It might be corrupted.")
                self.sessions, self.command_snippets = {}, []
        else:
            self.sessions = {"Example-Router": {"host": "192.168.1.1", "port": 22, "user": "cisco", "password": ""}}
            self.command_snippets = [{"name": "Show Run", "command": "show running-config"}, {"name": "Show IP Int Brief", "command": "show ip interface brief"}]
            self.save_config()

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'sessions': self.sessions, 'command_snippets': self.command_snippets}, f, indent=4)

    def update_session_list(self):
        self.session_tree.delete(0, tk.END)
        for session_name in sorted(self.sessions.keys()):
            self.session_tree.insert(tk.END, session_name)

    def add_or_edit_session(self, session_name=None, duplicate=False):
        dialog = SessionDialog(self, "Session Details", session_name=session_name, existing_details=self.sessions.get(session_name), duplicate=duplicate)
        if dialog.result:
            new_name, details = dialog.result
            if session_name and session_name != new_name and not duplicate:
                del self.sessions[session_name]
            self.sessions[new_name] = details
            self.save_config()
            self.update_session_list()
    
    def delete_session(self):
        if not self.session_tree.curselection(): return
        session_name = self.session_tree.get(self.session_tree.curselection()[0])
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete session '{session_name}'?"):
            del self.sessions[session_name]
            self.save_config()
            self.update_session_list()

    def show_session_context_menu(self, event):
        self.session_tree.selection_clear(0, tk.END)
        self.session_tree.selection_set(self.session_tree.nearest(event.y))
        if not self.session_tree.curselection(): return
        session_name = self.session_tree.get(self.session_tree.curselection()[0])
        menu = tk.Menu(self, tearoff=0, bg="#2B2B2B", fg="white")
        menu.add_command(label="Connect", command=lambda: self.connect_session(session_name))
        menu.add_command(label="Edit", command=lambda: self.add_or_edit_session(session_name))
        menu.add_command(label="Duplicate & Edit", command=lambda: self.add_or_edit_session(session_name, duplicate=True))
        menu.add_separator()
        menu.add_command(label="Delete", command=self.delete_session)
        menu.tk_popup(event.x_root, event.y_root)

    def show_tab_context_menu(self, event, tab_name):
        if tab_name == "Welcome": return
        menu = tk.Menu(self, tearoff=0, bg="#2B2B2B", fg="white")
        menu.add_command(label=f"Close '{tab_name}'", command=lambda: self.close_tab(tab_name))
        menu.tk_popup(event.x_root, event.y_root)

    def close_tab(self, tab_name):
        if tab_name in self.ssh_sessions:
            session_info = self.ssh_sessions.pop(tab_name)
            if session_info['client']:
                session_info['client'].close()
        try:
            self.tab_view.delete(tab_name)
        except tk.TclError:
            pass

    def close_all_tabs(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to close all tabs?"):
            for tab_name in list(self.ssh_sessions.keys()):
                self.close_tab(tab_name)
            for tab_name in self.tab_view.tab_names:
                if tab_name != "Welcome":
                    self.close_tab(tab_name)

    def on_session_double_click(self, event):
        if not self.session_tree.curselection(): return
        session_name = self.session_tree.get(self.session_tree.curselection()[0])
        self.connect_session(session_name)

    def handle_quick_connect(self, event=None):
        conn_str = self.quick_connect_entry.get()
        if '@' not in conn_str:
            messagebox.showerror("Invalid Format", "Please use the format: user@hostname:port")
            return
        user, host_info = conn_str.split('@', 1)
        host, port_str = (host_info.split(':', 1) + ["22"])[:2]
        try: port = int(port_str)
        except ValueError: messagebox.showerror("Invalid Port", f"Port '{port_str}' is not a valid number."); return
        session_name = f"Quick: {user}@{host}"
        session_details = {"user": user, "host": host, "port": port, "password": ""}
        self.connect_session(session_name, details=session_details)
        self.quick_connect_entry.delete(0, tk.END)

    def connect_session(self, session_name, details=None):
        try:
            self.tab_view.set(session_name)
            return
        except (KeyError, ValueError):
            pass
        session_details = details or self.sessions.get(session_name)
        if not session_details:
            messagebox.showerror("Error", "Session details not found.")
            return
        tab = self.tab_view.add(session_name)
        self.tab_view.set(session_name)
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        # Setup terminal output
        # We'll use a normal Text widget for better control
        terminal_output = tk.Text(tab, font=("Consolas", 12), bg="#212121", fg="#F2F2F2", insertbackground="white", wrap="none", state="disabled", cursor="xterm")
        terminal_output.grid(row=0, column=0, sticky="nsew")
        terminal_output.bind("<Button-3>", lambda event, name=session_name: self.show_tab_context_menu(event, name))
        terminal_output.bind("<KeyPress>", lambda event, name=session_name: self.on_terminal_key_press(event, name))
        # Scrollbar
        scrollbar = tk.Scrollbar(tab, command=terminal_output.yview)
        terminal_output.config(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        # Terminal emulator state (pyte)
        screen = pyte.Screen(120, 40)
        stream = pyte.ByteStream()
        self.ssh_sessions[session_name] = {
            'client': None,
            'shell': None,
            'screen': screen,
            'stream': stream,
            'output_widget': terminal_output,
            'tab': tab
        }
        self.update_terminal_text(terminal_output, f"Attempting to connect to {session_details['host']}...\n")
        thread = threading.Thread(target=self.ssh_thread_worker, args=(session_name, session_details))
        thread.daemon = True
        thread.start()

    def on_terminal_key_press(self, event, session_name):
        """Send raw key codes to the remote shell (no local editing/history)."""
        session_info = self.ssh_sessions.get(session_name)
        if not session_info or not session_info['shell']:
            return "break"
        shell = session_info['shell']
        # Handle Ctrl+C and Ctrl+V
        if event.state == 4:
            if event.keysym.lower() == 'c':  # Ctrl+C
                shell.send('\x03')
                return "break"
            if event.keysym.lower() == 'v':  # Ctrl+V
                try:
                    clipboard_text = self.clipboard_get()
                    shell.send(clipboard_text)
                except tk.TclError:
                    pass
                return "break"
        # Send the correct key codes for terminal input
        try:
            if event.keysym == "Return":
                shell.send('\r')
            elif event.keysym == "BackSpace":
                shell.send('\x7f')  # DEL, most shells expect this
            elif event.keysym == "Up":
                shell.send('\x1b[A')
            elif event.keysym == "Down":
                shell.send('\x1b[B')
            elif event.keysym == "Right":
                shell.send('\x1b[C')
            elif event.keysym == "Left":
                shell.send('\x1b[D')
            elif event.keysym == "Tab":
                shell.send('\t')
            elif event.char and event.char.isprintable():
                shell.send(event.char)
        except Exception:
            pass
        return "break"

    def _get_password_from_dialog(self, details):
        password = None
        event = threading.Event()
        def open_dialog_and_set_password():
            nonlocal password
            dialog = PasswordDialog(self, "Password Required", f"Enter password for {details['user']}@{details['host']}:")
            password = dialog.result
            event.set()
        self.after(0, open_dialog_and_set_password)
        event.wait()
        return password

    def ssh_thread_worker(self, session_name, details):
        session_info = self.ssh_sessions[session_name]
        output_widget = session_info['output_widget']
        screen = session_info['screen']
        stream = session_info['stream']
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        session_info['client'] = client
        def render_screen():
            lines = screen.display
            self.update_terminal_text(output_widget, '\n'.join(lines) + '\n', overwrite=True)
        try:
            password = details.get("password")
            if password:
                try: password = base64.b64decode(password.encode('utf-8')).decode('utf-8')
                except Exception: password = ""
            if not password:
                password = self._get_password_from_dialog(details)
                if password is None:
                    self.update_terminal_text(output_widget, "\nConnection cancelled by user.\n")
                    return
            client.connect(hostname=details['host'], port=details['port'], username=details['user'], password=password, timeout=15, look_for_keys=False, allow_agent=False)
            shell = client.invoke_shell(term='xterm', width=120, height=40)
            session_info['shell'] = shell

            self.after(0, lambda: output_widget.config(state="normal"))
            self.after(0, lambda: output_widget.focus_set())
            self.update_terminal_text(output_widget, "Connected! Disabling terminal paging...\n")
            shell.send('terminal length 0\n')
            time.sleep(0.5)
            while client.get_transport() and client.get_transport().is_active():
                if shell.recv_ready():
                    output = shell.recv(8192)
                    try:
                        stream.feed(output)
                        while True:
                            data = stream.read()
                            if not data:
                                break
                            screen.feed(data.decode('utf-8', errors='ignore'))
                        self.after(0, render_screen)
                    except Exception as e:
                        self.after(0, lambda: self.update_terminal_text(output_widget, f"\n--- ERROR ---\n{str(e)}\n"))
                else:
                    time.sleep(0.05)
        except paramiko.AuthenticationException:
            self.update_terminal_text(output_widget, "\n--- CONNECTION FAILED ---\nAuthentication failed. Please check your username and password.\n")
        except socket.gaierror:
            self.update_terminal_text(output_widget, f"\n--- CONNECTION FAILED ---\nDNS lookup failed. Check the hostname: {details['host']}\n")
        except ConnectionRefusedError:
            self.update_terminal_text(output_widget, f"\n--- CONNECTION FAILED ---\nConnection refused by the server. Is SSH enabled on port {details['port']}?\n")
        except socket.timeout:
            self.update_terminal_text(output_widget, f"\n--- CONNECTION FAILED ---\nConnection to {details['host']} timed out.\n")
        except paramiko.SSHException as e:
            self.update_terminal_text(output_widget, f"\n--- SSH ERROR ---\n{str(e)}\n")
        except Exception as e:
            self.update_terminal_text(output_widget, f"\n--- UNEXPECTED ERROR ---\n{str(e)}\n")
        finally:
            if client: client.close()
            if session_name in self.ssh_sessions: del self.ssh_sessions[session_name]
            self.update_terminal_text(output_widget, "\n--- DISCONNECTED ---\n")
            self.after(0, lambda: output_widget.config(state="disabled"))

    def update_terminal_text(self, widget, text, overwrite=False):
        widget.config(state="normal")
        if overwrite:
            widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.config(state="disabled")

    def on_closing(self):
        for session_info in self.ssh_sessions.values():
            if session_info['client']:
                session_info['client'].close()
        self.destroy()

class SessionDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, session_name=None, existing_details=None, duplicate=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x350")
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.existing_details = existing_details or {}
        display_name = f"{session_name} (Copy)" if duplicate else (session_name or "")
        self.name_entry = self._create_entry("Session Name:", display_name, 0)
        self.host_entry = self._create_entry("Hostname/IP:", self.existing_details.get("host", ""), 1)
        self.port_entry = self._create_entry("Port:", self.existing_details.get("port", 22), 2)
        self.user_entry = self._create_entry("Username:", self.existing_details.get("user", ""), 3)
        ctk.CTkLabel(self, text="Password (optional):").grid(row=4, column=0, padx=20, pady=5, sticky="w")
        self.pass_entry = ctk.CTkEntry(self, show="*")
        self.pass_entry.grid(row=4, column=1, padx=20, pady=5, sticky="ew")
        self.save_pass_var = tk.IntVar()
        self.save_pass_check = ctk.CTkCheckBox(self, text="Save Password (insecurely)", variable=self.save_pass_var)
        self.save_pass_check.grid(row=5, column=1, padx=20, pady=5, sticky="w")
        if self.existing_details.get("password"):
            self.save_pass_check.select()
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        ctk.CTkButton(button_frame, text="Save", command=self.on_save).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Cancel", command=self.destroy).pack(side="left", padx=10)
        self.wait_window(self)

    def _create_entry(self, label_text, default_value, row):
        ctk.CTkLabel(self, text=label_text).grid(row=row, column=0, padx=20, pady=5, sticky="w")
        entry = ctk.CTkEntry(self)
        entry.insert(0, str(default_value))
        entry.grid(row=row, column=1, padx=20, pady=5, sticky="ew")
        return entry

    def on_save(self):
        session_name = self.name_entry.get()
        if not all([session_name, self.host_entry.get(), self.port_entry.get(), self.user_entry.get()]):
            messagebox.showerror("Validation Error", "All fields except password must be filled.", parent=self)
            return
        try: port = int(self.port_entry.get())
        except ValueError: messagebox.showerror("Validation Error", "Port must be a number.", parent=self); return
        password = ""
        if self.save_pass_var.get() == 1 and self.pass_entry.get():
            password = base64.b64encode(self.pass_entry.get().encode('utf-8')).decode('utf-8')
        elif self.save_pass_var.get() == 1 and not self.pass_entry.get():
            password = self.existing_details.get("password", "")
        self.result = (session_name, {"host": self.host_entry.get(), "port": port, "user": self.user_entry.get(), "password": password})
        self.destroy()

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = NexusTermApp()
    app.mainloop()