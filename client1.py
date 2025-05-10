import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, scrolledtext, messagebox
import socket
import threading
import gnupg
import os
import json
import queue
from datetime import datetime
import sys
import subprocess
import pyperclip
import uuid
import time
import logging

import self

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 65432
BUFFER_SIZE = 8192
MAX_FILE_SIZE_CLIENT = 50 * 1024 * 1024

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
except Exception:
    SCRIPT_DIR = os.getcwd()

DOWNLOAD_DIR = os.path.join(SCRIPT_DIR, "received_files")
TEMP_SEND_DIR = os.path.join(SCRIPT_DIR, "temp_send_files")
HISTORY_FILE = os.path.join(SCRIPT_DIR, "client_history.json")
SAVED_PUBLIC_KEYS_FILE = os.path.join(SCRIPT_DIR, "saved_public_keys.json")
SAVED_RECIPIENTS_FILE = os.path.join(SCRIPT_DIR, "saved_recipients.json")

GPG_BINARY_PATH_ENV = os.environ.get('GPG_EXECUTABLE')
GPG_BINARY_PATH_CONFIG = 'E:\GPG4win\file\GnuPG\bin\gpg.exe'


class PGPClientGUI:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("PGP Client")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        self.gpg = None
        self.gpg_init_error_message = None
        self._initialize_gpg()

        self.client_socket = None
        self.username = None
        self.is_connected = False
        self.receiver_thread = None
        self.message_queue = queue.Queue()
        self.pending_upload = None

        self.history = []
        self.saved_recipient_keys = []

        self.passphrase_requests = {}
        self.passphrase_lock = threading.Lock()

        for dir_path in [DOWNLOAD_DIR, TEMP_SEND_DIR]:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path)
                except OSError as e:
                    messagebox.showerror("Lỗi Tạo Thư Mục", f"Không thể tạo '{dir_path}': {e}")
                    self.root.destroy()
                    return

        self._setup_ui()
        self._load_history()
        self._load_saved_recipient_keys()
        self._populate_recipient_keys_treeview()
        self.root.after(100, self._process_message_queue)

        if self.gpg:
            self._find_and_display_my_keys()
            self._check_gpg_status(silent=True)
        else:
            self._disable_pgp_dependent_widgets()
            if self.gpg_init_error_message:
                messagebox.showerror("Lỗi Khởi Tạo GnuPG", self.gpg_init_error_message, parent=self.root)

    def _initialize_gpg(self):
        try:
            env_gpg_path = os.environ.get('GPG_EXECUTABLE')
            if env_gpg_path and os.path.exists(env_gpg_path) and os.access(env_gpg_path, os.X_OK):
                self.gpg = gnupg.GPG(gpgbinary=env_gpg_path, use_agent=True)
                self.gpg.list_keys()
                self.gpg_init_error_message = None
                logging.info(f"GPG initialized from GPG_EXECUTABLE: {env_gpg_path}")
                return

            config_gpg_path = GPG_BINARY_PATH_CONFIG
            if config_gpg_path and os.path.exists(config_gpg_path) and os.access(config_gpg_path, os.X_OK):
                self.gpg = gnupg.GPG(gpgbinary=config_gpg_path, use_agent=True)
                self.gpg.list_keys()
                self.gpg_init_error_message = None
                logging.info(f"GPG initialized from GPG_BINARY_PATH_CONFIG: {config_gpg_path}")
                return

            self.gpg = gnupg.GPG(use_agent=True)
            self.gpg.list_keys()
            self.gpg_init_error_message = None
            logging.info("GPG initialized using system PATH.")
            return

        except (OSError, Exception) as e_init:
            self.gpg = None
            common_paths = []
            if os.name == 'nt':
                common_paths = [
                    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "GnuPG", "bin", "gpg.exe"),
                    os.path.join(os.environ.get("ProgramFiles", ""), "GnuPG", "bin", "gpg.exe"),
                    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "GnuPG", "bin", "gpg.exe"),
                    "gpg.exe"
                ]
            else:
                common_paths = ["/usr/bin/gpg", "/usr/local/bin/gpg", "/opt/homebrew/bin/gpg", "gpg"]

            found_path = None
            for path_attempt in common_paths:
                try:
                    if not (os.path.exists(path_attempt) and os.access(path_attempt,
                                                                       os.X_OK)) and path_attempt != "gpg" and path_attempt != "gpg.exe":
                        if os.path.isabs(path_attempt): continue

                    self.gpg = gnupg.GPG(
                        gpgbinary=path_attempt if (path_attempt != "gpg" and path_attempt != "gpg.exe") else None,
                        use_agent=True)
                    self.gpg.list_keys()
                    found_path = path_attempt
                    break
                except (OSError, Exception):
                    self.gpg = None
                    continue

            if found_path:
                self.gpg_init_error_message = None
                logging.info(f"GPG found and initialized at: {found_path}")
            else:
                self.gpg = None
                self.gpg_init_error_message = (
                    "Lỗi: Không thể tìm thấy hoặc chạy GnuPG.\n"
                    "Hãy đảm bảo GnuPG (ví dụ: Gpg4win trên Windows, GnuPG trên Linux/macOS) đã được cài đặt và "
                    "đường dẫn tới 'gpg.exe' (hoặc 'gpg') nằm trong PATH hệ thống, "
                    "hoặc được cấu hình đúng trong script (biến GPG_BINARY_PATH_CONFIG).\n"
                    "Chức năng mã hóa/giải mã sẽ không hoạt động."
                )
                logging.critical(
                    f"GPG Initialization CRITICAL ERROR: {self.gpg_init_error_message}. Original error: {e_init}")

    def _setup_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        gpg_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="GPG", menu=gpg_menu, underline=0)
        gpg_menu.add_command(label="Kiểm tra GPG", command=self._check_gpg_status, underline=0)

        connect_frame = ttk.LabelFrame(self.root, text="Kết nối Server", padding="5 5 5 5")
        connect_frame.pack(pady=(5, 0), padx=10, fill="x")
        ttk.Label(connect_frame, text="Host:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.host_entry = ttk.Entry(connect_frame, width=15)
        self.host_entry.insert(0, DEFAULT_HOST)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)
        ttk.Label(connect_frame, text="Port:").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.port_entry = ttk.Entry(connect_frame, width=7)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=0, column=3, padx=5, pady=2)
        ttk.Label(connect_frame, text="Username:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.username_entry = ttk.Entry(connect_frame, width=15)
        self.username_entry.grid(row=1, column=1, padx=5, pady=2)
        self.username_entry.bind("<Return>", lambda event: self._toggle_connect())
        self.connect_button = ttk.Button(connect_frame, text="Kết nối", command=self._toggle_connect)
        self.connect_button.grid(row=1, column=2, columnspan=2, padx=5, pady=2, sticky="ew")

        gpg_manage_frame = ttk.LabelFrame(self.root, text="Quản lý Khóa GPG Cá Nhân", padding="5 5 5 5")
        gpg_manage_frame.pack(pady=5, padx=10, fill="x")

        self.generate_key_button = ttk.Button(gpg_manage_frame, text="Tạo Cặp Khóa Mới",
                                              command=self._show_generate_key_dialog)
        self.generate_key_button.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")

        ttk.Label(gpg_manage_frame, text="Private Key (Fingerprint):").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.my_private_key_var = tk.StringVar(value="Chưa có khóa / GPG lỗi")
        self.my_private_key_entry = ttk.Entry(gpg_manage_frame, textvariable=self.my_private_key_var, width=60,
                                              state="readonly")
        self.my_private_key_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        self._add_copy_context_menu(self.my_private_key_entry)

        ttk.Label(gpg_manage_frame, text="Public Key của bạn:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.my_public_key_text = scrolledtext.ScrolledText(gpg_manage_frame, height=4, width=60, wrap=tk.WORD,
                                                            state=tk.DISABLED, font=("Courier New", 9))
        self.my_public_key_text.grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        self._add_copy_context_menu(self.my_public_key_text, is_scrolled_text=True)

        self.copy_my_public_key_button = ttk.Button(gpg_manage_frame, text="Copy Public Key của bạn",
                                                    command=self._copy_my_public_key_to_clipboard)
        self.copy_my_public_key_button.grid(row=3, column=1, padx=5, pady=5, sticky="e")
        gpg_manage_frame.columnconfigure(1, weight=1)

        recipient_keys_frame = ttk.LabelFrame(self.root, text="Quản lý Public Keys Người Nhận", padding="5 5 5 5")
        recipient_keys_frame.pack(pady=5, padx=10, fill="x")

        tree_frame = ttk.Frame(recipient_keys_frame)
        tree_frame.pack(side=tk.LEFT, fill="x", expand=True, pady=2, padx=5)

        cols_recipient_keys = ('username', 'key_id')
        self.recipient_keys_tree = ttk.Treeview(tree_frame, columns=cols_recipient_keys, show='headings', height=4)
        self.recipient_keys_tree.heading('username', text='Username')
        self.recipient_keys_tree.column('username', width=120, anchor='w')
        self.recipient_keys_tree.heading('key_id', text='Key ID/Fingerprint')
        self.recipient_keys_tree.column('key_id', width=350, anchor='w')

        vsb_rk = ttk.Scrollbar(tree_frame, orient="vertical", command=self.recipient_keys_tree.yview)
        self.recipient_keys_tree.configure(yscrollcommand=vsb_rk.set)
        vsb_rk.pack(side=tk.RIGHT, fill='y')
        self.recipient_keys_tree.pack(side=tk.LEFT, fill="both", expand=True)
        self.recipient_keys_tree.bind('<<TreeviewSelect>>', self._on_recipient_key_select)
        self.recipient_keys_tree.bind("<Button-3>", self._show_recipient_key_context_menu)

        keys_buttons_frame = ttk.Frame(recipient_keys_frame)
        keys_buttons_frame.pack(side=tk.LEFT, fill='y', padx=5, pady=2)

        self.add_recipient_key_button = ttk.Button(keys_buttons_frame, text="Thêm Key Người Nhận",
                                                   command=self._show_add_recipient_key_dialog)
        self.add_recipient_key_button.pack(pady=2, fill='x')
        self.remove_recipient_key_button = ttk.Button(keys_buttons_frame, text="Xóa Key Đã Chọn",
                                                      command=self._remove_selected_recipient_key, state=tk.DISABLED)
        self.remove_recipient_key_button.pack(pady=2, fill='x')
        self._populate_recipient_keys_treeview()

        main_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        main_frame.pack(pady=(0, 5), padx=10, fill="both", expand=True)
        main_frame.columnconfigure(1, weight=3)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

        user_list_frame = ttk.LabelFrame(main_frame, text="Người dùng Online", padding=5)
        user_list_frame.grid(row=0, column=0, padx=(0, 5), pady=0, sticky="nswe")
        self.user_listbox = tk.Listbox(user_list_frame, height=15, exportselection=False, width=20)
        user_scrollbar = ttk.Scrollbar(user_list_frame, orient="vertical", command=self.user_listbox.yview)
        self.user_listbox.config(yscrollcommand=user_scrollbar.set)
        user_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.user_listbox.pack(side=tk.LEFT, fill="both", expand=True)
        self.user_listbox.bind('<<ListboxSelect>>', self._on_user_select)

        notebook_frame = ttk.Frame(main_frame)
        notebook_frame.grid(row=0, column=1, padx=(5, 0), pady=0, sticky="nswe")
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill="both", expand=True)

        log_tab = ttk.Frame(self.notebook, padding=2)
        self.notebook.add(log_tab, text="Log / Chat Chung")
        self.chat_area = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD, state=tk.DISABLED, height=10,
                                                   font=("Arial", 10))
        self.chat_area.pack(fill="both", expand=True)

        history_tab = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(history_tab, text="Lịch Sử Giao Dịch")

        history_filter_frame = ttk.Frame(history_tab)
        history_filter_frame.pack(fill="x", pady=(0, 5))
        ttk.Label(history_filter_frame, text="Lọc theo người dùng:").pack(side=tk.LEFT, padx=(0, 5))
        self.history_user_filter_var = tk.StringVar()
        self.history_user_filter_combo = ttk.Combobox(history_filter_frame, textvariable=self.history_user_filter_var,
                                                      state="readonly", width=25)
        self.history_user_filter_combo.pack(side=tk.LEFT)
        self.history_user_filter_combo.bind("<<ComboboxSelected>>", self._on_history_user_filter_change)

        cols_history = ('timestamp', 'type', 'direction', 'partner', 'details', 'status', 'path')
        self.history_tree = ttk.Treeview(history_tab, columns=cols_history, show='headings', height=10)
        self.history_tree.heading('timestamp', text='Thời gian')
        self.history_tree.column('timestamp', width=130, anchor='w', stretch=tk.NO)
        self.history_tree.heading('type', text='Loại')
        self.history_tree.column('type', width=50, anchor='w', stretch=tk.NO)
        self.history_tree.heading('direction', text='Chiều')
        self.history_tree.column('direction', width=60, anchor='w', stretch=tk.NO)
        self.history_tree.heading('partner', text='Đối tác')
        self.history_tree.column('partner', width=100, anchor='w')
        self.history_tree.heading('details', text='Chi tiết')
        self.history_tree.column('details', width=200, anchor='w')
        self.history_tree.heading('status', text='Trạng thái')
        self.history_tree.column('status', width=120, anchor='w')
        self.history_tree.heading('path', text='Đường dẫn')
        self.history_tree.column('path', width=150, anchor='w')

        vsb_h = ttk.Scrollbar(history_tab, orient="vertical", command=self.history_tree.yview)
        hsb_h = ttk.Scrollbar(history_tab, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=vsb_h.set, xscrollcommand=hsb_h.set)
        vsb_h.pack(side='right', fill='y')
        hsb_h.pack(side='bottom', fill='x')
        self.history_tree.pack(side='left', fill='both', expand=True)
        self.history_tree.bind("<Double-1>", self._on_history_item_double_click)

        action_frame = ttk.LabelFrame(self.root, text="Hành động", padding="5 5 5 5")
        action_frame.pack(pady=(0, 5), padx=10, fill="x")
        ttk.Label(action_frame, text="Người nhận:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.recipient_username_entry = ttk.Entry(action_frame, width=20, state=tk.DISABLED)
        self.recipient_username_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        ttk.Label(action_frame, text="GPG Key ID (Người nhận):").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.recipient_gpg_id_entry = ttk.Entry(action_frame, width=30, state=tk.DISABLED)
        self.recipient_gpg_id_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew", columnspan=1)
        self._add_copy_context_menu(self.recipient_gpg_id_entry)

        self.send_file_button = ttk.Button(action_frame, text="Gửi File...", command=self._send_file_action,
                                           state=tk.DISABLED)
        self.send_file_button.grid(row=0, column=2, padx=5, pady=2, rowspan=2, sticky="nsew")

        self.decrypt_gpg_file_button = ttk.Button(action_frame, text="Giải mã file .gpg", command=self._decrypt_gpg_file_dialog)
        self.decrypt_gpg_file_button.grid(row=0, column=3, padx=5, pady=2, rowspan=2, sticky="nsew")

        self.message_entry = ttk.Entry(action_frame, width=40, state=tk.DISABLED)
        self.message_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=2, sticky="ew")
        self.message_entry.bind("<Return>", lambda event: self._send_message_action())
        self.send_message_button = ttk.Button(action_frame, text="Gửi Tin Nhắn", command=self._send_message_action,
                                              state=tk.DISABLED)
        self.send_message_button.grid(row=2, column=2, padx=5, pady=2, sticky="ew")
        action_frame.columnconfigure(1, weight=2)
        action_frame.columnconfigure(2, weight=0)
        action_frame.columnconfigure(3, weight=0)

        self.status_var = tk.StringVar()
        self.status_var.set("Chưa kết nối.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self._update_history_display()

    def _add_copy_context_menu(self, widget, is_scrolled_text=False):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Copy", command=lambda w=widget, ist=is_scrolled_text: self._copy_widget_content(w, ist))

        def show_menu(event):
            if isinstance(event.widget, (ttk.Entry, tk.Entry)):
                if not event.widget.selection_present():
                    event.widget.select_range(0, tk.END)
                    event.widget.icursor(tk.END)
            menu.post(event.x_root, event.y_root)

        widget.bind("<Button-3>", show_menu)

    def _copy_widget_content(self, widget, is_scrolled_text=False):
        try:
            if is_scrolled_text:
                content = widget.get("1.0", tk.END).strip()
            elif hasattr(widget, 'selection_get') and widget.selection_present():
                content = widget.selection_get()
            elif isinstance(widget, (ttk.Entry, tk.Entry)):
                content = widget.get()
            else:
                content = ""

            if content:
                pyperclip.copy(content)
                self._log_message("Đã copy vào clipboard.", "INFO")
            else:
                self._log_message("Không có gì để copy.", "INFO")
        except tk.TclError:
            if isinstance(widget, (ttk.Entry, tk.Entry)):
                content = widget.get()
                if content:
                    pyperclip.copy(content)
                    self._log_message("Đã copy vào clipboard.", "INFO")
                else:
                    self._log_message("Không có gì để copy (Entry rỗng).", "INFO")
            else:
                self._log_message("Lỗi khi copy: Không có nội dung được chọn.", "WARNING")
        except Exception as e:
            self._log_message(f"Lỗi khi copy: {e}", "ERROR")
            messagebox.showerror("Lỗi Copy", f"Không thể copy nội dung: {e}", parent=self.root)

    def _show_recipient_key_context_menu(self, event):
        selection = self.recipient_keys_tree.identify_row(event.y)
        if selection:
            self.recipient_keys_tree.selection_set(selection)
            item_details = self.recipient_keys_tree.item(selection, 'values')
            if item_details and len(item_details) > 1:
                key_id_to_copy = item_details[1]
                menu = tk.Menu(self.recipient_keys_tree, tearoff=0)
                menu.add_command(label="Copy Key ID",
                                 command=lambda kid=key_id_to_copy: self._copy_text_to_clipboard(kid))
                menu.post(event.x_root, event.y_root)

    def _copy_text_to_clipboard(self, text):
        try:
            pyperclip.copy(text)
            self._log_message(f"Đã copy '{text[:30]}...' vào clipboard.", "INFO")
        except Exception as e:
            self._log_message(f"Lỗi copy: {e}", "ERROR")
            messagebox.showerror("Lỗi Copy", f"Không thể copy: {e}", parent=self.root)

    def _log_message(self, message, level="INFO", exc_info=False):
        if not hasattr(self, 'chat_area') or not self.chat_area.winfo_exists():
            print(f"[{level}] {message}")
            if exc_info:
                import traceback
                traceback.print_exc()
            return

        now = datetime.now().strftime("%H:%M:%S")
        tag = level.lower()
        if not hasattr(self, f"{tag}_tag_configured"):
            color_map = {"error": "red", "critical_error": "red", "warning": "orange", "success": "green",
                         "decrypted_msg": "blue", "incoming": "blue", "message": "blue", "status": "navy",
                         "file": "purple", "info": "black", "debug_verbose": "gray"}
            font_weight = "bold" if level in ["ERROR", "CRITICAL_ERROR", "SUCCESS", "DECRYPTED_MSG"] else "normal"
            font_config = ("Arial", 10, font_weight)
            try:
                self.chat_area.tag_config(tag, foreground=color_map.get(tag, "black"), font=font_config)
                setattr(self, f"{tag}_tag_configured", True)
            except tk.TclError as e:
                print(f"Warning: Could not configure tag '{tag}': {e}")

        formatted_message = f"[{now}] {message}\n"
        if level == "DECRYPTED_MSG": formatted_message = f"[{now}] {self.username if message.startswith(self.username + ':') else ''}{'GIẢI MÃ: ' if not message.startswith(self.username + ':') else ''}{message}\n"

        try:
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.insert(tk.END, formatted_message, tag)
            self.chat_area.config(state=tk.DISABLED)
            self.chat_area.see(tk.END)
        except tk.TclError as e:
            print(f"Error writing to chat area: {e}")

        if exc_info:
            import traceback
            tb_str = traceback.format_exc()
            try:
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.insert(tk.END, tb_str + "\n", "error")
                self.chat_area.config(state=tk.DISABLED)
                self.chat_area.see(tk.END)
            except tk.TclError:
                print(tb_str)

        if level in ["STATUS", "ERROR", "SUCCESS", "CRITICAL_ERROR", "WARNING"] or \
                any(s in message for s in ["Đang", "Connecting", "Sending", "Receiving", "Chờ", "Waiting"]):
            self.status_var.set(message.split('\n')[0])

    def _on_user_select(self, event):
        if not self.is_connected: return
        selection = self.user_listbox.curselection()
        if selection:
            selected_username = self.user_listbox.get(selection[0])
            is_self = (selected_username == self.username)
            can_enable_actions = self.is_connected and self.gpg and not is_self
            target_state = tk.NORMAL if can_enable_actions else tk.DISABLED

            self.recipient_username_entry.config(state=tk.NORMAL)
            self.recipient_username_entry.delete(0, tk.END)
            if not is_self:
                self.recipient_username_entry.insert(0, selected_username)
            else:
                self.recipient_username_entry.insert(0, self.username if self.username else "")
            self.recipient_username_entry.config(state=tk.DISABLED)

            for widget in [self.recipient_gpg_id_entry, self.message_entry, self.send_file_button,
                           self.send_message_button]:
                widget.config(state=target_state)

            if can_enable_actions:
                found_key_id = None
                for key_info in self.saved_recipient_keys:
                    if key_info.get("username") == selected_username:
                        found_key_id = key_info.get("key_id")
                        break
                self.recipient_gpg_id_entry.config(state=tk.NORMAL)
                self.recipient_gpg_id_entry.delete(0, tk.END)
                if found_key_id:
                    self.recipient_gpg_id_entry.insert(0, found_key_id)
                self.recipient_gpg_id_entry.config(
                    state=target_state if target_state == tk.NORMAL and found_key_id else tk.DISABLED)
            else:
                self.recipient_gpg_id_entry.config(state=tk.NORMAL)
                self.recipient_gpg_id_entry.delete(0, tk.END)
                self.recipient_gpg_id_entry.config(state=tk.DISABLED)
                self.message_entry.delete(0, tk.END)
        else:
            self._disable_action_widgets_for_self()

    def _toggle_connect(self):
        if not self.is_connected:
            host, port_str, username_val = (self.host_entry.get().strip(), self.port_entry.get().strip(),
                                            self.username_entry.get().strip())
            if not (host and port_str and username_val):
                messagebox.showerror("Thiếu thông tin", "Nhập Host, Port và Username.", parent=self.root)
                return
            if " " in username_val:
                messagebox.showerror("Username không hợp lệ", "Username không được chứa dấu cách.", parent=self.root)
                return
            try:
                port = int(port_str)
                assert 0 < port < 65536
            except (ValueError, AssertionError):
                messagebox.showerror("Port không hợp lệ", "Port phải là số từ 1-65535.", parent=self.root)
                return
            self.username = username_val
            self._log_message(f"Đang kết nối tới {host}:{port} với username {self.username}...", "STATUS")
            self.connect_button.config(state=tk.DISABLED)
            threading.Thread(target=self._connect_worker, args=(host, port, self.username), daemon=True).start()
        else:
            self._log_message("Đang ngắt kết nối...", "STATUS")
            self._disconnect_worker()

    def _connect_worker(self, host, port, username_to_register):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((host, port))
            self.client_socket.settimeout(None)
            register_payload = json.dumps({"type": "register", "username": username_to_register})
            self.client_socket.sendall(register_payload.encode('utf-8'))
            self.client_socket.settimeout(10.0)
            response_raw = self.client_socket.recv(BUFFER_SIZE)
            self.client_socket.settimeout(None)
            if not response_raw: raise ConnectionAbortedError("Server không phản hồi đăng ký.")
            response = json.loads(response_raw.decode('utf-8'))
            if response.get("type") == "register_ack" and response.get("status") == "success":
                self.is_connected = True
                self.message_queue.put({"gui_action": "connect_success", "message": response.get("message")})
                self.receiver_thread = threading.Thread(target=self._receiver_worker, daemon=True,
                                                        name="ClientReceiverThread")
                self.receiver_thread.start()
            else:
                self.message_queue.put(
                    {"gui_action": "connect_fail", "message": response.get("message", "Đăng ký thất bại.")})
                self._safe_close_socket()
        except (socket.timeout, ConnectionRefusedError, ConnectionAbortedError, json.JSONDecodeError) as e:
            self.message_queue.put({"gui_action": "connect_fail", "message": f"Lỗi kết nối: {e}"})
            self._safe_close_socket()
        except Exception as e:
            self.message_queue.put({"gui_action": "connect_fail", "message": f"Lỗi kết nối khác: {e}"})
            self._safe_close_socket()
        finally:
            if not self.is_connected:
                self.message_queue.put({"gui_action": "reenable_connect_button_if_needed"})

    def _safe_close_socket(self):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass
            try:
                self.client_socket.close()
            except Exception:
                pass
        self.client_socket = None

    def _disconnect_worker(self):
        if self.is_connected: self._log_message("Đang ngắt kết nối...", "STATUS")
        self.is_connected = False
        self._safe_close_socket()
        self.message_queue.put({"gui_action": "disconnect_cleanup"})

    def _receiver_worker(self):
        active_buffer = b""
        file_op_details = None

        while self.is_connected and self.client_socket:
            try:
                if file_op_details:
                    bytes_to_read = min(BUFFER_SIZE, file_op_details['total_size'] - file_op_details['bytes_received'])
                    if bytes_to_read <= 0:
                        self._complete_file_reception(file_op_details)
                        file_op_details = None
                        active_buffer = b""
                        continue

                    self.client_socket.settimeout(60.0)
                    chunk = self.client_socket.recv(bytes_to_read)
                    self.client_socket.settimeout(None)

                    if not chunk:
                        self._log_message(f"Kết nối bị ngắt khi đang nhận file {file_op_details['filename']}.", "ERROR")
                        if file_op_details.get('file_handle') and not file_op_details['file_handle'].closed:
                            file_op_details['file_handle'].close()
                        if file_op_details.get('temp_path') and os.path.exists(file_op_details['temp_path']):
                            try:
                                os.remove(file_op_details['temp_path'])
                            except OSError:
                                pass
                        self._update_history_entry_status_by_encrypted_path(file_op_details.get('temp_path'),
                                                                            "Lỗi: Mất kết nối khi nhận")
                        file_op_details = None
                        self.message_queue.put(
                            {"server_event": "connection_lost", "message": "Mất kết nối khi nhận file."})
                        break

                    file_op_details['file_handle'].write(chunk)
                    file_op_details['bytes_received'] += len(chunk)

                    total, received = file_op_details.get("total_size", 0), file_op_details["bytes_received"]
                    prog_msg = f"Đang nhận '{os.path.basename(file_op_details['filename'])}': "
                    prog_msg += f"{received / 1024:.1f}KB / {total / 1024:.1f}KB ({(received / total) * 100 if total > 0 else 0 :.1f}%)"
                    self.status_var.set(prog_msg)

                    if file_op_details['bytes_received'] >= file_op_details['total_size']:
                        self._complete_file_reception(file_op_details)
                        file_op_details = None
                        active_buffer = b""
                    continue

                self.client_socket.settimeout(None)
                data_chunk = self.client_socket.recv(BUFFER_SIZE)
                if not data_chunk:
                    if self.is_connected:
                        self.message_queue.put({"server_event": "connection_lost", "message": "Mất kết nối (EOF)."})
                    break

                active_buffer += data_chunk

                while active_buffer:
                    message_str, remaining_buffer = self._extract_next_json_from_buffer(active_buffer)

                    if message_str:
                        active_buffer = remaining_buffer
                        try:
                            parsed_message = json.loads(message_str)
                            if parsed_message.get("type") == "file_chunk_stream_start":
                                if file_op_details:
                                    self._log_message(
                                        f"Lỗi logic: Nhận file_chunk_stream_start trong khi đang xử lý file khác: {file_op_details['filename']}",
                                        "ERROR")
                                    if file_op_details.get('file_handle') and not file_op_details['file_handle'].closed:
                                        file_op_details['file_handle'].close()
                                    if file_op_details.get('temp_path') and os.path.exists(
                                            file_op_details['temp_path']):
                                        try:
                                            os.remove(file_op_details['temp_path'])
                                        except OSError:
                                            pass

                                fname = parsed_message.get("filename",
                                                           f"unknown_file_{datetime.now().strftime('%Y%m%d%H%M%S')}.gpg")
                                sender = parsed_message.get("sender", "ẩn danh")
                                fsize = parsed_message.get("file_size", 0)

                                if fsize <= 0:
                                    self._log_message(
                                        f"Nhận thông báo file '{fname}' từ {sender} với kích thước không hợp lệ: {fsize}.",
                                        "ERROR")
                                    continue

                                tmp_path = os.path.join(DOWNLOAD_DIR,
                                                        f"enc_recv_{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{os.path.basename(fname)}")

                                try:
                                    if not os.path.exists(DOWNLOAD_DIR): os.makedirs(DOWNLOAD_DIR)
                                    current_file_handle = open(tmp_path, 'wb')

                                    file_op_details = {
                                        'filename': fname,
                                        'original_sender': sender,
                                        'total_size': fsize,
                                        'bytes_received': 0,
                                        'temp_path': tmp_path,
                                        'file_handle': current_file_handle
                                    }
                                    self._log_message(
                                        f"Bắt đầu nhận file '{fname}' ({fsize} bytes) từ {sender}. Lưu tạm tại: {tmp_path}",
                                        "FILE")
                                    self._add_history_entry(
                                        type="file", direction="received", partner=sender,
                                        details=fname,
                                        status="Đang nhận...",
                                        encrypted_path=tmp_path
                                    )
                                except Exception as e_open_tmp:
                                    self._log_message(f"Không thể mở file tạm '{tmp_path}' để nhận: {e_open_tmp}",
                                                      "ERROR")
                                    file_op_details = None
                                    self._update_history_entry_status_by_details(direction="received", partner=sender,
                                                                                 details_match=fname,
                                                                                 new_status=f"Lỗi mở file tạm: {e_open_tmp}",
                                                                                 is_file=True)
                                continue

                            else:
                                self.message_queue.put({"server_event": "json_message", "payload": parsed_message})

                        except json.JSONDecodeError:
                            self._log_message(f"Lỗi giải mã JSON nội bộ sau khi trích xuất: '{message_str[:200]}'",
                                              "CRITICAL_ERROR")
                            active_buffer = b""
                            break
                    else:
                        if len(active_buffer) > BUFFER_SIZE * 5:
                            self._log_message(
                                f"Buffer nhận quá lớn ({len(active_buffer)} bytes) mà không có JSON hoàn chỉnh. Có thể có lỗi streaming. Đang xóa buffer.",
                                "ERROR")
                            active_buffer = b""
                        break

            except socket.timeout:
                if file_op_details:
                    self._log_message(
                        f"Timeout khi đang nhận file {file_op_details['filename']}. Đã nhận {file_op_details['bytes_received']}/{file_op_details['total_size']}.",
                        "WARNING")
                continue
            except ConnectionResetError:
                self.message_queue.put({"server_event": "connection_lost", "message": "Server đã reset kết nối."})
                break
            except ConnectionAbortedError:
                self.message_queue.put(
                    {"server_event": "connection_lost", "message": "Kết nối đã bị hủy bởi phần mềm."})
                break
            except OSError as e_sock:
                if self.is_connected:
                    self.message_queue.put({"server_event": "connection_lost", "message": f"Lỗi socket: {e_sock}"})
                break
            except Exception as e_recv_loop:
                if self.is_connected:
                    self._log_message(f"Lỗi nghiêm trọng trong luồng nhận: {e_recv_loop}", "CRITICAL_ERROR",
                                      exc_info=True)
                    self.message_queue.put({"server_event": "receive_error", "message": f"Lỗi nhận: {e_recv_loop}"})
                break

        if file_op_details:
            self._log_message(f"Luồng nhận dừng khi đang xử lý file {file_op_details['filename']}. Dọn dẹp.", "WARNING")
            if file_op_details.get('file_handle') and not file_op_details['file_handle'].closed:
                file_op_details['file_handle'].close()
            if file_op_details.get('temp_path') and os.path.exists(file_op_details['temp_path']):
                self._update_history_entry_status_by_encrypted_path(file_op_details.get('temp_path'),
                                                                    "Lỗi: Luồng nhận dừng")

        if self.is_connected:
            self.message_queue.put({"server_event": "connection_lost", "message": "Luồng nhận đã dừng hoạt động."})
        logging.info("Receiver worker thread finished.")

    def _extract_next_json_from_buffer(self, current_buffer, json_end_idx=None):
        if not current_buffer:
            return None, current_buffer

        try:
            first_brace_idx = current_buffer.find(b'{')
            if first_brace_idx == -1:
                return None, current_buffer

            if first_brace_idx > 0:
                self._log_message(
                    f"Dữ liệu rác ({first_brace_idx} bytes) được tìm thấy trước JSON object trong buffer.",
                    "WARNING")

            search_buffer = current_buffer[first_brace_idx:]
            open_braces = 0
            in_string = False
            escape_next = False

            for i, byte_val in enumerate(search_buffer):
                try:
                    char = bytes([byte_val]).decode('utf-8')
                except UnicodeDecodeError:
                    return None, current_buffer

                if escape_next:
                    escape_next = False
                    continue
                if char == '\\':
                    escape_next = True
                    continue

                if char == '"':
                    in_string = not in_string
                elif not in_string:
                    if char == '{':
                        open_braces += 1
                    elif char == '}':
                        open_braces -= 1
                        if open_braces == 0:
                            json_end_index = i + 1
                            json_candidate_bytes = search_buffer[:json_end_index]
                            try:
                                json_candidate_str = json_candidate_bytes.decode('utf-8')
                                json.loads(json_candidate_str)  # Validate JSON
                                return json_candidate_str, current_buffer[first_brace_idx + json_end_index:]
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                return None, current_buffer

            if len(current_buffer) > BUFFER_SIZE * 5:
                self._log_message(
                    f"Buffer nhận quá lớn ({len(current_buffer)} bytes) mà không có JSON hoàn chỉnh.",
                    "ERROR")
                return None, b""

            return None, current_buffer

        except Exception as e:
            self._log_message(f"Lỗi xử lý buffer: {e}", "ERROR")
            return None, current_buffer

    def _complete_file_reception(self, file_op_details):
        if not file_op_details:
            return

        filename = file_op_details['filename']
        temp_path = file_op_details['temp_path']
        original_sender = file_op_details['original_sender']

        try:
            if file_op_details.get('file_handle') and not file_op_details['file_handle'].closed:
                file_op_details['file_handle'].close()

            if not os.path.exists(temp_path):
                self._log_message(f"File tạm không tồn tại: {temp_path}", "ERROR")
                return

            file_size = os.path.getsize(temp_path)
            self._log_message(f"[LOG] Kích thước file mã hóa nhận được: {file_size} bytes", "DEBUG_VERBOSE")
            if file_size < 100:
                self._log_message(f"[CẢNH BÁO] File mã hóa nhận về quá nhỏ (<100 bytes), có thể bị lỗi khi truyền tải!", "WARNING")
                messagebox.showwarning("File nhận bất thường", f"File mã hóa nhận về quá nhỏ (<100 bytes), có thể bị lỗi khi truyền tải!\n\nĐường dẫn: {temp_path}", parent=self.root)

            if file_size == 0:
                self._log_message(f"File nhận được rỗng: {filename}", "ERROR")
                os.remove(temp_path)
                return

            self.status_var.set(f"File mã hóa '{os.path.basename(filename)}' đã nhận xong. Đang chuẩn bị giải mã...")
            self._log_message(
                f"Đã nhận đầy đủ file mã hóa: {filename} từ {original_sender}. Kích thước: {file_size}.",
                "FILE")
            self._update_history_entry_status_by_encrypted_path(temp_path, "Đã nhận (chờ giải mã)")

            if not self.gpg:
                self._log_message(f"Lỗi GPG: Không thể giải mã {filename}. File được lưu tại {temp_path}.", "ERROR")
                self._update_history_entry_status_by_encrypted_path(temp_path, "Lỗi GPG, không thể giải mã")
                return

            threading.Thread(target=self._decrypt_file_worker,
                             args=(temp_path, filename, original_sender),
                             daemon=True).start()

        except Exception as e_complete:
            self._log_message(f"Lỗi khi hoàn tất nhận file {filename}: {e_complete}", "ERROR")
            self._update_history_entry_status_by_encrypted_path(temp_path, f"Lỗi xử lý sau nhận: {e_complete}")

    def _process_message_queue(self):
        try:
            while True:
                msg = self.message_queue.get_nowait()
                gui_action = msg.get("gui_action")
                server_event = msg.get("server_event")
                worker_event = msg.get("worker_event")

                if gui_action:
                    self._handle_gui_action(gui_action, msg)
                elif server_event:
                    self._handle_server_event(server_event, msg)
                elif worker_event:
                    self._handle_worker_event(worker_event, msg)
        except queue.Empty:
            pass
        finally:
            if hasattr(self.root, 'winfo_exists') and self.root.winfo_exists():
                self.root.after(100, self._process_message_queue)

    def _handle_worker_event(self, event_type, msg_data):
        if event_type == "passphrase_result":
            request_id = msg_data.get("request_id")
            passphrase = msg_data.get("passphrase")
            cancelled = msg_data.get("cancelled", False)
            with self.passphrase_lock:
                if request_id in self.passphrase_requests:
                    req_info = self.passphrase_requests[request_id]
                    req_info['result'] = passphrase
                    req_info['cancelled'] = cancelled
                    req_info['event'].set()
                else:
                    self._log_message(f"Lỗi: Không tìm thấy yêu cầu passphrase ID {request_id}", "ERROR")

    def _request_passphrase_from_worker(self, purpose_message):
        request_id = str(uuid.uuid4())
        event = threading.Event()
        with self.passphrase_lock:
            self.passphrase_requests[request_id] = {'event': event, 'result': None, 'cancelled': False}
        self.message_queue.put({
            "gui_action": "request_passphrase", "request_id": request_id, "purpose": purpose_message
        })
        event.wait(timeout=300.0)
        with self.passphrase_lock:
            if request_id in self.passphrase_requests:
                result_info = self.passphrase_requests.pop(request_id)
                if not event.is_set():
                    return None, True
                return result_info['result'], result_info['cancelled']
            return None, True

    def _handle_gui_action(self, action, msg):
        if action == "request_passphrase":
            request_id = msg.get("request_id")
            purpose = msg.get("purpose", "Nhập passphrase:")
            passphrase = simpledialog.askstring("PGP Passphrase", purpose, parent=self.root, show='*')
            self.message_queue.put({
                "worker_event": "passphrase_result", "request_id": request_id,
                "passphrase": passphrase, "cancelled": passphrase is None
            })
            return

        elif action == "connect_success":
            self._log_message(msg.get("message", "Đã kết nối!"), "SUCCESS")
            self.connect_button.config(text="Ngắt Kết nối", state=tk.NORMAL)
            for widget in [self.host_entry, self.port_entry, self.username_entry]: widget.config(state=tk.DISABLED)
            if not self.gpg:
                self._log_message("GnuPG không khả dụng. Chức năng mã hóa/giải mã sẽ bị hạn chế.", "WARNING")
                self._disable_pgp_dependent_widgets()
            else:
                self._find_and_display_my_keys()
        elif action == "connect_fail":
            messagebox.showerror("Lỗi Kết nối", msg.get("message", "Kết nối thất bại."), parent=self.root)
            self._log_message(msg.get("message", "Kết nối thất bại."), "ERROR")
            for widget in [self.connect_button, self.host_entry, self.port_entry, self.username_entry]: widget.config(
                state=tk.NORMAL)
            self.connect_button.config(text="Kết nối")
            self.is_connected = False
        elif action == "disconnect_cleanup":
            self._log_message("Đã ngắt kết nối.", "STATUS")
            for widget in [self.connect_button, self.host_entry, self.port_entry, self.username_entry]: widget.config(
                state=tk.NORMAL)
            self.connect_button.config(text="Kết nối")
            self.user_listbox.delete(0, tk.END)
            self._disable_action_widgets_for_self()

            if self.pending_upload and self.pending_upload.get("encrypted_path") and os.path.exists(
                    self.pending_upload["encrypted_path"]):
                try:
                    os.remove(self.pending_upload["encrypted_path"])
                except OSError:
                    pass
            self.pending_upload = None
            self.is_connected = False
            self._update_history_user_filter()
        elif action == "reenable_connect_button_if_needed":
            if not self.is_connected:
                for widget in [self.connect_button, self.host_entry, self.port_entry,
                               self.username_entry]: widget.config(state=tk.NORMAL)
                self.connect_button.config(text="Kết nối")
        elif action == "update_status":
            self._log_message(msg.get("message", "Cập nhật trạng thái."), "STATUS")
        elif action == "update_status_only":
            self.status_var.set(msg.get("message", ""))
        elif action == "show_error":
            messagebox.showerror("Lỗi", msg.get("message", "Đã có lỗi xảy ra."), parent=self.root)
            self._log_message(msg.get("message", "Đã có lỗi xảy ra."), "ERROR")
        elif action == "show_info":
            messagebox.showinfo("Thông báo", msg.get("message", "Thông tin."), parent=self.root)
            self._log_message(msg.get("message", "Thông tin."), "INFO")
        elif action == "enable_button" and msg.get("button"):
            button = msg.get("button")
            if button and hasattr(button, 'winfo_exists') and button.winfo_exists(): button.config(state=tk.NORMAL)
        elif action == "clear_message_entry":
            self.message_entry.delete(0, tk.END)
        elif action == "log_decrypted_message":
            sender = msg.get('sender')
            content = msg.get('content')
            log_content = f"{sender}: {content}" if sender != self.username else f"{self.username}: {content}"
            self._log_message(log_content, "DECRYPTED_MSG")
        elif action == "update_history_display":
            self._update_history_display()
        elif action == "display_my_keys":
            priv_fp = msg.get("private_fingerprint", "Không tìm thấy khóa bí mật")
            pub_key_block = msg.get("public_key_block", "Không thể xuất public key")
            uid = msg.get("uid", "")
            self.my_private_key_var.set(priv_fp)
            self.my_public_key_text.config(state=tk.NORMAL)
            self.my_public_key_text.delete("1.0", tk.END)
            self.my_public_key_text.insert(tk.END, pub_key_block)
            self.my_public_key_text.config(state=tk.DISABLED)
            if priv_fp != "Không tìm thấy khóa bí mật" and uid:
                self._log_message(f"Khóa cá nhân được sử dụng: {uid} [{priv_fp}]", "INFO")
            elif priv_fp == "Không tìm thấy khóa bí mật":
                self._log_message("Không tìm thấy khóa bí mật cá nhân.", "WARNING")
        elif action == "refresh_recipient_keys_treeview":
            self._populate_recipient_keys_treeview()

    def _handle_server_event(self, event, msg, err_msg=None, msg_type=None):
        payload = msg.get("payload", {})
        if event == "json_message":
            msg_type = payload.get("type")
            if msg_type == "user_list":
                self._update_user_list(payload.get("users", []))
                self._update_history_user_filter()
            elif msg_type == "incoming_file_notification":
                self._log_message(
                    f"{payload.get('sender')} muốn gửi file '{payload.get('filename')}' (kích thước mã hóa: {payload.get('file_size', 0) / (1024 * 1024):.2f}MB).",
                    "INCOMING")
            elif msg_type == "proceed_with_file_upload":
                if self.pending_upload and self.pending_upload.get("recipient") == payload.get(
                        "recipient") and self.pending_upload.get("encrypted_filename_for_server") == payload.get(
                    "filename"):
                    self._log_message(
                        f"Server chấp nhận upload file '{payload.get('filename')}' tới {payload.get('recipient')}. Bắt đầu tải lên...",
                        "INFO")
                    self._proceed_with_actual_upload()
                else:
                    self._log_message("Lỗi: 'proceed_with_file_upload' không khớp hoặc không có file chờ tải lên.",
                                      "WARNING")
                    if self.pending_upload and self.pending_upload.get("encrypted_path") and os.path.exists(
                            self.pending_upload["encrypted_path"]):
                        try:
                            os.remove(self.pending_upload["encrypted_path"])
                        except OSError:
                            pass
                    self.pending_upload = None
                    if hasattr(self, 'send_file_button') and self.send_file_button.cget(
                            'state') == tk.DISABLED: self.send_file_button.config(state=tk.NORMAL)

            elif msg_type == "incoming_text":
                if not self.gpg:
                    self._log_message(f"Lỗi GPG: Không thể giải mã tin nhắn từ {payload.get('sender')}.", "ERROR")
                    return
                self._log_message(f"Nhận tin nhắn mã hóa từ {payload.get('sender')}. Đang chờ giải mã...", "MESSAGE")
                threading.Thread(target=self._decrypt_text_message_worker,
                                 args=(payload.get("content"), payload.get("sender")), daemon=True).start()

            elif msg_type == "error":
                err_msg = payload.get('message', 'Lỗi không xác định từ server.');
                self._log_message(f"Lỗi từ Server: {err_msg}", "ERROR");
                messagebox.showerror("Lỗi Server", err_msg, parent=self.root)
                if any(s in err_msg for s in ["Username already taken", "Invalid username"]) and not self.is_connected:
                    [w.config(state=tk.NORMAL) for w in
                     [self.connect_button, self.host_entry, self.port_entry, self.username_entry]];
                    self.connect_button.config(text="Kết nối")
            elif "Recipient" in err_msg and (
                    "not online" in err_msg or "does not exist" in err_msg or "not reachable" in err_msg or "went offline" in err_msg):
                if hasattr(self, 'send_file_button') and self.send_file_button.cget('state') == tk.DISABLED:
                    self.send_file_button.config(state=tk.NORMAL)
                if hasattr(self, 'send_message_button') and self.send_message_button.cget('state') == tk.DISABLED:
                    self.send_message_button.config(state=tk.NORMAL)


        elif msg_type == "file_sent_ack":
            ack_msg_text = payload.get('message', 'Đã xử lý.')
            self._log_message(f"Server Ack: {ack_msg_text}", "SUCCESS")
            recipient_acked = payload.get('recipient')
            original_filename_from_server_ack = payload.get('original_filename',
                                                            payload.get('filename', '').replace('.gpg', ''))

            self._update_history_entry_status_by_details(
                direction="sent", partner=recipient_acked,
                details_match=original_filename_from_server_ack,
                new_status="Đã gửi lên server (chờ chuyển tiếp)",
                is_file=True
            )
        elif msg_type == "file_fully_received_by_recipient":
            sender_of_file = payload.get('sender')
            filename_delivered = payload.get('filename')
            self._log_message(
                f"Xác nhận: File '{filename_delivered}' của bạn đã được giao thành công tới {sender_of_file}.",
                "SUCCESS")
            self._update_history_entry_status_by_details(
                direction="sent", partner=sender_of_file,
                details_match=filename_delivered,
                new_status="Đã giao cho người nhận",
                is_file=True
            )
        elif msg_type == "message_sent_ack":
            ack_msg_text_txt = payload.get('message', 'Đã xử lý.')
            self._log_message(f"Server Ack (tin nhắn): {ack_msg_text_txt}", "SUCCESS")
            recipient_acked_txt = payload.get('recipient')
            original_text_preview_from_ack = payload.get('original_text_preview')

            if original_text_preview_from_ack:
                self._update_history_entry_status_by_details(
                    direction="sent", partner=recipient_acked_txt,
                    details_match=original_text_preview_from_ack,
                    new_status="Đã gửi lên server (tin nhắn)",
                    is_file=False
                )
            else:
                self._log_message("Message ACK không có preview, không thể cập nhật history chính xác.", "WARNING")

        elif msg_type == "file_transfer_failed":
            reason = payload.get('reason', 'Không rõ lý do.')
            fn_failed = payload.get('filename', 'unknown_file.gpg').replace('.gpg', '')
            orig_sender_failed = payload.get('sender', 'unknown_sender')
            recipient_failed_on_server = payload.get('recipient', None)

            self._log_message(
                f"Server thông báo: Chuyển file '{fn_failed}' từ {orig_sender_failed} tới {recipient_failed_on_server or 'N/A'} thất bại: {reason}",
                "ERROR")
            messagebox.showerror("Lỗi Chuyển File Từ Server",
                                 f"Việc chuyển file '{fn_failed}' đã thất bại.\nLý do từ server: {reason}",
                                 parent=self.root)

            if self.username == orig_sender_failed:
                self._update_history_entry_status_by_details(
                    direction="sent", partner=recipient_failed_on_server if recipient_failed_on_server else "N/A",
                    details_match=fn_failed, new_status=f"Gửi thất bại (server): {reason}", is_file=True
                )
                if self.pending_upload and self.pending_upload.get("original_filename") == fn_failed:
                    path_del = self.pending_upload.get("encrypted_path")
                    self.pending_upload = None
                    if hasattr(self, 'send_file_button'): self.send_file_button.config(state=tk.NORMAL)
                    if path_del and os.path.exists(path_del):
                        try:
                            os.remove(path_del)
                        except OSError:
                            pass
            else:
                self._update_history_entry_status_by_details(
                    direction="received", partner=orig_sender_failed,
                    details_match=payload.get('filename', 'unknown_file.gpg'),
                    new_status=f"Nhận thất bại (server): {reason}", is_file=True
                )

        elif event == "connection_lost":
            if self.is_connected: messagebox.showwarning("Mất Kết Nối", msg.get("message", "Mất kết nối tới server."),
                                                         parent=self.root)
            self._log_message(msg.get("message", "Mất kết nối tới server."), "ERROR")
            self._disconnect_worker()

        elif event == "receive_error":
            messagebox.showerror("Lỗi Nhận Dữ Liệu", msg.get("message", "Lỗi khi nhận dữ liệu từ server."),
                                 parent=self.root)
            self._log_message(msg.get("message", "Lỗi khi nhận dữ liệu từ server."), "ERROR")
            if self.is_connected: self._disconnect_worker()

    def _decrypt_text_message_worker(self, encrypted_content, sender):
        if not self.gpg:
            self.message_queue.put({"gui_action": "show_error", "message": "GnuPG không khả dụng để giải mã tin nhắn."})
            return
        try:
            passphrase, cancelled = self._request_passphrase_from_worker(
                f"Nhập passphrase cho tin nhắn mã hóa từ {sender}:")
            if cancelled:
                self.message_queue.put({"gui_action": "update_status", "message": "Đã hủy giải mã tin nhắn."})
                return
            if passphrase is None and not cancelled:
                self.message_queue.put(
                    {"gui_action": "show_error", "message": "Không nhận được passphrase để giải mã."})
                return

            data = self.gpg.decrypt(encrypted_content, passphrase=passphrase)
            if data.ok:
                decrypted_text = data.data.decode('utf-8', 'replace')
                self.message_queue.put(
                    {"gui_action": "log_decrypted_message", "sender": sender, "content": decrypted_text})
                preview = decrypted_text[:100] + ("..." if len(decrypted_text) > 100 else "")
                self._add_history_entry(type="text", direction="received", partner=sender, details=preview,
                                        status="Đã giải mã",
                                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        _full_text_for_display=decrypted_text)
            else:
                self.message_queue.put(
                    {"gui_action": "show_error",
                     "message": f"Giải mã tin nhắn từ {sender} thất bại: {data.stderr or data.status}"})
        except Exception as e:
            self.message_queue.put({"gui_action": "show_error", "message": f"Lỗi ngoại lệ khi giải mã tin nhắn: {e}"})

    def _decrypt_file_worker(self, encrypted_path, original_filename, sender):
        try:
            if not os.path.exists(encrypted_path):
                self._log_message(f"File mã hóa không tồn tại: {encrypted_path}", "ERROR")
                self._update_history_entry_status_by_encrypted_path(encrypted_path, "Lỗi: File mã hóa không tồn tại")
                return

            # Log private key hiện có
            priv_keys = [k['fingerprint'] for k in self.gpg.list_keys(True)]
            self._log_message(f"[LOG] Private keys hiện có: {priv_keys}", "DEBUG_VERBOSE")

            # Lấy tên file đã giải mã (bỏ .gpg nếu có)
            if original_filename.lower().endswith('.gpg'):
                decrypted_filename = original_filename[:-4]
            else:
                decrypted_filename = original_filename + ".decrypted"
            decrypted_path = os.path.join(DOWNLOAD_DIR, decrypted_filename)
            base_path, ext = os.path.splitext(decrypted_path)
            counter = 1
            while os.path.exists(decrypted_path):
                decrypted_path = f"{base_path}_{counter}{ext}"
                counter += 1

            # Log kích thước file mã hóa trước khi giải mã
            try:
                enc_size = os.path.getsize(encrypted_path)
                self._log_message(f"[LOG] Kích thước file mã hóa trước khi giải mã: {enc_size} bytes", "DEBUG_VERBOSE")
            except Exception as e:
                self._log_message(f"[LOG] Không thể lấy kích thước file mã hóa: {e}", "WARNING")

            # Yêu cầu passphrase nếu cần
            passphrase = None
            need_passphrase = False
            for key in self.gpg.list_keys(True):
                if key.get('fingerprint') in priv_keys and key.get('fingerprint') in encrypted_path:
                    need_passphrase = True
                    break
            if need_passphrase:
                passphrase = self._request_passphrase_from_worker(f"Nhập passphrase để giải mã file từ {sender}:")[0]

            with open(encrypted_path, 'rb') as ef:
                try:
                    if passphrase:
                        decrypted_data = self.gpg.decrypt_file(ef, passphrase=passphrase)
                    else:
                        decrypted_data = self.gpg.decrypt_file(ef)
                    if not decrypted_data.ok:
                        error_msg = f"Lỗi giải mã: {decrypted_data.status}"
                        self._log_message(error_msg, "ERROR")
                        self._update_history_entry_status_by_encrypted_path(encrypted_path, error_msg)
                        return

                    with open(decrypted_path, 'wb') as df:
                        df.write(decrypted_data.data)

                    # Log kích thước file sau khi giải mã
                    try:
                        dec_size = os.path.getsize(decrypted_path)
                        self._log_message(f"[LOG] Kích thước file sau khi giải mã: {dec_size} bytes", "DEBUG_VERBOSE")
                    except Exception as e:
                        self._log_message(f"[LOG] Không thể lấy kích thước file sau giải mã: {e}", "WARNING")

                    self._log_message(
                        f"Đã giải mã thành công file từ {sender}: {decrypted_filename}",
                        "FILE")
                    self._update_history_entry_status_by_encrypted_path(
                        encrypted_path, "Đã giải mã thành công", decrypted_path)
                    self.root.after(0, self._show_decryption_success_notification, decrypted_path, decrypted_filename)

                except Exception as e_decrypt:
                    error_msg = f"Lỗi trong quá trình giải mã: {e_decrypt}"
                    self._log_message(error_msg, "ERROR")
                    self._update_history_entry_status_by_encrypted_path(encrypted_path, error_msg)

        except Exception as e:
            self._log_message(f"Lỗi xử lý file mã hóa {encrypted_path}: {e}", "ERROR")
            self._update_history_entry_status_by_encrypted_path(encrypted_path, f"Lỗi xử lý: {e}")
        # KHÔNG xóa file .gpg sau khi giải mã, để giữ lại file mã hóa gốc
        # finally:
        #     try:
        #         if os.path.exists(encrypted_path):
        #             os.remove(encrypted_path)
        #     except:
        #         pass

    def _send_file_action(self):
        if not self.is_connected:
            messagebox.showwarning("Chưa Kết Nối", "Vui lòng kết nối tới server trước khi gửi file.", parent=self.root)
            return
        if not self.gpg:
            messagebox.showerror("Lỗi GnuPG", "GnuPG không khả dụng. Không thể gửi file.", parent=self.root)
            return
        rec_user = self.recipient_username_entry.get().strip()
        rec_gpg_id = self.recipient_gpg_id_entry.get().strip()
        if not (rec_user and rec_gpg_id):
            messagebox.showerror("Thiếu Thông Tin",
                                 "Tên người nhận và GPG Key ID của người nhận là bắt buộc để gửi file.",
                                 parent=self.root)
            return

        fpath = filedialog.askopenfilename(title="Chọn File để Gửi", parent=self.root)
        if not fpath: return
        try:
            fsize = os.path.getsize(fpath)
            if fsize == 0: raise AssertionError("File rỗng, không thể gửi.")
            if fsize > MAX_FILE_SIZE_CLIENT: raise AssertionError(
                f"File quá lớn (tối đa {MAX_FILE_SIZE_CLIENT // (1024 * 1024)}MB).")
        except FileNotFoundError:
            messagebox.showerror("Lỗi File", f"Không tìm thấy file: {fpath}", parent=self.root)
            return
        except AssertionError as e_assert:
            messagebox.showerror("Lỗi File", str(e_assert), parent=self.root)
            return
        except OSError as e:
            messagebox.showerror("Lỗi File", f"Không thể truy cập file: {e}", parent=self.root)
            return

        self._log_message(
            f"Đang chuẩn bị file '{os.path.basename(fpath)}' để gửi tới {rec_user} (Key ID: {rec_gpg_id[:16]}...)",
            "STATUS")
        self.send_file_button.config(state=tk.DISABLED)
        threading.Thread(target=self._send_file_worker, args=(fpath, rec_user, rec_gpg_id), daemon=True).start()

    def _send_file_worker(self, file_to_send_path, recipient_user, recipient_gpg):
        enc_temp_fpath = None
        orig_basename = os.path.basename(file_to_send_path)
        timestamp_sent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log kích thước file gốc
        try:
            file_size = os.path.getsize(file_to_send_path)
            self._log_message(f"[LOG] Kích thước file gốc: {file_size} bytes", "DEBUG_VERBOSE")
        except Exception as e:
            self._log_message(f"[LOG] Không thể lấy kích thước file gốc: {e}", "WARNING")

        # Log fingerprint dùng để mã hóa
        self._log_message(f"[LOG] Mã hóa file cho recipient_gpg: {recipient_gpg}", "DEBUG_VERBOSE")

        self._add_history_entry(
            type="file", direction="sent", partner=recipient_user, details=orig_basename,
            status="Đang chuẩn bị...", timestamp=timestamp_sent, path=file_to_send_path
        )

        try:
            if not self.gpg: raise Exception("GnuPG không khả dụng.")
            self._update_history_entry_status_by_details(
                direction="sent", partner=recipient_user, details_match=orig_basename,
                new_status="Đang mã hóa...", is_file=True, timestamp_match=timestamp_sent)

            self.message_queue.put(
                {"gui_action": "update_status_only", "message": f"Đang mã hóa file '{orig_basename}'..."})
            enc_temp_fpath = os.path.join(TEMP_SEND_DIR,
                                          f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{orig_basename}.gpg")
            with open(file_to_send_path, 'rb') as f_in:
                status = self.gpg.encrypt_file(f_in, recipients=[recipient_gpg], output=enc_temp_fpath,
                                               always_trust=True)

            # Log kích thước file mã hóa
            if os.path.exists(enc_temp_fpath):
                enc_size = os.path.getsize(enc_temp_fpath)
                self._log_message(f"[LOG] Kích thước file mã hóa: {enc_size} bytes", "DEBUG_VERBOSE")
            else:
                self._log_message(f"[LOG] File mã hóa không tồn tại sau khi mã hóa!", "ERROR")

            if not status.ok or not os.path.exists(enc_temp_fpath) or os.path.getsize(enc_temp_fpath) == 0:
                gpg_error_details = f"GPG stderr: {status.stderr}. GPG status: {status.status}"
                self._log_message(f"Lỗi mã hóa PGP cho file: {gpg_error_details}", "ERROR")
                raise Exception(f"Lỗi Mã hóa PGP: {status.stderr or status.status or 'Output file mã hóa rỗng.'}")

            enc_fsize = os.path.getsize(enc_temp_fpath)
            fname_for_server = os.path.basename(enc_temp_fpath)

            req_payload = json.dumps(
                {"type": "file_transfer_request",
                 "recipient": recipient_user,
                 "filename": fname_for_server,
                 "file_size": enc_fsize,
                 "original_filename": orig_basename
                 })

            if not self.client_socket or not self.is_connected: raise ConnectionError("Mất kết nối tới server.")

            self._update_history_entry_status_by_details(
                direction="sent", partner=recipient_user, details_match=orig_basename,
                new_status="Đang gửi yêu cầu tới server...", is_file=True, timestamp_match=timestamp_sent)

            self.client_socket.sendall(req_payload.encode('utf-8'))
            self.message_queue.put({"gui_action": "update_status",
                                    "message": f"Đã gửi yêu cầu cho file '{orig_basename}'. Đang chờ server chấp nhận..."})

            self.pending_upload = {
                "encrypted_path": enc_temp_fpath,
                "encrypted_filename_for_server": fname_for_server,
                "recipient": recipient_user,
                "button_to_reenable": self.send_file_button,
                "original_filename": orig_basename,
                "timestamp_sent": timestamp_sent
            }
        except Exception as e:
            self.message_queue.put({"gui_action": "show_error", "message": f"Lỗi chuẩn bị gửi file: {e}"})
            self.message_queue.put({"gui_action": "enable_button", "button": self.send_file_button})
            self._update_history_entry_status_by_details(
                direction="sent", partner=recipient_user, details_match=orig_basename,
                new_status=f"Lỗi chuẩn bị: {str(e)[:50]}", is_file=True, timestamp_match=timestamp_sent)
            if enc_temp_fpath and os.path.exists(enc_temp_fpath):
                try:
                    os.remove(enc_temp_fpath)
                except OSError:
                    pass
            self.pending_upload = None

    def _send_message_action(self):
        if not self.is_connected:
            messagebox.showwarning("Chưa Kết Nối", "Vui lòng kết nối tới server trước khi gửi tin nhắn.",
                                   parent=self.root)
            return
        if not self.gpg:
            messagebox.showerror("Lỗi GnuPG", "GnuPG không khả dụng. Không thể gửi tin nhắn.", parent=self.root)
            return
        rec_user = self.recipient_username_entry.get().strip()
        rec_gpg_id = self.recipient_gpg_id_entry.get().strip()
        msg_text = self.message_entry.get().strip()
        if not (rec_user and rec_gpg_id and msg_text):
            messagebox.showerror("Thiếu Thông Tin",
                                 "Tên người nhận, GPG Key ID người nhận, và nội dung tin nhắn là bắt buộc.",
                                 parent=self.root)
            return

        self._log_message(f"Đang chuẩn bị tin nhắn cho {rec_user}...", "STATUS")
        self.send_message_button.config(state=tk.DISABLED)
        threading.Thread(target=self._send_message_worker, args=(msg_text, rec_user, rec_gpg_id), daemon=True).start()

    def _send_message_worker(self, text_content, rec_user, rec_gpg):
        timestamp_sent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        preview = text_content[:100] + ("..." if len(text_content) > 100 else "")

        self._add_history_entry(
            type="text", direction="sent", partner=rec_user, details=preview,
            status="Đang mã hóa...", timestamp=timestamp_sent, _full_text_for_display=text_content
        )

        try:
            if not self.gpg: raise Exception("GnuPG không khả dụng.")
            self.message_queue.put({"gui_action": "update_status_only", "message": "Đang mã hóa tin nhắn..."})
            enc_msg = self.gpg.encrypt(text_content.encode('utf-8'), recipients=[rec_gpg], always_trust=True)

            if not enc_msg.ok:
                gpg_error_details = f"GPG stderr: {enc_msg.stderr}. GPG status: {enc_msg.status}"
                self._log_message(f"Lỗi mã hóa PGP cho tin nhắn: {gpg_error_details}", "ERROR")
                self._update_history_entry_status_by_details(
                    direction="sent", partner=rec_user, details_match=preview,
                    new_status=f"Lỗi mã hóa: {enc_msg.stderr or enc_msg.status}",
                    is_file=False, timestamp_match=timestamp_sent)
                raise Exception(f"Lỗi Mã hóa PGP: {enc_msg.stderr or enc_msg.status}")

            req_payload = json.dumps({"type": "text_message",
                                      "recipient": rec_user,
                                      "content": str(enc_msg),
                                      "original_text_preview": preview})
            if not self.client_socket or not self.is_connected: raise ConnectionError("Mất kết nối tới server.")
            self.client_socket.sendall(req_payload.encode('utf-8'))

            self.message_queue.put(
                {"gui_action": "update_status", "message": f"Đã gửi tin nhắn mã hóa tới {rec_user}."})
            self.message_queue.put({"gui_action": "clear_message_entry"})
            self._update_history_entry_status_by_details(
                direction="sent", partner=rec_user, details_match=preview,
                new_status="Đã gửi (chờ ACK server)", is_file=False, timestamp_match=timestamp_sent
            )
        except Exception as e:
            self.message_queue.put({"gui_action": "show_error", "message": f"Lỗi gửi tin nhắn: {e}"})
            self._update_history_entry_status_by_details(
                direction="sent", partner=rec_user, details_match=preview,
                new_status=f"Lỗi gửi: {str(e)[:50]}", is_file=False, timestamp_match=timestamp_sent)
        finally:
            self.message_queue.put({"gui_action": "enable_button", "button": self.send_message_button})

    def _proceed_with_actual_upload(self):
        if not self.pending_upload:
            self._log_message("Không có file nào đang chờ tải lên để xử lý.", "WARNING")
            if hasattr(self, 'send_file_button'): self.send_file_button.config(state=tk.NORMAL)
            return
        upload_info = self.pending_upload
        threading.Thread(target=self._actual_upload_worker, args=(upload_info,), daemon=True).start()

    def _actual_upload_worker(self, upload_info_arg):
        if not upload_info_arg or not isinstance(upload_info_arg, dict):
            self.message_queue.put(
                {"gui_action": "show_error", "message": "Lỗi tải lên nội bộ: thông tin upload không hợp lệ."})
            return

        enc_f_path = upload_info_arg.get("encrypted_path")
        fname_on_server = upload_info_arg.get("encrypted_filename_for_server")
        btn_to_reenable = upload_info_arg.get("button_to_reenable")
        upload_recipient = upload_info_arg.get("recipient")
        original_filename = upload_info_arg.get("original_filename")
        timestamp_sent = upload_info_arg.get("timestamp_sent")

        if not enc_f_path or not fname_on_server:
            self.message_queue.put({"gui_action": "show_error", "message": "Lỗi tải lên: Thiếu chi tiết file."})
            return

        bytes_sent, upload_ok = 0, False

        try:
            self._update_history_entry_status_by_details(
                direction="sent", partner=upload_recipient, details_match=original_filename,
                new_status="Đang tải lên server...", is_file=True, timestamp_match=timestamp_sent
            )
            self.message_queue.put(
                {"gui_action": "update_status_only", "message": f"Đang tải lên file '{original_filename}'..."})
            if not self.client_socket or not self.is_connected: raise ConnectionError(
                "Mất kết nối tới server khi đang tải lên.")
            if not os.path.exists(enc_f_path): raise FileNotFoundError(
                f"File mã hóa tạm thời {enc_f_path} không tìm thấy để tải lên.")
            f_total_size = os.path.getsize(enc_f_path)

            with open(enc_f_path, 'rb') as f_send:
                while True:
                    chunk = f_send.read(BUFFER_SIZE)
                    if not chunk: break
                    self.client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                    if f_total_size > 0 and (bytes_sent == f_total_size or (bytes_sent % (BUFFER_SIZE * 20) == 0)):
                        self.message_queue.put({"gui_action": "update_status_only",
                                                "message": f"Đang tải lên '{original_filename}': {(bytes_sent / f_total_size) * 100:.1f}%"})
            if bytes_sent == f_total_size:
                self.message_queue.put({"gui_action": "update_status",
                                        "message": f"Đã tải lên hoàn tất file '{original_filename}' lên server."})
                upload_ok = True
            else:
                raise Exception(f"Tải lên không hoàn tất. Đã gửi {bytes_sent}/{f_total_size} bytes.")
        except (FileNotFoundError, ConnectionError) as e:
            self.message_queue.put({"gui_action": "show_error", "message": str(e)})
        except Exception as e:
            self.message_queue.put(
                {"gui_action": "show_error", "message": f"Lỗi khi tải file '{original_filename}' lên server: {e}"})
        finally:
            new_hist_status = "Lỗi tải lên server"
            if upload_ok: new_hist_status = "Chờ server xác nhận chuyển tiếp..."

            self._update_history_entry_status_by_details(
                direction="sent", partner=upload_recipient, details_match=original_filename,
                new_status=new_hist_status, is_file=True, timestamp_match=timestamp_sent
            )

            if enc_f_path and os.path.exists(enc_f_path):
                try:
                    os.remove(enc_f_path)
                except OSError as e_remove:
                    self._log_message(f"Không thể xóa file mã hóa tạm {enc_f_path} sau khi tải lên: {e_remove}",
                                      "WARNING")

            if btn_to_reenable: self.message_queue.put({"gui_action": "enable_button", "button": btn_to_reenable})

            if self.pending_upload and self.pending_upload.get("encrypted_path") == enc_f_path:
                self.pending_upload = None

    def _disable_pgp_dependent_widgets(self):
        """Vô hiệu hóa các widget phụ thuộc vào GPG"""
        for widget in [self.generate_key_button, self.copy_my_public_key_button]:
            widget.configure(state="disabled")
        self.my_private_key_var.set("Chưa có khóa / GPG lỗi")
        self.my_public_key_text.configure(state="normal")
        self.my_public_key_text.delete(1.0, tk.END)
        self.my_public_key_text.configure(state="disabled")

    def _on_closing(self):
        do_close = True
        if self.is_connected:
            if not messagebox.askokcancel("Thoát Ứng Dụng", "Bạn có chắc muốn ngắt kết nối và thoát?",
                                          parent=self.root):
                do_close = False
        if do_close:
            if self.is_connected: self._disconnect_worker()
            self._save_history()
            self._save_saved_recipient_keys()
            self._cleanup_temp_files()
            self.root.destroy()

    def _cleanup_temp_files(self):
        """Xóa an toàn các file tạm"""
        for dir_path in [DOWNLOAD_DIR, TEMP_SEND_DIR]:
            if os.path.exists(dir_path):
                try:
                    for file in os.listdir(dir_path):
                        file_path = os.path.join(dir_path, file)
                        try:
                            if os.path.isfile(file_path):
                                os.unlink(file_path)
                        except Exception as e:
                            print(f"Lỗi khi xóa file {file_path}: {e}")
                except Exception as e:
                    print(f"Lỗi khi xóa thư mục {dir_path}: {e}")

    def _check_gpg_status(self, silent=False):
        if not self.gpg:
            msg = "GnuPG chưa được khởi tạo hoặc không tìm thấy."
            if not silent:
                messagebox.showerror("Lỗi GnuPG", msg, parent=self.root)
            self._log_message("Kiểm tra GPG: Chưa khởi tạo.", "ERROR")
            return

        try:
            version = self.gpg.version()
            if not version:
                msg = "Không thể xác định phiên bản GPG"
                if not silent:
                    messagebox.showwarning("Cảnh báo GnuPG", msg, parent=self.root)
                self._log_message(msg, "WARNING")
                return

            # Kiểm tra danh sách khóa
            public_keys = self.gpg.list_keys()
            secret_keys = self.gpg.list_keys(True)

            msg = f"GnuPG hoạt động tốt.\n\n" \
                  f"Phiên bản: {version}\n" \
                  f"Số khóa công khai: {len(public_keys)}\n" \
                  f"Số khóa bí mật: {len(secret_keys)}"

            if public_keys:
                msg += "\n\nDanh sách khóa công khai:"
                for key in public_keys:
                    msg += f"\n- {key.get('fingerprint', 'Unknown')}"

            if secret_keys:
                msg += "\n\nDanh sách khóa bí mật:"
                for key in secret_keys:
                    msg += f"\n- {key.get('fingerprint', 'Unknown')}"

            if not silent:
                messagebox.showinfo("Trạng thái GnuPG", msg, parent=self.root)
            self._log_message(
                f"Kiểm tra GPG thành công: {len(secret_keys)} khóa bí mật, {len(public_keys)} khóa công khai", "INFO")

        except Exception as e:
            msg = f"Lỗi khi kiểm tra GPG: {e}"
            if not silent:
                messagebox.showerror("Lỗi GnuPG", msg, parent=self.root)
            self._log_message(msg, "ERROR")

    def _show_generate_key_dialog(self):
        if not self.gpg:
            messagebox.showerror("Lỗi GnuPG", "GnuPG chưa sẵn sàng để tạo khóa.", parent=self.root)
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Tạo Cặp Khóa PGP Mới")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(expand=True, fill="both")
        ttk.Label(frame, text="Tên Thật:").grid(row=0, column=0, sticky="w", pady=2)
        name_entry = ttk.Entry(frame, width=40)
        name_entry.grid(row=0, column=1, pady=2)
        ttk.Label(frame, text="Email:").grid(row=1, column=0, sticky="w", pady=2)
        email_entry = ttk.Entry(frame, width=40)
        email_entry.grid(row=1, column=1, pady=2)
        ttk.Label(frame, text="Passphrase:").grid(row=2, column=0, sticky="w", pady=2)
        passphrase_entry = ttk.Entry(frame, width=40, show="*")
        passphrase_entry.grid(row=2, column=1, pady=2)
        ttk.Label(frame, text="Xác nhận Passphrase:").grid(row=3, column=0, sticky="w", pady=2)
        passphrase_confirm_entry = ttk.Entry(frame, width=40, show="*")
        passphrase_confirm_entry.grid(row=3, column=1, pady=2)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        def on_generate():
            name, email, pw1, pw2 = name_entry.get().strip(), email_entry.get().strip(), passphrase_entry.get(), passphrase_confirm_entry.get()
            if not (name and email and pw1 and pw2):
                messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đủ Tên, Email, và Passphrase.", parent=dialog)
                return
            if pw1 != pw2:
                messagebox.showerror("Lỗi Passphrase", "Passphrase và xác nhận passphrase không khớp.", parent=dialog)
                return
            if '@' not in email or '.' not in email.split('@')[-1]:
                messagebox.showerror("Email Không Hợp Lệ", "Vui lòng nhập địa chỉ email hợp lệ.", parent=dialog)
                return
            gen_button.config(state=tk.DISABLED)
            cancel_button.config(state=tk.DISABLED)
            dialog.title("Đang tạo khóa...")
            self._log_message(f"Bắt đầu quá trình tạo khóa cho {name} <{email}>...", "STATUS")
            threading.Thread(target=self._generate_key_worker, args=(name, email, pw1, dialog), daemon=True).start()

        gen_button = ttk.Button(button_frame, text="Tạo Khóa", command=on_generate)
        gen_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Hủy Bỏ", command=dialog.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)
        dialog.wait_window()

    def _generate_key_worker(self, name, email, passphrase, dialog_to_close):
        try:
            if not self.gpg: raise Exception("GnuPG không khả dụng.")
            input_data = self.gpg.gen_key_input(name_real=name, name_email=email, passphrase=passphrase, key_type="RSA",
                                                key_length=3072)
            self.message_queue.put(
                {"gui_action": "update_status_only",
                 "message": "Đang tạo khóa PGP (quá trình này có thể mất vài phút)..."})
            key = self.gpg.gen_key(input_data)
            if key and key.fingerprint:
                fp = key.fingerprint
                uid = f"{name} <{email}>"
                public_key_block = self.gpg.export_keys(fp)
                if public_key_block:
                    success_msg = f"Tạo cặp khóa PGP thành công!\nFingerprint: {fp}\nUserID: {uid}"
                    self.message_queue.put({"gui_action": "show_info", "message": success_msg})
                    self.message_queue.put({"gui_action": "update_status", "message": "Tạo cặp khóa PGP thành công."})
                    self.message_queue.put({"gui_action": "display_my_keys", "private_fingerprint": fp,
                                            "public_key_block": public_key_block, "uid": uid})
                else:
                    self.message_queue.put({"gui_action": "show_error",
                                            "message": f"Tạo khóa thành công (Fingerprint: {fp}) nhưng không thể xuất public key."})
            else:
                error_detail = getattr(key, 'stderr', getattr(key, 'status', 'Không tạo được khóa. Kiểm tra log GPG.'))
                self.message_queue.put(
                    {"gui_action": "show_error", "message": f"Tạo khóa PGP thất bại: {error_detail}"})
        except Exception as e:
            self.message_queue.put({"gui_action": "show_error", "message": f"Lỗi ngoại lệ khi tạo khóa PGP: {e}"})
        finally:
            if dialog_to_close and dialog_to_close.winfo_exists(): self.root.after(0, dialog_to_close.destroy)

    def _find_and_display_my_keys(self):
        if not self.gpg:
            self.message_queue.put({"gui_action": "display_my_keys", "private_fingerprint": "GPG không khả dụng",
                                    "public_key_block": "GPG không khả dụng", "uid": ""})
            return
        try:
            private_keys = self.gpg.list_keys(True)
            if private_keys:
                first_key = private_keys[0]
                fp = first_key['fingerprint']
                uid = first_key['uids'][0] if first_key['uids'] else 'N/A'
                public_key_block = self.gpg.export_keys(fp)
                if not public_key_block: public_key_block = "Không thể xuất public key."
                self.message_queue.put(
                    {"gui_action": "display_my_keys", "private_fingerprint": fp, "public_key_block": public_key_block,
                     "uid": uid})
            else:
                self.message_queue.put(
                    {"gui_action": "display_my_keys", "private_fingerprint": "Không tìm thấy khóa bí mật nào",
                     "public_key_block": "", "uid": ""})
        except Exception as e:
            self._log_message(f"Lỗi khi tìm khóa cá nhân: {e}", "ERROR")
            self.message_queue.put({"gui_action": "display_my_keys", "private_fingerprint": "Lỗi tìm khóa",
                                    "public_key_block": "Lỗi tìm khóa", "uid": ""})

    def _copy_my_public_key_to_clipboard(self):
        if not self.gpg:
            messagebox.showerror("Lỗi GnuPG", "GnuPG chưa sẵn sàng.", parent=self.root)
            return
        public_key_content = self.my_public_key_text.get("1.0", tk.END).strip()
        if public_key_content and public_key_content not in ["GPG không khả dụng", "Không thể xuất public key.",
                                                             "Lỗi tìm khóa"]:
            try:
                pyperclip.copy(public_key_content)
                self._log_message("Public key của bạn đã được sao chép vào clipboard.", "SUCCESS")
                messagebox.showinfo("Đã Sao Chép", "Public key của bạn đã được sao chép vào clipboard.",
                                    parent=self.root)
            except Exception as e:
                self._log_message(f"Lỗi khi sao chép public key: {e}", "ERROR")
                messagebox.showerror("Lỗi Sao Chép",
                                     f"Không thể sao chép public key: {e}\nHãy thử sao chép thủ công từ ô hiển thị.",
                                     parent=self.root)
        else:
            messagebox.showwarning("Không có Public Key",
                                   "Không có public key để sao chép. Hãy tạo hoặc chọn khóa trước.",
                                   parent=self.root)

    def _load_history(self):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    self.history = json.load(f)
                    if not isinstance(self.history, list):
                        self.history = []
                    if len(self.history) > 200:
                        self.history = self.history[:200]
            else:
                self.history = []
        except Exception as e:
            self._log_message(f"Lỗi khi tải lịch sử: {e}", "ERROR")
            self.history = []

    def _show_add_recipient_key_dialog(self):
        if not self.gpg:
            messagebox.showerror("Lỗi GnuPG", "GnuPG chưa sẵn sàng để thêm key.", parent=self.root)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Thêm Public Key")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        username_frame = ttk.Frame(main_frame)
        username_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(username_frame, text="Tên người dùng:").pack(side=tk.LEFT)
        username_entry = ttk.Entry(username_frame)
        username_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        key_frame = ttk.Frame(main_frame)
        key_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(key_frame, text="Public Key (ASCII Armor):").pack(anchor=tk.W)
        key_text = scrolledtext.ScrolledText(key_frame, wrap=tk.WORD, height=10)
        key_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))

        def validate_and_add():
            try:
                username = username_entry.get().strip()
                key_data = key_text.get("1.0", tk.END).strip()

                if not username or not key_data:
                    messagebox.showerror("Lỗi", "Vui lòng điền đầy đủ thông tin.", parent=dialog)
                    return

                import_result = self.gpg.import_keys(key_data)
                if import_result.count == 1:
                    key_id = import_result.fingerprints[0]

                    # Kiểm tra xem key đã tồn tại chưa
                    if any(k.get("key_id") == key_id for k in self.saved_recipient_keys):
                        messagebox.showerror(
                            "Lỗi",
                            f"Public key này đã được thêm trước đó.",
                            parent=dialog
                        )
                        return

                    self.saved_recipient_keys.append({
                        "username": username,
                        "key_id": key_id,
                        "key_data_preview": key_data[:100] + "..."
                    })
                    self._save_saved_recipient_keys()
                    self.message_queue.put({"gui_action": "refresh_recipient_keys_treeview"})
                    self._log_message(
                        f"Đã thêm và import public key cho {username} (ID: {key_id[:16]}...).",
                        "SUCCESS"
                    )
                    messagebox.showinfo(
                        "Thành Công",
                        f"Đã thêm public key cho {username}.",
                        parent=dialog
                    )
                    dialog.destroy()
            except Exception as e:
                messagebox.showerror(
                    "Lỗi",
                    f"Lỗi khi xử lý public key: {e}",
                    parent=dialog
                )

        ttk.Button(
            button_frame,
            text="Thêm",
            command=validate_and_add
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            button_frame,
            text="Hủy",
            command=dialog.destroy
        ).pack(side=tk.LEFT)

    def _on_recipient_key_select(self, event=None):
        selected_items = self.recipient_keys_tree.selection()
        if selected_items:
            self.remove_recipient_key_button.config(state=tk.NORMAL)
            item_id = selected_items[0]
            item_details = self.recipient_keys_tree.item(item_id, 'values')
            if item_details and len(item_details) > 1:
                username_from_key_list = item_details[0]
                key_id_from_key_list = item_details[1]

                current_selected_online_user = self.recipient_username_entry.get()

                if self.recipient_username_entry.cget(
                        'state') == tk.DISABLED and current_selected_online_user == username_from_key_list:
                    self.recipient_gpg_id_entry.config(state=tk.NORMAL)
                    self.recipient_gpg_id_entry.delete(0, tk.END)
                    self.recipient_gpg_id_entry.insert(0, key_id_from_key_list)
                    if not (self.username == current_selected_online_user) and self.is_connected and self.gpg:
                        for widget in [self.message_entry, self.send_file_button, self.send_message_button]:
                            widget.config(state=tk.NORMAL)
                    else:  # Is self or not connected/gpg
                        self.recipient_gpg_id_entry.config(state=tk.DISABLED)
                        for widget in [self.message_entry, self.send_file_button, self.send_message_button]:
                            widget.config(state=tk.DISABLED)

                elif self.recipient_username_entry.cget('state') != tk.DISABLED or not current_selected_online_user:
                    self.recipient_username_entry.config(state=tk.NORMAL)
                    self.recipient_username_entry.delete(0, tk.END)
                    self.recipient_username_entry.insert(0, username_from_key_list)
                    self.recipient_username_entry.config(state=tk.DISABLED)

                    self.recipient_gpg_id_entry.config(state=tk.NORMAL)
                    self.recipient_gpg_id_entry.delete(0, tk.END)
                    self.recipient_gpg_id_entry.insert(0, key_id_from_key_list)

                    if not (self.username == username_from_key_list) and self.is_connected and self.gpg:
                        for widget in [self.message_entry, self.send_file_button, self.send_message_button]:
                            widget.config(state=tk.NORMAL)
                    else:  # Is self or not connected/gpg
                        self.recipient_gpg_id_entry.config(state=tk.DISABLED)
                        for widget in [self.message_entry, self.send_file_button, self.send_message_button]:
                            widget.config(state=tk.DISABLED)
        else:
            self.remove_recipient_key_button.config(state=tk.DISABLED)

    def _load_saved_recipient_keys(self):
        try:
            if os.path.exists(SAVED_RECIPIENTS_FILE):
                with open(SAVED_RECIPIENTS_FILE, 'r', encoding='utf-8') as f:
                    self.saved_recipient_keys = json.load(f)
            else:
                self.saved_recipient_keys = []
        except Exception as e:
            self._log_message(f"Lỗi khi đọc danh sách public key đã lưu: {e}", "ERROR", exc_info=True)
            self.saved_recipient_keys = []

    def _save_saved_recipient_keys(self):
        try:
            temp_file = f"{SAVED_RECIPIENTS_FILE}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.saved_recipient_keys, f, indent=4, ensure_ascii=False)
            if os.path.exists(SAVED_RECIPIENTS_FILE):
                os.replace(temp_file, SAVED_RECIPIENTS_FILE)
            else:
                os.rename(temp_file, SAVED_RECIPIENTS_FILE)
        except Exception as e:
            print(f"Warning: Không thể lưu danh sách public key vào '{SAVED_RECIPIENTS_FILE}': {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass

    def _save_history(self):
        try:
            if len(self.history) > 200:
                self.history = self.history[:200]

            temp_file = f"{HISTORY_FILE}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=4, ensure_ascii=False)

            if os.path.exists(HISTORY_FILE):
                os.replace(temp_file, HISTORY_FILE)
            else:
                os.rename(temp_file, HISTORY_FILE)

        except (IOError, Exception) as e:
            print(f"Warning: Không thể lưu lịch sử vào '{HISTORY_FILE}': {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass

    def _add_history_entry(self, type, direction, partner, details, status, timestamp=None, path=None,
                           encrypted_path=None, _full_text_for_display=None):
        if timestamp is None: timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"timestamp": timestamp, "type": type, "direction": direction, "partner": partner, "details": details,
                 "status": status}
        if path: entry["path"] = path
        if encrypted_path: entry["encrypted_path"] = encrypted_path
        if _full_text_for_display and type == "text": entry["_full_text_for_display"] = _full_text_for_display
        self.history.insert(0, entry)
        self._save_history()
        self.message_queue.put({"gui_action": "update_history_display"})

    def _update_history_entry_status_by_encrypted_path(self, encrypted_path_to_find, new_status, decrypted_path=None):
        found = False
        if not encrypted_path_to_find: return  # Tránh lỗi nếu path rỗng
        for entry in self.history:
            if entry.get("type") == "file" and entry.get("direction") == "received" and entry.get(
                    "encrypted_path") == encrypted_path_to_find:
                entry["status"] = new_status
                if decrypted_path: entry["path"] = decrypted_path
                found = True
                break
        if found:
            self._save_history()
            self.message_queue.put({"gui_action": "update_history_display"})

    def _update_history_entry_status_by_details(self, direction, partner, details_match, new_status, is_file,
                                                timestamp_match=None):
        found_entry = None
        target_type = "file" if is_file else "text"
        for entry in self.history:
            if entry.get("direction") == direction and entry.get("partner") == partner and \
                    entry.get("details") == details_match and entry.get("type") == target_type:
                if timestamp_match and entry.get("timestamp") == timestamp_match:
                    found_entry = entry
                    break
                elif not timestamp_match and found_entry is None:  # Ưu tiên entry mới nhất nếu không có timestamp_match
                    found_entry = entry
        if found_entry:
            found_entry["status"] = new_status
            self._save_history()
            self.message_queue.put({"gui_action": "update_history_display"})

    def _update_history_display(self, filter_user=None):
        if not hasattr(self, 'history_tree') or not self.history_tree.winfo_exists():
            return

        self.history_tree.delete(*self.history_tree.get_children())
        current_filter = filter_user if filter_user else self.history_user_filter_var.get()

        if current_filter == "Tất cả người dùng":
            filtered_history = self.history
        else:
            filtered_history = [entry for entry in self.history if entry.get("partner") == current_filter]

        for entry in filtered_history:
            self.history_tree.insert('', tk.END, values=(
                entry.get("timestamp", ""),
                entry.get("type", "N/A"),
                entry.get("direction", "N/A"),
                entry.get("partner", "N/A"),
                entry.get("details", "N/A"),
                entry.get("status", "N/A"),
                entry.get("path", "") if entry.get("type") == "file" else ""
            ))

        self._update_history_user_filter()

    def _update_history_user_filter(self):
        if not hasattr(self, 'history_user_filter_combo'):
            return

        users = {"Tất cả người dùng"}
        users.update(entry.get("partner", "N/A") for entry in self.history if entry.get("partner"))

        sorted_users = sorted(list(users), key=lambda x: (x == "Tất cả người dùng", x.lower()))

        current_val = self.history_user_filter_var.get()
        self.history_user_filter_combo['values'] = sorted_users

        if current_val not in sorted_users:
            self.history_user_filter_var.set(sorted_users[0] if sorted_users else "")

    def _on_history_user_filter_change(self, event=None):
        self._update_history_display()

    def _on_history_item_double_click(self, event):
        if not hasattr(self, 'history_tree'): return
        selected_item_iid = self.history_tree.focus()
        if not selected_item_iid: return
        item_values_tuple = self.history_tree.item(selected_item_iid, 'values')
        if not item_values_tuple or len(item_values_tuple) < 7: return

        item_values = list(item_values_tuple)  # Chuyển tuple sang list để dễ truy cập
        timestamp, item_type, direction, partner, details, status, path_val = item_values[0], item_values[1], \
        item_values[
            2], item_values[3], item_values[4], item_values[5], item_values[6]

        found_entry = None
        for entry in self.history:
            if entry.get("timestamp") == timestamp and entry.get("type") == item_type and \
                    entry.get("direction") == direction and entry.get("partner") == partner and \
                    str(entry.get("details", "")) == details:
                found_entry = entry
                break

        if not found_entry:
            self._log_message("Không tìm thấy thông tin chi tiết cho mục lịch sử này trong dữ liệu.", "WARNING")
            return

        if item_type == "file":
            encrypted_path = found_entry.get("encrypted_path")
            decrypted_path_from_history = found_entry.get(
                "path") if direction == "received" and status == "Đã giải mã" else None

            if status == "Đã giải mã" and decrypted_path_from_history and os.path.exists(decrypted_path_from_history):
                try:
                    folder = os.path.dirname(decrypted_path_from_history)
                    if os.path.exists(folder):
                        if os.name == 'nt':
                            os.startfile(folder)
                        elif sys.platform == 'darwin':
                            subprocess.Popen(['open', folder])
                        else:
                            subprocess.Popen(['xdg-open', folder])
                        self._log_message(f"Đã mở thư mục chứa file: {folder}", "INFO")
                except Exception as e_open_folder:
                    messagebox.showerror("Lỗi Mở Thư Mục", f"Không thể mở thư mục chứa file: {e_open_folder}",
                                         parent=self.root)
            elif direction == "received" and encrypted_path and os.path.exists(
                    encrypted_path) and status != "Đã giải mã":
                if not self.gpg:
                    messagebox.showerror("Lỗi GnuPG", "GnuPG không khả dụng để thử giải mã lại.", parent=self.root)
                    return
                self._log_message(f"Thử giải mã lại file: {details} từ {partner}", "INFO")
                threading.Thread(target=self._decrypt_file_worker,
                                 args=(encrypted_path, details, partner),  # details ở đây là tên file mã hóa
                                 daemon=True).start()
            elif (direction == "received" and (
                    not encrypted_path or not os.path.exists(encrypted_path)) and status != "Đã giải mã") or \
                    (direction == "sent" and not os.path.exists(found_entry.get("path", "")) and status not in [
                        "Đã giao cho người nhận", "Đã gửi lên server (chờ chuyển tiếp)"]):

                missing_file_path = encrypted_path if direction == "received" else found_entry.get("path", "")
                messagebox.showwarning("Không Tìm Thấy File",
                                       f"File gốc hoặc file mã hóa không còn tồn tại tại đường dẫn:\n{missing_file_path}",
                                       parent=self.root)
                if direction == "received":
                    self._update_history_entry_status_by_encrypted_path(encrypted_path, "File mã hóa bị mất")
                else:  # Sent file
                    self._update_history_entry_status_by_details(direction="sent", partner=partner,
                                                                 details_match=details, new_status="File gốc bị mất",
                                                                 is_file=True, timestamp_match=timestamp)

        elif item_type == "text":
            full_text_content = found_entry.get("_full_text_for_display", details)
            messagebox.showinfo(f"Nội dung tin nhắn ({direction} {'tới' if direction == 'sent' else 'từ'} {partner})",
                                full_text_content, parent=self.root)

    def _update_user_list(self, users_list):
        if not hasattr(self, 'user_listbox'): return
        sel_indices = self.user_listbox.curselection()
        sel_user = self.user_listbox.get(sel_indices[0]) if sel_indices else None

        self.user_listbox.delete(0, tk.END)
        users = sorted(users_list)
        for user in users: self.user_listbox.insert(tk.END, user)

        if sel_user and sel_user in users:
            try:
                idx = users.index(sel_user)
                self.user_listbox.selection_set(idx)
                self.user_listbox.activate(idx)
                self.user_listbox.see(idx)
            except (ValueError, tk.TclError):
                pass
        elif not users:
            self._disable_action_widgets_for_self()

    def _remove_selected_recipient_key(self):
        selected_items = self.recipient_keys_tree.selection()
        if not selected_items:
            messagebox.showwarning("Chưa chọn key", "Hãy chọn một key từ danh sách để xóa.", parent=self.root)
            return
        item_id_to_remove = selected_items[0]
        item_details = self.recipient_keys_tree.item(item_id_to_remove, 'values')
        username_to_remove = item_details[0]
        key_id_to_remove = item_details[1]
        if messagebox.askyesno("Xác nhận Xóa Key",
                               f"Bạn có chắc muốn xóa public key đã lưu của '{username_to_remove}' (ID: {key_id_to_remove[:16]}...)?\nLưu ý: Key sẽ không bị xóa khỏi GPG keyring của bạn, chỉ xóa khỏi danh sách quản lý này.",
                               parent=self.root):
            original_length = len(self.saved_recipient_keys)
            self.saved_recipient_keys = [entry for entry in self.saved_recipient_keys if
                                         entry.get("key_id") != key_id_to_remove]
            if len(self.saved_recipient_keys) < original_length:
                self._save_saved_recipient_keys()
                self.message_queue.put({"gui_action": "refresh_recipient_keys_treeview"})
                self._log_message(
                    f"Đã xóa public key của {username_to_remove} (ID: {key_id_to_remove[:16]}...) khỏi danh sách quản lý.",
                    "INFO")
            else:
                self._log_message(f"Không tìm thấy key ID {key_id_to_remove} trong danh sách đã lưu để xóa.", "WARNING")

    def _disable_action_widgets_for_self(self):
        for entry_widget in [self.recipient_username_entry, self.recipient_gpg_id_entry, self.message_entry]:
            entry_widget.config(state=tk.NORMAL)
            entry_widget.delete(0, tk.END)
        if self.username: self.recipient_username_entry.insert(0, self.username)
        for widget in [self.recipient_username_entry, self.recipient_gpg_id_entry, self.message_entry,
                       self.send_file_button, self.send_message_button]:
            widget.config(state=tk.DISABLED)

    def _show_decryption_success_notification(self, decrypted_path, original_filename):
        notification_window = tk.Toplevel(self.root)
        notification_window.title("Giải mã thành công")
        notification_window.geometry("420x180")
        notification_window.transient(self.root)

        frame = ttk.Frame(notification_window, padding="20")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=f"File '{original_filename}' đã được giải mã thành công!", wraplength=380).pack(pady=(0, 10))
        ttk.Label(frame, text=f"Lưu tại: {decrypted_path}", wraplength=380).pack(pady=(0, 20))

        def open_file():
            try:
                if os.name == 'nt':
                    os.startfile(decrypted_path)
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', decrypted_path])
                else:
                    subprocess.Popen(['xdg-open', decrypted_path])
            except Exception as e:
                messagebox.showerror("Lỗi Mở File", f"Không thể mở file: {e}", parent=notification_window)
            notification_window.destroy()

        def open_folder():
            try:
                folder = os.path.dirname(decrypted_path)
                if os.name == 'nt':
                    os.startfile(folder)
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', folder])
                else:
                    subprocess.Popen(['xdg-open', folder])
            except Exception as e:
                messagebox.showerror("Lỗi Mở Thư Mục", f"Không thể mở thư mục: {e}", parent=notification_window)
            notification_window.destroy()

        def view_file():
            import os
            import mimetypes
            from tkinter import Toplevel, Text, Scrollbar, Canvas, NW, Listbox, END
            try:
                mime_type, _ = mimetypes.guess_type(decrypted_path)
                ext = os.path.splitext(decrypted_path)[-1].lower()
                if mime_type and mime_type.startswith('text'):
                    # Hiển thị file text
                    view_win = Toplevel(self.root)
                    view_win.title(f"Xem file: {os.path.basename(decrypted_path)}")
                    view_win.geometry("700x500")
                    txt = Text(view_win, wrap=tk.WORD)
                    txt.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
                    sb = Scrollbar(view_win, command=txt.yview)
                    sb.pack(side=tk.RIGHT, fill=tk.Y)
                    txt.config(yscrollcommand=sb.set)
                    with open(decrypted_path, 'r', encoding='utf-8', errors='replace') as f:
                        txt.insert(tk.END, f.read())
                    txt.config(state=tk.DISABLED)
                elif mime_type and mime_type.startswith('image'):
                    # Hiển thị file ảnh
                    from PIL import Image, ImageTk
                    img_win = Toplevel(self.root)
                    img_win.title(f"Xem ảnh: {os.path.basename(decrypted_path)}")
                    img = Image.open(decrypted_path)
                    canvas = Canvas(img_win, width=img.width, height=img.height)
                    canvas.pack()
                    tk_img = ImageTk.PhotoImage(img)
                    canvas.create_image(0, 0, anchor=NW, image=tk_img)
                    canvas.image = tk_img
                elif ext == '.pdf':
                    try:
                        import fitz  # PyMuPDF
                        pdf_win = Toplevel(self.root)
                        pdf_win.title(f"Xem PDF: {os.path.basename(decrypted_path)}")
                        doc = fitz.open(decrypted_path)
                        page = doc.load_page(0)
                        pix = page.get_pixmap()
                        from PIL import Image, ImageTk
                        import io
                        img = Image.open(io.BytesIO(pix.tobytes()))
                        canvas = Canvas(pdf_win, width=img.width, height=img.height)
                        canvas.pack()
                        tk_img = ImageTk.PhotoImage(img)
                        canvas.create_image(0, 0, anchor=NW, image=tk_img)
                        canvas.image = tk_img
                    except Exception as e:
                        messagebox.showerror("Lỗi xem PDF", f"Không thể xem PDF: {e}", parent=notification_window)
                elif ext in ['.zip', '.rar', '.7z']:
                    archive_win = Toplevel(self.root)
                    archive_win.title(f"Nội dung file nén: {os.path.basename(decrypted_path)}")
                    archive_win.geometry("500x400")
                    lb = Listbox(archive_win)
                    lb.pack(fill=tk.BOTH, expand=True)
                    try:
                        if ext == '.zip':
                            import zipfile
                            with zipfile.ZipFile(decrypted_path, 'r') as zf:
                                for name in zf.namelist():
                                    lb.insert(END, name)
                        elif ext == '.rar':
                            import rarfile
                            with rarfile.RarFile(decrypted_path, 'r') as rf:
                                for name in rf.namelist():
                                    lb.insert(END, name)
                        elif ext == '.7z':
                            import py7zr
                            with py7zr.SevenZipFile(decrypted_path, 'r') as zf:
                                for name in zf.getnames():
                                    lb.insert(END, name)
                    except Exception as e:
                        messagebox.showerror("Lỗi đọc file nén", f"Không thể đọc file nén: {e}", parent=notification_window)
                else:
                    messagebox.showinfo("Không hỗ trợ xem trực tiếp", f"Không hỗ trợ xem trực tiếp file này: {mime_type or ext}", parent=notification_window)
            except Exception as e:
                messagebox.showerror("Lỗi Xem File", f"Không thể xem file: {e}", parent=notification_window)

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(button_frame, text="Mở File", command=open_file).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Mở Thư Mục", command=open_folder).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Xem File", command=view_file).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Đóng", command=notification_window.destroy).pack(side="right", padx=5)

        notification_window.focus_set()

    def _populate_recipient_keys_treeview(self):
        if not hasattr(self, 'recipient_keys_tree'): return
        self.recipient_keys_tree.delete(*self.recipient_keys_tree.get_children())
        for entry in self.saved_recipient_keys:
            username = entry.get("username", "N/A")
            key_id = entry.get("key_id", "N/A")
            self.recipient_keys_tree.insert("", tk.END, values=(username, key_id))

    def _decrypt_gpg_file_dialog(self):
        import mimetypes
        import os
        file_path = filedialog.askopenfilename(
            title="Chọn file .gpg để giải mã",
            filetypes=[("GPG files", "*.gpg"), ("All files", "*.*")],
            parent=self.root)
        if not file_path:
            return

        # Kiểm tra có private key không
        if not self.gpg:
            messagebox.showerror("Lỗi GPG", "GnuPG không khả dụng.", parent=self.root)
            return
        if not self.gpg.list_keys(True):
            messagebox.showerror("Không có private key", "Bạn chưa có private key nào trong keyring để giải mã.", parent=self.root)
            return

        # Chọn nơi lưu file giải mã
        orig_name = os.path.basename(file_path)
        if orig_name.lower().endswith('.gpg'):
            out_name = orig_name[:-4]
        else:
            out_name = orig_name + ".decrypted"
        out_path = filedialog.asksaveasfilename(
            title="Lưu file đã giải mã thành...",
            initialfile=out_name,
            defaultextension="",
            parent=self.root)
        if not out_path:
            return

        # Thực hiện giải mã
        try:
            with open(file_path, 'rb') as f_in:
                result = self.gpg.decrypt_file(f_in, output=out_path)
            if result.ok:
                messagebox.showinfo("Thành công", f"Đã giải mã thành công file: {out_path}", parent=self.root)
                if messagebox.askyesno("Mở file", "Bạn có muốn mở file vừa giải mã bằng phần mềm mặc định không?", parent=self.root):
                    try:
                        if os.name == 'nt':
                            os.startfile(out_path)
                        elif sys.platform == 'darwin':
                            subprocess.Popen(['open', out_path])
                        else:
                            subprocess.Popen(['xdg-open', out_path])
                    except Exception as e:
                        messagebox.showerror("Lỗi mở file", f"Không thể mở file: {e}", parent=self.root)
            else:
                messagebox.showerror(
                    "Lỗi giải mã",
                    f"Giải mã thất bại: {result.stderr or result.status}\n\nCó thể file không đúng định dạng, không đúng key, hoặc không phải file mã hóa PGP.",
                    parent=self.root)
        except Exception as e:
            messagebox.showerror("Lỗi ngoại lệ", f"Lỗi khi giải mã: {e}", parent=self.root)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(threadName)s - %(filename)s:%(lineno)d - %(message)s')
    try:
        pyperclip.paste()
    except pyperclip.PyperclipException as e:
        root_check = tk.Tk()
        root_check.withdraw()
        messagebox.showerror("Lỗi Thiếu Thư Viện Pyperclip",
                             f"Không thể khởi chạy pyperclip (dùng để copy/paste).\nLỗi: {e}\n"
                             "Hãy cài đặt một chương trình copy/paste vào clipboard mà pyperclip hỗ trợ (ví dụ: xclip hoặc xsel trên Linux, hoặc cài đặt pyperclip đúng cách trên Windows/Mac).\n"
                             "Ứng dụng sẽ thoát.")
        sys.exit(1)
    root = tk.Tk()
    app = PGPClientGUI(root)
    root.mainloop()