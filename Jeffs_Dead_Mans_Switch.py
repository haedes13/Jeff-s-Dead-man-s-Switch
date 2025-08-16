# Save as buskill_secure.py
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading, wmi, pythoncom, os, time, ctypes, json, hashlib, keyboard, sys, signal
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

KEY_SIZE = 32
SALT_SIZE = 16
CHUNK_SIZE = 64 * 1024
DEVICE_VID = "16C0"
DEVICE_PID = "27DB"
STATE_FILE = os.path.expandvars(r"%PROGRAMDATA%\buskill_state.json")

encryption_targets = []
password = None
armed = False
hotkey_registered = False
armed_close_protection = False
window = None
password_entry = None
shutdown_on_removal = None  # tk.BooleanVar assigned in setup_gui()

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump({
                "armed": armed,
                "password_hash": hash_password(password) if password else "",
                "targets": encryption_targets
            }, f)
    except Exception as e:
        print("Failed to save state:", e)

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return None

def derive_key(pwd, salt):
    return PBKDF2(pwd.encode(), salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(infile, outfile, pwd):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(pwd, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    with open(infile, 'rb') as fi, open(outfile, 'wb') as fo:
        fo.write(salt + nonce)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            fo.write(cipher.encrypt(chunk))
        fo.write(cipher.digest())

def encrypt_folder(folder, pwd):
    aes_files = []
    for root, _, files in os.walk(folder):
        for fn in files:
            path = os.path.join(root, fn)
            if not path.endswith('.aes'):
                ep = path + ".aes"
                encrypt_file(path, ep, pwd)
                os.remove(path)
                aes_files.append(ep)
    return aes_files

def encrypt_all_targets():
    new_t = []
    for p in encryption_targets:
        try:
            if os.path.isfile(p):
                ep = p + ".aes"
                encrypt_file(p, ep, password)
                os.remove(p)
                new_t.append(ep)
            elif os.path.isdir(p):
                new_t.extend(encrypt_folder(p, password))
        except Exception as e:
            print(f"[Encryption Error] {p}: {e}")
    encryption_targets.clear()
    encryption_targets.extend(new_t)
    update_file_list()

def decrypt_file(infile, outfile, pwd):
    with open(infile, 'rb') as fi:
        salt = fi.read(SALT_SIZE)
        nonce = fi.read(16)
        ciphertext = fi.read()
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        key = derive_key(pwd, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        with open(outfile, 'wb') as fo:
            fo.write(cipher.decrypt_and_verify(ciphertext, tag))

def decrypt_all_targets(pwd):
    originals = []
    for p in encryption_targets[:]:
        try:
            if os.path.isfile(p) and p.endswith('.aes'):
                out = p[:-4]
                decrypt_file(p, out, pwd)
                os.remove(p)
                originals.append(out)
        except Exception as e:
            print(f"[Decryption Error] {p}: {e}")
    encryption_targets.clear()
    encryption_targets.extend(originals)
    update_file_list()

def is_device_connected():
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for usb in c.Win32_PnPEntity():
            if usb.PNPDeviceID and DEVICE_VID in usb.PNPDeviceID and DEVICE_PID in usb.PNPDeviceID:
                return True
    finally:
        pythoncom.CoUninitialize()
    return False

def lock_pc():
    ctypes.windll.user32.LockWorkStation()

def shutdown_pc():
    os.system("shutdown /s /t 0")

def keep_lock_loop():
    while not is_device_connected():
        lock_pc()
        time.sleep(1)

def monitor_usb():
    global armed
    while armed:
        if not is_device_connected():
            if shutdown_on_removal.get():
                shutdown_pc()
            else:
                lock_pc()
                if encryption_targets and password:
                    threading.Thread(target=encrypt_all_targets, daemon=True).start()
                threading.Thread(target=keep_lock_loop, daemon=True).start()
            while not is_device_connected():
                time.sleep(1)
        time.sleep(1)

def require_password_before_exit():
    if armed:
        messagebox.showwarning("Denied", "You must disarm before exiting.")
        return
    if not armed_close_protection:
        window.destroy()
        return
    attempt = simpledialog.askstring("Exit Password", "Enter password to exit:", show="*")
    if attempt and hash_password(attempt) == hash_password(password):
        unregister_hotkey()
        window.destroy()
        sys.exit(0)
    else:
        messagebox.showerror("Wrong Password", "Cannot close without correct password.")

def activate_close_protection():
    global armed_close_protection
    armed_close_protection = True
    signal.signal(signal.SIGINT, lambda *_: require_password_before_exit())
    signal.signal(signal.SIGTERM, lambda *_: require_password_before_exit())
    window.protocol("WM_DELETE_WINDOW", require_password_before_exit)
    window.bind("<Alt-F4>", lambda e: "break")

def deactivate_close_protection():
    global armed_close_protection
    armed_close_protection = False
    window.protocol("WM_DELETE_WINDOW", window.destroy)
    window.unbind("<Alt-F4>")
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

def toggle_gui():
    if window.state() == "withdrawn":
        window.deiconify()
    else:
        window.withdraw()

def register_hotkey():
    global hotkey_registered
    if not hotkey_registered:
        keyboard.add_hotkey("ctrl+alt+b", toggle_gui)
        hotkey_registered = True

def unregister_hotkey():
    global hotkey_registered
    if hotkey_registered:
        keyboard.remove_hotkey("ctrl+alt+b")
        hotkey_registered = False

def arm():
    global armed, password
    pwd = password_entry.get()
    if not pwd:
        messagebox.showerror("Missing Password", "Enter password before arming.")
        return
    if not is_device_connected():
        messagebox.showerror("Device Not Connected", "Device is not connected.")
        return
    password = pwd
    armed = True
    save_state()
    password_entry.delete(0, tk.END)
    arm_button.config(state="disabled")
    disarm_button.config(state="normal")
    status_label.config(text="BusKill is ARMED")
    window.config(bg="#ff3333")
    window.withdraw()
    register_hotkey()
    activate_close_protection()
    threading.Thread(target=monitor_usb, daemon=True).start()

def disarm():
    global armed
    entered = password_entry.get()
    if not is_device_connected():
        messagebox.showerror("USB Not Connected", "Insert device to disarm.")
        return
    if not entered:
        messagebox.showerror("Missing Password", "Enter password to disarm.")
        return
    if hash_password(entered) != hash_password(password):
        messagebox.showerror("Incorrect Password", "Incorrect password.")
        return
    try:
        if encryption_targets:
            decrypt_all_targets(entered)
            messagebox.showinfo("Decryption", "Files decrypted.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return
    password_entry.delete(0, tk.END)
    arm_button.config(state="normal")
    disarm_button.config(state="disabled")
    status_label.config(text="BusKill is DISARMED")
    window.config(bg="#339999")
    armed = False
    save_state()
    deactivate_close_protection()
    unregister_hotkey()

def add_files():
    fs = filedialog.askopenfilenames(title="Select Files")
    for f in fs:
        if f not in encryption_targets:
            encryption_targets.append(f)
    update_file_list()

def add_folder():
    fd = filedialog.askdirectory(title="Select Folder")
    if fd and fd not in encryption_targets:
        encryption_targets.append(fd)
    update_file_list()

def remove_selected():
    sel = list(file_listbox.curselection())
    for i in reversed(sel):
        del encryption_targets[i]
    update_file_list()

def update_file_list():
    file_listbox.delete(0, tk.END)
    for p in encryption_targets:
        file_listbox.insert(tk.END, p)

def hide_console():
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

def setup_gui():
    global window, password_entry, arm_button, disarm_button, status_label, file_listbox, shutdown_on_removal

    window = tk.Tk()
    window.title("BusKill Secure Encryptor")
    window.geometry("600x550")
    window.config(bg="#3399ff")
    window.attributes("-topmost", True)

    shutdown_on_removal = tk.BooleanVar(value=False)

    status_label = tk.Label(window, text="BusKill is DISARMED", fg="white", bg=window["bg"], font=("Arial", 14))
    status_label.pack(pady=10)
    tk.Label(window, text="Password:", bg=window["bg"], fg="white", font=("Arial", 12)).pack()
    password_entry = tk.Entry(window, show="*", font=("Arial",12), width=30)
    password_entry.pack(pady=5)

    cb = tk.Checkbutton(window, text="Shutdown on USB Removal", variable=shutdown_on_removal,
                        bg=window["bg"], fg="white", selectcolor="#3399ff", font=("Arial", 10),
                        activebackground=window["bg"], activeforeground="white")
    cb.pack(pady=5)

    bf = tk.Frame(window, bg=window["bg"])
    bf.pack(pady=5)
    tk.Button(bf, text="Add File", command=add_files).grid(row=0, column=0, padx=5)
    tk.Button(bf, text="Add Folder", command=add_folder).grid(row=0, column=1, padx=5)
    tk.Button(bf, text="Remove Selected", command=remove_selected).grid(row=0, column=2, padx=5)

    file_listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, width=70, height=10)
    file_listbox.pack(pady=10)

    arm_button = tk.Button(window, text="Arm", command=arm, bg="#007bff", fg="white", width=20, height=2)
    arm_button.pack(pady=10)
    disarm_button = tk.Button(window, text="Disarm", command=disarm, bg="#dc3545", fg="white", width=20, height=2)
    disarm_button.pack(pady=5)
    disarm_button.config(state="disabled")

    window.protocol("WM_DELETE_WINDOW", require_password_before_exit)

if __name__ == "__main__":
    restore = "--restore" in sys.argv
    setup_gui()

    if restore:
        state = load_state()
        if state:
            encryption_targets[:] = state.get("targets", [])
            armed = state.get("armed", False)
            saved_hash = state.get("password_hash")
            update_file_list()
            if armed:
                pwd = simpledialog.askstring("Restore Password", "Enter your password:", show="*")
                if pwd and hash_password(pwd) == saved_hash:
                    password = pwd
                    arm()
                else:
                    messagebox.showerror("Restore failed", "Incorrect password.")
                    password_entry.delete(0, tk.END)

    hide_console()
    window.mainloop()