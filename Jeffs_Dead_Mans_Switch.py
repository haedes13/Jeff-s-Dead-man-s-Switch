import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import wmi
import pythoncom
import os
import time
import ctypes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from tqdm import tqdm
import keyboard
import sys

# --- Device Info ---
DEVICE_VID = "16C0"
DEVICE_PID = "27DB"

# --- AES Constants ---
KEY_SIZE = 32
SALT_SIZE = 16
CHUNK_SIZE = 64 * 1024
encryption_targets = []
password = None
armed = False
hotkey_registered = False

# --- Locking ---
def lock_pc():
    ctypes.windll.user32.LockWorkStation()

def is_device_connected():
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for usb in c.Win32_PnPEntity():
            if usb.PNPDeviceID and DEVICE_VID in usb.PNPDeviceID and DEVICE_PID in usb.PNPDeviceID:
                return True
    except Exception as e:
        print(f"[ERROR] USB detection failed: {e}")
    finally:
        pythoncom.CoUninitialize()
    return False

def keep_locking_until_usb_inserted():
    print("[LOCK LOOP] Enforcing lock until USB returns...")
    while not is_device_connected():
        lock_pc()
        time.sleep(0.5)  # Slight delay to avoid rapid looping

# --- AES Crypto ---
def derive_key(pwd, salt):
    return PBKDF2(pwd.encode(), salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(input_file, output_file, pwd):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(pwd, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    file_size = os.path.getsize(input_file)

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(nonce)
        for _ in tqdm(range(0, file_size, CHUNK_SIZE), desc=f"Encrypting {os.path.basename(input_file)}"):
            chunk = f_in.read(CHUNK_SIZE)
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)
        f_out.write(cipher.digest())

def encrypt_folder(folder_path, pwd):
    aes_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            path = os.path.join(root, file)
            if not path.endswith('.aes'):
                encrypted_path = path + ".aes"
                encrypt_file(path, encrypted_path, pwd)
                os.remove(path)
                aes_files.append(encrypted_path)
    return aes_files

def encrypt_all_targets():
    global encryption_targets
    new_targets = []
    for path in encryption_targets:
        if os.path.isfile(path):
            encrypted_path = path + ".aes"
            encrypt_file(path, encrypted_path, password)
            os.remove(path)
            new_targets.append(encrypted_path)
        elif os.path.isdir(path):
            new_targets.extend(encrypt_folder(path, password))
    encryption_targets.clear()
    encryption_targets.extend(new_targets)

def decrypt_file(input_file, output_file, pwd):
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        ciphertext = f_in.read()
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        key = derive_key(pwd, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        with open(output_file, 'wb') as f_out:
            f_out.write(cipher.decrypt_and_verify(ciphertext, tag))

def decrypt_all_targets(pwd):
    original_files = []
    for path in encryption_targets[:]:
        if os.path.isfile(path) and path.endswith('.aes'):
            original_file = path[:-4]
            decrypt_file(path, original_file, pwd)
            os.remove(path)
            original_files.append(original_file)
    encryption_targets.clear()
    encryption_targets.extend(original_files)
    update_file_list()

# --- Monitor Thread ---
def monitor_usb():
    global armed, password
    print("[*] USB Monitoring Started")
    while armed:
        if not is_device_connected():
            print("[!] USB Removed")

            # ⚡ Lock immediately
            lock_pc()

            # 💾 Encrypt files in background
            if encryption_targets and password:
                print("[*] Encrypting files in background...")
                threading.Thread(target=encrypt_all_targets, daemon=True).start()

            # Reset password field
            password_entry.delete(0, tk.END)
            password = None

            # 🔁 Keep locking until reinserted
            threading.Thread(target=keep_locking_until_usb_inserted, daemon=True).start()

            # Wait here until reinserted
            while not is_device_connected():
                time.sleep(0.1)  # More frequent USB reinsertion check

            print("[+] USB Reinserted — Awaiting Disarm")

        time.sleep(0.1)  # 🔁 Check more frequently (100ms)

# --- Hotkey Toggle ---
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

# --- GUI Actions ---
def arm():
    global armed, password
    pwd = password_entry.get()
    if not pwd:
        messagebox.showerror("Missing Password", "Please enter password before arming.")
        return

    password = pwd
    armed = True
    password_entry.delete(0, tk.END)

    arm_button.config(state="disabled")
    disarm_button.config(state="normal")
    status_label.config(text="BusKill is ARMED", fg="white")
    window.config(bg="#ff3333")

    # Hide GUI and start monitoring
    window.withdraw()
    register_hotkey()
    threading.Thread(target=monitor_usb, daemon=True).start()

def disarm():
    global armed
    if not is_device_connected():
        messagebox.showerror("USB Not Connected", "Insert the USB device to disarm and decrypt.")
        return

    pwd = password_entry.get()
    if not pwd:
        if any(path.endswith('.aes') for path in encryption_targets):
            messagebox.showerror("Missing Password", "Please enter password to decrypt files.")
        else:
            messagebox.showerror("Missing Password", "Please enter password to disarm.")
        return

    try:
        if encryption_targets:
            decrypt_all_targets(pwd)
            messagebox.showinfo("Decryption Complete", "All files successfully decrypted.")
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Error decrypting files:\n{e}")
        return

    password_entry.delete(0, tk.END)
    arm_button.config(state="normal")
    disarm_button.config(state="disabled")
    status_label.config(text="BusKill is DISARMED", fg="white")
    window.config(bg="#3399ff")
    armed = False
    unregister_hotkey()

def add_files():
    files = filedialog.askopenfilenames(title="Select Files")
    for f in files:
        if f not in encryption_targets:
            encryption_targets.append(f)
    update_file_list()

def add_folder():
    folder = filedialog.askdirectory(title="Select Folder")
    if folder and folder not in encryption_targets:
        encryption_targets.append(folder)
    update_file_list()

def remove_selected():
    selected = list(file_listbox.curselection())
    for i in reversed(selected):
        del encryption_targets[i]
    update_file_list()

def update_file_list():
    file_listbox.delete(0, tk.END)
    for path in encryption_targets:
        file_listbox.insert(tk.END, path)

# --- Close Handler ---
def on_closing():
    unregister_hotkey()
    sys.exit()

# --- GUI Layout ---
window = tk.Tk()
window.title("BusKill Secure Encryptor")
window.geometry("600x500")
window.config(bg="#3399ff")
window.protocol("WM_DELETE_WINDOW", on_closing)

status_label = tk.Label(window, text="BusKill is DISARMED", fg="white", bg=window["bg"], font=("Arial", 14))
status_label.pack(pady=10)

tk.Label(window, text="Password:", bg=window["bg"], fg="white", font=("Arial", 12)).pack()
password_entry = tk.Entry(window, show="*", font=("Arial", 12), width=30)
password_entry.pack(pady=5)

btn_frame = tk.Frame(window, bg=window["bg"])
btn_frame.pack(pady=5)
tk.Button(btn_frame, text="Add File", command=add_files, width=12).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Add Folder", command=add_folder, width=12).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Remove Selected", command=remove_selected, width=14).grid(row=0, column=2, padx=5)

file_listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, width=70, height=10, font=("Arial", 10))
file_listbox.pack(pady=10)

arm_button = tk.Button(window, text="Arm", command=arm, bg="#007bff", fg="white", font=("Arial", 14), width=20, height=2)
arm_button.pack(pady=10)

disarm_button = tk.Button(window, text="Disarm", command=disarm, bg="#dc3545", fg="white", font=("Arial", 14), width=20, height=2)
disarm_button.pack(pady=10)
disarm_button.config(state="disabled")

window.mainloop()