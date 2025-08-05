# 💻 BusKill-Inspired Laptop Security System (Dead Man’s Switch)

This project is a Python-based USB tethering security system that **locks your PC and encrypts selected files** when a specific USB device (like an ATTINY85 or flash drive) is unplugged from your system. It mimics a "Dead Man’s Switch" that activates automatically in theft or emergency situations.

> ⚠️ **Disclaimer**: This tool does not currently include a persistent background monitor to relaunch after being terminated from Task Manager. Only the main application is implemented in this release.

---

## 📷 Demo Screenshots
<img width="747" height="663" alt="image" src="https://github.com/user-attachments/assets/ed877fbd-9658-40db-bde8-a14c37959609" />


---

## ✨ Features

- 🔐 AES-256 Encryption for selected files and folders
- 🔑 USB device-based trigger (based on VID and PID)
- 🧠 Password-protected arming and disarming
- 🔒 Auto lock workstation on USB removal
- 📦 Portable EXE generation using PyInstaller
- 🖥️ GUI-based control with minimalistic design
- 💡 Hotkey toggle (`Ctrl+Alt+B`) to show/hide GUI

---

## 📦 Requirements

### ✅ Software

- Python 3.8 or above  
- PyInstaller (for converting to `.exe`)  
- Any IDE or Command Line Interface (CMD / PowerShell)

---

## 🔧 Required Python Libraries

Install all required libraries with this single command:

```bash
pip install pycryptodome tqdm keyboard wmi

```

## 🧩 Setup Instructions

### 1️⃣ Clone or Download the Repository

```bash
git clone https://github.com/yourusername/buskill-usb-encryption.git
cd buskill-usb-encryption

```

### 2️⃣ 🧪 Identify Your USB Device
You need to find the VID (Vendor ID) and PID (Product ID) of your USB trigger device:

**➤ Steps:
Plug in the USB device you want to use as your "kill switch".**

Open Device Manager.

Find the device under Universal Serial Bus devices or Ports (COM & LPT).

Right-click > Properties > Details tab.

In the Property dropdown, choose: Device Instance Path.

You’ll see something like:
USB\VID_16C0&PID_27DB\ABC123...

**➤ Copy your VID and PID:**
In this example:

VID = 16C0

PID = 27DB

### 3️⃣ 🛠️ Modify the Python Code
Open the main script (buskill_secure.py) in your IDE or text editor.

Find these lines near the top:
```bash
DEVICE_VID = "16C0"
DEVICE_PID = "27DB"

```
Replace 16C0 and 27DB with your actual device's VID and PID values.

### 4️⃣ ⚙️ Run or Build the Application

**▶️ To Run from Source (Python script):**
1. Ensure Python is installed and in PATH.

2. Double-click or run via terminal:
```bash
python buskill_secure.py

```

**🧱 To Generate Standalone .exe File:**
1. Open CMD or Terminal in the project directory.

2. Run the following command:
```bash
py -m PyInstaller --noconfirm --onefile --windowed buskill_secure.py


```
3. After completion, the dist/ folder will contain buskill_secure.exe.

4. You can now move the .exe to any location and run it directly.

## 🔐 Usage Instructions

1. Launch the application.

2. Add files or folders you want to protect.

3. Enter a secure password and click "Arm".

4. The application will minimize. To bring back the application CTRL + ALT + B which is the Hotkey. This hotkey can be changed based om the user.

5. If the designated USB device is removed:

(i)  🖥️ Your system will lock immediately.

(ii) 🔐 The selected files/folders will be AES encrypted.

6. Reconnect the USB, launch the app, enter the same password, and click "Disarm" to decrypt your files.

## 🚫 Limitations
❌ No restart monitoring: If this application is force-closed via Task Manager, it does not currently restart or monitor automatically.

❌ Deletion or corruption of buskill_state.json (saved state file) will prevent decryption.

❗ Use responsibly and back up important files before using this tool.

## 👨‍💻 Author
Jeffry Joseph
Cybersecurity | Python |VAPT| Digital Forensics 
