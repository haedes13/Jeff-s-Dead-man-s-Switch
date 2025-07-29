# 💻 BusKill-Inspired Laptop Security System (Dead Man’s Switch)

This project is a Python-based USB tethering security system that **locks your PC and encrypts selected files** when a specific USB device (like an ATTINY85 or flash drive) is unplugged from your system. It mimics a "Dead Man’s Switch" that activates automatically in theft or emergency situations.

> ⚠️ **Disclaimer**: This tool does not currently include a persistent background monitor to relaunch after being terminated from Task Manager. Only the main application is implemented in this release.

---

## 📷 Demo Screenshots
_Add your screenshots here: GUI, encryption progress, USB disconnect lock screen, etc._

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
