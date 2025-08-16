import winreg
import getpass
import sys
import ctypes
import os

PASSWORD = "YourStrongPassword"  # Change this to your own strong password

def is_admin():
    """Check if script is run as Administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def block_usb():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
        winreg.CloseKey(key)
        print("[+] USB storage devices are now BLOCKED (registry updated).")
    except PermissionError:
        print("[!] Permission denied. Please run this script as Administrator.")

def unblock_usb():
    typed_pass = getpass.getpass("Enter password to unblock USB: ")
    if typed_pass != PASSWORD:
        print("[!] Incorrect password. Access denied.")
        return

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
        winreg.CloseKey(key)
        print("[+] USB storage devices are now ENABLED (registry updated).")
    except PermissionError:
        print("[!] Permission denied. Please run this script as Administrator.")

def check_status():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                             0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)
        if value == 4:
            print("[*] USB storage devices are currently BLOCKED.")
        elif value == 3:
            print("[*] USB storage devices are currently ENABLED.")
        else:
            print(f"[*] Unknown USBSTOR status: {value}")
    except FileNotFoundError:
        print("[!] USBSTOR registry key not found.")
    except PermissionError:
        print("[!] Permission denied. Please run this script as Administrator.")

def main():
    if not is_admin():
        print("[!] This script must be run as Administrator.")
        # Re-run the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        return

    if len(sys.argv) < 2:
        print("Usage: python usb_blocker_windows.py [block|unblock|status]")
        return

    action = sys.argv[1].lower()
    if action == "block":
        block_usb()
    elif action == "unblock":
        unblock_usb()
    elif action == "status":
        check_status()
    else:
        print("[!] Invalid argument. Use block/unblock/status.")

if __name__ == "__main__":
    main()