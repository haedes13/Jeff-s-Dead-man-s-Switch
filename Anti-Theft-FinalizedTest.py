import tkinter as tk
import threading
import wmi
import pythoncom
import os
import time
import ctypes

# Digispark USB Device VID & PID
DEVICE_VID = "16C0"
DEVICE_PID = "27DB"

armed = False
monitor_thread = None

def lock_pc():
    """Lock the workstation."""
    ctypes.windll.user32.LockWorkStation()

def is_device_connected():
    """Check if the USB device is currently connected."""
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

def monitor_usb():
    """Continuously monitor USB and lock PC if device removed."""
    global armed
    print("[*] USB Monitoring Thread Started")
    while armed:
        if not is_device_connected():
            print("[!] USB Removed - Locking PC")
            lock_pc()
            time.sleep(2)
            # Wait for USB to be reinserted
            while not is_device_connected():
                print("[!] USB still missing - locking again")
                lock_pc()
                time.sleep(5)
            print("[+] USB detected - resuming")
        time.sleep(1)

def arm():
    """Activate BusKill monitoring."""
    global armed, monitor_thread
    if not armed:
        armed = True
        arm_button.config(state="disabled")
        disarm_button.config(state="normal")
        status_label.config(text="BusKill is currently armed.", fg="white")
        window.config(bg="#ff3333")  # Red for armed
        monitor_thread = threading.Thread(target=monitor_usb, daemon=True)
        monitor_thread.start()

def disarm():
    """Deactivate BusKill monitoring."""
    global armed
    armed = False
    arm_button.config(state="normal")
    disarm_button.config(state="disabled")
    status_label.config(text="BusKill is currently disarmed.", fg="white")
    window.config(bg="#3399ff")  # Blue for disarmed

# === GUI ===
window = tk.Tk()
window.title("BusKill")
window.geometry("400x300")
window.config(bg="#3399ff")

status_label = tk.Label(window, text="BusKill is currently disarmed.", fg="white", bg=window["bg"], font=("Arial", 14))
status_label.pack(pady=40)

arm_button = tk.Button(window, text="Arm", command=arm, bg="#007bff", fg="white", font=("Arial", 14), width=20, height=2)
arm_button.pack(pady=10)

disarm_button = tk.Button(window, text="Disarm", command=disarm, bg="#dc3545", fg="white", font=("Arial", 14), width=20, height=2)
disarm_button.pack(pady=10)
disarm_button.config(state="disabled")

window.mainloop()
