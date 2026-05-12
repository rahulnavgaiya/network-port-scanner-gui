# network-port-scanner-gui
The Network Port Scanner GUI is a Python-based application used to scan open ports and identify active services on a target system. It uses socket, threading, and tkinter libraries to perform fast multi-threaded scanning through a simple graphical user interface.

import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox

# -------------------------------
# Common Port Services
# -------------------------------
COMMON_PORTS = {
    20: 'FTP-Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-Alt'
}

# -------------------------------
# Port Scanner Class
# -------------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_threads = max_threads

        self.open_ports = []
        self.queue = queue.Queue()

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                self.open_ports.append((port, service))

            sock.close()

        except Exception:
            pass

    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run_scan(self):
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        threads = []

        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.queue.join()

        return sorted(self.open_ports)


# -------------------------------
# GUI Application
# -------------------------------
class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Port Scanner")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Target
        tk.Label(root, text="Target IP / Hostname:").pack(pady=5)
        self.target_entry = tk.Entry(root, width=40)
        self.target_entry.pack()

        # Start Port
        tk.Label(root, text="Start Port:").pack(pady=5)
        self.start_port_entry = tk.Entry(root, width=20)
        self.start_port_entry.pack()

        # End Port
        tk.Label(root, text="End Port:").pack(pady=5)
        self.end_port_entry = tk.Entry(root, width=20)
        self.end_port_entry.pack()

        # Scan Button
        self.scan_button = tk.Button(
            root,
            text="Start Scan",
            command=self.start_scan,
            bg="green",
            fg="white",
            width=20
        )
        self.scan_button.pack(pady=10)

        # Results Box
        self.result_box = tk.Text(root, height=18, width=80)
        self.result_box.pack(pady=10)

        # Scrollbar
        scrollbar = ttk.Scrollbar(root, command=self.result_box.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_box.config(yscrollcommand=scrollbar.set)

    def start_scan(self):
        target = self.target_entry.get().strip()

        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())

        except ValueError:
            messagebox.showerror("Error", "Ports must be integers!")
            return

        if start_port < 1 or end_port > 65535:
            messagebox.showerror("Error", "Port range must be 1 - 65535")
            return

        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"Scanning {target}...\n\n")

        threading.Thread(
            target=self.run_scanner,
            args=(target, start_port, end_port),
            daemon=True
        ).start()

    def run_scanner(self, target, start_port, end_port):
        try:
            ip = socket.gethostbyname(target)

            self.result_box.insert(tk.END, f"Resolved IP: {ip}\n")
            self.result_box.insert(tk.END, "-" * 50 + "\n")

            scanner = PortScanner(ip, start_port, end_port)
            results = scanner.run_scan()

            if results:
                for port, service in results:
                    self.result_box.insert(
                        tk.END,
                        f"[OPEN] Port {port:<5} Service: {service}\n"
                    )
            else:
                self.result_box.insert(tk.END, "No open ports found.\n")

            self.result_box.insert(tk.END, "\nScan Completed.")

        except socket.gaierror:
            messagebox.showerror("Error", "Invalid Hostname/IP")

        except Exception as e:
            messagebox.showerror("Error", str(e))


# -------------------------------
# Run Application
# -------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
