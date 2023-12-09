import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import socket
import requests

def get_geo_info(ip_address):
    api_token = ""
    url = f"http://ipinfo.io/{ip_address}?token={api_token}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return {
            "IP": data.get("ip"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Country": data.get("country"),
            "Location": data.get("loc"),
            "ISP": data.get("org"),
            "AS": data.get("asn"),
            "Hostname": data.get("hostname"),
        }
    except requests.RequestException as e:
        return {"Error": f"Failed to retrieve information for {ip_address}. Error: {e}"}


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        self.tabControl = ttk.Notebook(root)
        self.tabControl.pack(expand=1, fill="both")

        self.tab1 = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab1, text='Scan Results')

        self.tab2 = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab2, text='Save Results')

        self.create_tab1_widgets()
        self.create_tab2_widgets()

    def create_tab1_widgets(self):
        frame = ttk.Frame(self.tab1)
        frame.pack(fill="both", expand=True)

        self.target_label = ttk.Label(frame, text="Insert IP address:")
        self.target_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

        self.target_entry = ttk.Entry(frame, width=15)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.scan_button = ttk.Button(frame, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)

        self.result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=20)
        self.result_text.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

    def create_tab2_widgets(self):
        frame = ttk.Frame(self.tab2)
        frame.pack(fill="both", expand=True)

        self.save_button = ttk.Button(frame, text="Save Results", command=self.save_results)
        self.save_button.pack(padx=10, pady=10)

        self.save_status = ttk.Label(frame, text="")
        self.save_status.pack(padx=10, pady=10)

    def start_scan(self):
        target = self.target_entry.get()
        self.result_text.delete(1.0, tk.END)

        if not target:
            self.result_text.insert(tk.END, "Please enter an IP address.\n")
            return

        open_ports = self.check_ports(target)
        host_info = get_host_info(target)
        geo_info = get_geo_info(target)

        results = {
            "Host Information": host_info,
            "Geographical Information": geo_info,
            "Open Ports": open_ports,
        }

        self.display_results(results)

    def check_ports(self, target):
        open_ports = []
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 443]  # Диапазон стандартных портов

        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except Exception as e:
                pass
        return open_ports

    def display_results(self, results):
        for category, info in results.items():
            self.result_text.insert(tk.END, f"{category}:\n")
            if isinstance(info, dict):
                for key, value in info.items():
                    self.result_text.insert(tk.END, f"  {key}: {value}\n")
            elif isinstance(info, list):
                for item in info:
                    self.result_text.insert(tk.END, f"  - {item}\n")
            else:
                self.result_text.insert(tk.END, f"  {info}\n")
            self.result_text.insert(tk.END, "\n")

    def save_results(self):
        results = self.result_text.get(1.0, tk.END)
        filename = "scan_results.txt"
        with open(filename, "a") as file:
            file.write(results)
            file.write("\n\n===============================\n\n")
        self.save_status.config(text=f"Results appended to {filename}")

def get_host_info(target):
    try:
        host_info = socket.gethostbyaddr(target)
        return {
            "IP": target,
            "Hostname": host_info[0],
            "Aliases": host_info[1],
            "Canonical Name": host_info[2]
        }
    except socket.herror:
        return {"IP": target, "Hostname": "Unknown"}

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()


