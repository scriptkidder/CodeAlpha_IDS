import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from collections import defaultdict
import time
import threading
from plyer import notification
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Constants
TIME_WINDOW = 10  # Time window in seconds
PORT_SCAN_THRESHOLD = 5
SYN_FLOOD_THRESHOLD = 10

# Data structures
detection_data = defaultdict(list)

# Configure Email settings
SMTP_SERVER = "smtp.example.com"  # Replace with your SMTP server
SMTP_PORT = 587  # SMTP server port
SENDER_EMAIL = "your_email@example.com"
RECEIVER_EMAIL = "receiver_email@example.com"
SENDER_PASSWORD = "your_email_password"  # Use app-specific password if required

# GUI class for the IDS
class IntrusionDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Intrusion Detection System")
        self.root.geometry("700x600")  # Increase window size
        self.root.config(bg='#f2f2f2')  # Light gray background

        # Interface selection
        self.interface_label = tk.Label(root, text="Select Network Interface:", font=("Helvetica", 12), bg="#f2f2f2")
        self.interface_label.pack(pady=10)

        self.interface_combo = ttk.Combobox(root, values=self.get_interfaces(), state="readonly", font=("Helvetica", 12))
        self.interface_combo.pack(pady=10)

        # Port scan and SYN flood thresholds
        self.port_scan_label = tk.Label(root, text="Port Scan Threshold:", font=("Helvetica", 12), bg="#f2f2f2")
        self.port_scan_label.pack(pady=10)
        self.port_scan_entry = tk.Entry(root, font=("Helvetica", 12))
        self.port_scan_entry.insert(0, str(PORT_SCAN_THRESHOLD))
        self.port_scan_entry.pack(pady=5)

        self.syn_flood_label = tk.Label(root, text="SYN Flood Threshold:", font=("Helvetica", 12), bg="#f2f2f2")
        self.syn_flood_label.pack(pady=10)
        self.syn_flood_entry = tk.Entry(root, font=("Helvetica", 12))
        self.syn_flood_entry.insert(0, str(SYN_FLOOD_THRESHOLD))
        self.syn_flood_entry.pack(pady=5)

        # Start/Stop buttons
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring, font=("Helvetica", 12), bg="#4CAF50", fg="white", relief="raised")
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED, font=("Helvetica", 12), bg="#F44336", fg="white", relief="raised")
        self.stop_button.pack(pady=10)

        # Display alerts
        self.alerts_label = tk.Label(root, text="Detected Intrusions:", font=("Helvetica", 14, "bold"), bg="#f2f2f2")
        self.alerts_label.pack(pady=10)

        self.alerts_text = tk.Text(root, height=10, width=80, state=tk.DISABLED, font=("Helvetica", 12), bg="#e8e8e8", fg="black", wrap="word")
        self.alerts_text.pack(pady=10)

        # Export Logs Button
        self.export_button = tk.Button(root, text="Export Logs", command=self.export_logs, font=("Helvetica", 12), bg="#2196F3", fg="white", relief="raised")
        self.export_button.pack(pady=10)

        # Plot Graph Button
        self.plot_button = tk.Button(root, text="Plot Packet Count", command=self.plot_graph, font=("Helvetica", 12), bg="#FFC107", fg="white", relief="raised")
        self.plot_button.pack(pady=10)

        self.packet_counts = []
        self.packet_info = []

        # Interactive Graph
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, self.root)
        self.canvas.get_tk_widget().pack(pady=10)

        self.running = False
        self.sniff_thread = None

        # Setup database
        self.db_conn = sqlite3.connect("intrusion_logs.db")
        self.create_table()

    def get_interfaces(self):
        return [iface.name for iface in conf.ifaces.values() if iface.name != 'lo']

    def start_monitoring(self):
        selected_interface = self.interface_combo.get()
        if not selected_interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.config(state=tk.DISABLED)

        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(selected_interface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_monitoring(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # Ensure the sniffing thread is properly stopped
        if self.sniff_thread.is_alive():
            self.sniff_thread.join()

        messagebox.showinfo("Info", "Monitoring stopped.")

    def sniff_packets(self, interface):
        print(f"Sniffing packets on interface: {interface}")  # Debugging
        try:
            sniff(
                iface=interface,
                filter="ip",  # Capture all IP packets
                prn=self.detect_intrusion,
                store=False,
                timeout=10,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"Error while sniffing: {e}")
            messagebox.showerror("Error", f"Error while sniffing packets: {e}")

    def detect_intrusion(self, packet):
        print(packet.summary())  # Debugging: Print each packet summary
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet.proto
            current_time = time.time()
            self.packet_info.append((src_ip, dst_ip, protocol, current_time))

            # Clean up old data
            self.packet_info = [
                (src, dst, proto, t) for src, dst, proto, t in self.packet_info if current_time - t <= TIME_WINDOW
            ]

            # Detect Port scan
            unique_ips = {entry[0] for entry in self.packet_info}
            if len(unique_ips) > int(self.port_scan_entry.get()):
                self.log_alert(f"[ALERT] Port scan detected from IP: {src_ip}", severity="High")
                self.send_email_alert(f"Port scan detected from IP: {src_ip}")

            # Detect SYN Flood
            syn_count = sum(1 for _, _, p, _ in self.packet_info if p == 6)  # TCP protocol is 6
            if syn_count > int(self.syn_flood_entry.get()):
                self.log_alert(f"[ALERT] SYN flood detected from IP: {src_ip}", severity="High")
                self.send_email_alert(f"SYN flood detected from IP: {src_ip}")

            # Update packet count for the graph
            self.packet_counts.append(len(self.packet_info))
            if len(self.packet_counts) > 100:
                self.packet_counts.pop(0)

            # Update the detected intrusions list in the GUI
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.insert(tk.END, f"Packet from {src_ip} to {dst_ip} detected.\n")
            self.alerts_text.see(tk.END)
            self.alerts_text.config(state=tk.DISABLED)

            # Update Graph
            self.update_graph()

    def log_alert(self, alert, severity="Medium"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {alert} - Severity: {severity}"
        
        # Log to database
        cursor = self.db_conn.cursor()
        cursor.execute("INSERT INTO logs (log) VALUES (?)", (log_entry,))
        self.db_conn.commit()

        # Show notification
        notification.notify(
            title="Intrusion Detected",
            message=log_entry,
            timeout=10
        )

    def update_graph(self):
        self.ax.clear()
        self.ax.plot(self.packet_counts, color='blue')
        self.ax.set_title('Packets per Second')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.canvas.draw()

    def send_email_alert(self, alert_message):
        try:
            msg = MIMEMultipart()
            msg["From"] = SENDER_EMAIL
            msg["To"] = RECEIVER_EMAIL
            msg["Subject"] = "Intrusion Detection Alert"

            body = MIMEText(alert_message, "plain")
            msg.attach(body)

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

            notification.notify(
                title="Intrusion Detected",
                message=alert_message,
                timeout=10
            )
        except Exception as e:
            print(f"Error sending email alert: {e}")

    def create_table(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                          id INTEGER PRIMARY KEY,
                          log TEXT)''')
        self.db_conn.commit()

    def export_logs(self):
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT * FROM logs")
        rows = cursor.fetchall()

        with open("intrusion_logs.txt", "w") as file:
            for row in rows:
                file.write(f"{row[1]}\n")

        messagebox.showinfo("Info", "Logs exported successfully to intrusion_logs.txt.")

    def plot_graph(self):
        plt.figure(figsize=(10, 5))
        plt.plot(self.packet_counts, color='blue')
        plt.title('Packets per Second')
        plt.xlabel('Time')
        plt.ylabel('Packet Count')
        plt.show()

# Run the application
root = tk.Tk()
app = IntrusionDetectionApp(root)
root.mainloop()
