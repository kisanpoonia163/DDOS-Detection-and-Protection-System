#!/usr/bin/env python3
import sys, threading, subprocess, configparser, logging, datetime, time, csv, os, requests, smtplib, email.message, socket
from io import StringIO

# Set matplotlib backend explicitly for PyQt5
import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from scapy.all import sniff, TCP, UDP, ICMP, IP, rdpcap, raw
from PyQt5 import QtWidgets, QtCore, QtGui

###########################################
# Domain Resolution Cache and Function
###########################################
domain_cache = {}
def resolve_domain(ip):
    if ip in domain_cache:
        return domain_cache[ip]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        domain_cache[ip] = hostname
        return hostname
    except Exception:
        domain_cache[ip] = ""
        return ""

###########################################
# Config Loader
###########################################
class ConfigLoader:
    def __init__(self, filename='config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(filename)
    def get(self, section, option, fallback=None):
        return self.config.get(section, option, fallback=fallback)

###########################################
# Packet Capture Module
###########################################
class PacketCapture(threading.Thread):
    def __init__(self, interface, bpf_filter, callback):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.callback = callback
        self.stop_event = threading.Event()
    def run(self):
        try:
            sniff(iface=self.interface,
                  filter=self.bpf_filter,
                  prn=self.packet_handler,
                  stop_filter=self.should_stop)
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
    def packet_handler(self, packet):
        self.callback(packet)
    def should_stop(self, packet):
        return self.stop_event.is_set()
    def stop(self):
        self.stop_event.set()

###########################################
# Packet Analyzer Module
###########################################
class PacketAnalyzer:
    def analyze_packet(self, packet):
        details = {}
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src = ip_layer.src
            dst = ip_layer.dst
            details['src'] = src
            details['dst'] = dst
            details['src_domain'] = resolve_domain(src)
            details['dst_domain'] = resolve_domain(dst)
        else:
            details['src'] = details['dst'] = "N/A"
            details['src_domain'] = details['dst_domain'] = ""
        if packet.haslayer(TCP):
            details['protocol'] = 'TCP'
            tcp = packet.getlayer(TCP)
            details['src_port'] = str(tcp.sport)
            details['dst_port'] = str(tcp.dport)
            details['info'] = f"TCP Flags: {tcp.flags}"
        elif packet.haslayer(UDP):
            details['protocol'] = 'UDP'
            udp = packet.getlayer(UDP)
            details['src_port'] = str(udp.sport)
            details['dst_port'] = str(udp.dport)
            details['info'] = "UDP packet"
        elif packet.haslayer(ICMP):
            details['protocol'] = 'ICMP'
            details['src_port'] = details['dst_port'] = ""
            details['info'] = "ICMP packet"
        else:
            details['protocol'] = packet.lastlayer().name
            details['src_port'] = details['dst_port'] = ""
            details['info'] = packet.summary()
        details['length'] = str(len(packet))
        return details

###########################################
# Anomaly Detector Module
###########################################
class AnomalyDetector:
    def __init__(self, rate_limit):
        self.rate_limit = int(rate_limit)
        self.ip_counters = {}  # {ip: [count, last_reset_time]}
        self.lock = threading.Lock()
    def update_and_check(self, ip):
        now = time.time()
        with self.lock:
            if ip not in self.ip_counters:
                self.ip_counters[ip] = [1, now]
                return False
            count, last = self.ip_counters[ip]
            if now - last > 1:
                self.ip_counters[ip] = [1, now]
                return False
            else:
                count += 1
                self.ip_counters[ip] = [count, last]
                return count > self.rate_limit

###########################################
# Mitigation Engine Module
###########################################
class MitigationEngine:
    def __init__(self):
        self.blocked_ips = set()
        self.lock = threading.Lock()
    def block_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                return
            try:
                subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                self.blocked_ips.add(ip)
                logging.info(f"Blocked IP: {ip}")
            except Exception as e:
                logging.error(f"Error blocking IP {ip}: {e}")
    def unblock_ip(self, ip):
        with self.lock:
            if ip not in self.blocked_ips:
                return
            try:
                subprocess.check_call(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                self.blocked_ips.remove(ip)
                logging.info(f"Unblocked IP: {ip}")
            except Exception as e:
                logging.error(f"Error unblocking IP {ip}: {e}")

###########################################
# Threat Intelligence Module
###########################################
class ThreatIntelligence:
    def __init__(self, feed_url, update_interval):
        self.feed_url = feed_url.strip()
        self.update_interval = int(update_interval)
        self.malicious_ips = set()
        self.lock = threading.Lock()
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.update_thread.start()
    def update_loop(self):
        while True:
            self.update_threats()
            time.sleep(self.update_interval)
    def update_threats(self):
        if not self.feed_url:
            return
        try:
            response = requests.get(self.feed_url, timeout=10)
            if response.status_code == 200:
                data = response.json()  # Expects JSON array of IPs
                with self.lock:
                    self.malicious_ips = set(data)
                logging.info("Threat intelligence updated.")
            else:
                logging.warning("Threat intelligence feed returned non-200 status")
        except Exception as e:
            logging.error(f"Error updating threat intelligence: {e}")
    def is_malicious(self, ip):
        with self.lock:
            return ip in self.malicious_ips

###########################################
# Alert Manager Module
###########################################
class AlertManager:
    def __init__(self, email_alert, sms_alert, smtp_server, smtp_port, email_from, email_to, email_user, email_pass):
        self.email_alert = (email_alert.lower() == 'yes')
        self.sms_alert = (sms_alert.lower() == 'yes')
        self.smtp_server = smtp_server
        self.smtp_port = int(smtp_port) if smtp_port else 25
        self.email_from = email_from
        self.email_to = email_to
        self.email_user = email_user
        self.email_pass = email_pass
    def send_alert(self, message):
        logging.warning(f"ALERT: {message}")
        if self.email_alert and self.smtp_server and self.email_to:
            self.send_email_alert(message)
    def send_email_alert(self, message):
        try:
            msg = email.message.EmailMessage()
            msg.set_content(message)
            msg['Subject'] = 'DDoS Detection Alert'
            msg['From'] = self.email_from
            msg['To'] = self.email_to
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.email_user and self.email_pass:
                    server.login(self.email_user, self.email_pass)
                server.send_message(msg)
            logging.info("Email alert sent.")
        except Exception as e:
            logging.error(f"Error sending email alert: {e}")

###########################################
# TCP Stream Dialog (Follow TCP Stream)
###########################################
class TCPStreamDialog(QtWidgets.QDialog):
    def __init__(self, conversation_packets, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Follow TCP Stream")
        self.resize(800, 600)
        layout = QtWidgets.QVBoxLayout(self)
        text = QtWidgets.QTextEdit(self)
        text.setReadOnly(True)
        stream_info = "\n".join(packet.summary() for packet in conversation_packets)
        text.setText(stream_info)
        layout.addWidget(text)
        btn = QtWidgets.QPushButton("Close", self)
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)

###########################################
# Packet Details Panel (Embedded Details)
###########################################
class PacketDetailsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        self.details_tabs = QtWidgets.QTabWidget(self)
        self.info_text = QtWidgets.QTextEdit(self)
        self.info_text.setReadOnly(True)
        self.hex_text = QtWidgets.QTextEdit(self)
        self.hex_text.setReadOnly(True)
        self.details_tabs.addTab(self.info_text, "Detailed Info")
        self.details_tabs.addTab(self.hex_text, "Hex Dump")
        layout.addWidget(self.details_tabs)
    def update_details(self, packet):
        try:
            info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i+32] for i in range(0, len(hex_dump), 32))
            self.info_text.setText(info)
            self.hex_text.setText(formatted_hex)
        except Exception as e:
            self.info_text.setText(f"Error: {e}")
            self.hex_text.setText("")

###########################################
# Advanced Dashboard (GUI) Module with QTabWidget and Details Panel
###########################################
class AdvancedDashboard(QtWidgets.QMainWindow):
    # Custom signals for actions
    startCaptureRequested = QtCore.pyqtSignal()
    pauseCaptureRequested = QtCore.pyqtSignal()
    stopCaptureRequested = QtCore.pyqtSignal()
    openFileRequested = QtCore.pyqtSignal()
    clearTableRequested = QtCore.pyqtSignal()
    refreshBlockedRequested = QtCore.pyqtSignal()
    packetDoubleClicked = QtCore.pyqtSignal(int)
    packet_signal = QtCore.pyqtSignal(dict)

    def __init__(self, refresh_interval):
        super().__init__()
        self.setWindowTitle("Advanced DDoS Detection & Protection System")
        self.resize(1400, 900)
        self.refresh_interval = refresh_interval
        self.traffic_data = []
        self.max_data_points = 60
        self.packet_lengths = []
        self.init_ui()

    def init_ui(self):
        # Apply vibrant dark theme
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; }
            QTableWidget { background-color: #252526; color: #d4d4d4; gridline-color: #3c3c3c; }
            QHeaderView::section { background-color: #3c3c3c; color: #ffffff; padding: 4px; }
            QToolBar { background-color: #007acc; border: none; }
            QToolButton { background-color: #005a9e; color: #ffffff; border: 1px solid #005a9e; padding: 6px; }
            QToolButton:pressed { background-color: #003f6b; }
            QLineEdit { background-color: #3c3c3c; color: #d4d4d4; border: 1px solid #555555; padding: 4px; }
            QPushButton { background-color: #0e639c; color: #ffffff; border: 1px solid #0e639c; padding: 6px; }
            QPushButton:pressed { background-color: #073c5e; }
            QStatusBar { background-color: #007acc; color: #ffffff; }
            QMenuBar { background-color: #3c3c3c; color: #ffffff; }
            QMenu { background-color: #252526; color: #d4d4d4; }
            QMenu::item:selected { background-color: #005a9e; }
        """)
        # Create menu bar with Export and Reset options
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        export_csv = QtWidgets.QAction("Export Table to CSV", self)
        export_csv.triggered.connect(self.export_table_csv)
        save_pcap = QtWidgets.QAction("Save PCAP", self)
        save_pcap.triggered.connect(self.save_pcap)
        reset_stats = QtWidgets.QAction("Reset Stats", self)
        reset_stats.triggered.connect(self.reset_stats)
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(export_csv)
        file_menu.addAction(save_pcap)
        file_menu.addAction(reset_stats)
        file_menu.addAction(exit_action)
        # Create QTabWidget with three tabs: "Live Capture", "Statistics", "Conversation View"
        self.tabs = QtWidgets.QTabWidget(self)
        self.setCentralWidget(self.tabs)
        # Tab 1: Live Capture
        self.live_tab = QtWidgets.QWidget()
        live_vlayout = QtWidgets.QVBoxLayout(self.live_tab)
        # Capture control toolbar (added as a separate QToolBar at the top)
        self.capture_toolbar = QtWidgets.QToolBar("Capture Controls", self)
        self.addToolBar(QtCore.Qt.TopToolBarArea, self.capture_toolbar)
        self.start_btn = QtWidgets.QToolButton(self); self.start_btn.setText("Start Capture")
        self.start_btn.clicked.connect(lambda: self.startCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.start_btn)
        self.pause_btn = QtWidgets.QToolButton(self); self.pause_btn.setText("Pause Capture")
        self.pause_btn.clicked.connect(lambda: self.pauseCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.pause_btn)
        self.stop_btn = QtWidgets.QToolButton(self); self.stop_btn.setText("Stop Capture")
        self.stop_btn.clicked.connect(lambda: self.stopCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.stop_btn)
        self.open_btn = QtWidgets.QToolButton(self); self.open_btn.setText("Open PCAP File")
        self.open_btn.clicked.connect(lambda: self.openFileRequested.emit())
        self.capture_toolbar.addWidget(self.open_btn)
        self.clear_btn = QtWidgets.QToolButton(self); self.clear_btn.setText("Clear Table")
        self.clear_btn.clicked.connect(lambda: self.clearTableRequested.emit())
        self.capture_toolbar.addWidget(self.clear_btn)
        self.refresh_blocked_btn = QtWidgets.QToolButton(self); self.refresh_blocked_btn.setText("Refresh Blocked IPs")
        self.refresh_blocked_btn.clicked.connect(lambda: self.refreshBlockedRequested.emit())
        self.capture_toolbar.addWidget(self.refresh_blocked_btn)
        # Filter bar
        filter_layout = QtWidgets.QHBoxLayout()
        self.filter_input = QtWidgets.QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter filter text (IP, protocol, etc.)")
        self.filter_btn = QtWidgets.QPushButton("Apply Filter", self)
        self.filter_btn.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_btn)
        live_vlayout.addLayout(filter_layout)
        # Vertical splitter: top part = horizontal splitter for table and blocked IP list; bottom part = details panel
        v_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        h_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.packet_table = QtWidgets.QTableWidget()
        self.packet_table.setColumnCount(10)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Src IP", "Src Domain", "Dst IP", "Dst Domain",
                                                      "Src Port", "Dst Port", "Protocol", "Length", "Info"])
        self.packet_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.packet_context_menu)
        self.packet_table.itemSelectionChanged.connect(self.handle_packet_selection)
        h_splitter.addWidget(self.packet_table)
        self.blocked_table = QtWidgets.QTableWidget()
        self.blocked_table.setColumnCount(2)
        self.blocked_table.setHorizontalHeaderLabels(["Blocked IP", "Blocked Since"])
        h_splitter.addWidget(self.blocked_table)
        h_splitter.setSizes([900,400])
        v_splitter.addWidget(h_splitter)
        # Details panel (embedded below the table)
        self.details_panel = PacketDetailsPanel(self)
        v_splitter.addWidget(self.details_panel)
        v_splitter.setStretchFactor(0, 3)
        v_splitter.setStretchFactor(1, 1)
        live_vlayout.addWidget(v_splitter)
        self.tabs.addTab(self.live_tab, "Live Capture")
        # Tab 2: Statistics
        self.stats_tab = QtWidgets.QWidget()
        stats_layout = QtWidgets.QVBoxLayout(self.stats_tab)
        self.charts_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.traffic_fig = plt.figure(figsize=(5,4))
        self.traffic_canvas = FigureCanvas(self.traffic_fig)
        self.traffic_ax = self.traffic_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.traffic_canvas)
        self.pie_fig = plt.figure(figsize=(5,4))
        self.pie_canvas = FigureCanvas(self.pie_fig)
        self.pie_ax = self.pie_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.pie_canvas)
        self.hist_fig = plt.figure(figsize=(5,4))
        self.hist_canvas = FigureCanvas(self.hist_fig)
        self.hist_ax = self.hist_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.hist_canvas)
        self.charts_splitter.setSizes([500,500,500])
        stats_layout.addWidget(self.charts_splitter)
        self.tabs.addTab(self.stats_tab, "Statistics")
        # Tab 3: Conversation View
        self.conv_tab = QtWidgets.QWidget()
        conv_layout = QtWidgets.QVBoxLayout(self.conv_tab)
        self.conv_table = QtWidgets.QTableWidget()
        self.conv_table.setColumnCount(4)
        self.conv_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Protocol", "Packet Count"])
        conv_layout.addWidget(self.conv_table)
        self.tabs.addTab(self.conv_tab, "Conversation View")
        # Status Bar
        self.statusBar = QtWidgets.QStatusBar(self)
        self.setStatusBar(self.statusBar)
    
    def handle_packet_selection(self):
        selected_items = self.packet_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            details = {}
            for col in range(self.packet_table.columnCount()):
                header = self.packet_table.horizontalHeaderItem(col).text()
                item = self.packet_table.item(row, col)
                details[header] = item.text() if item else ""
            self.details_panel.info_text.setText("\n".join(f"{k}: {v}" for k, v in details.items()))
            self.details_panel.hex_text.setText("Hex dump not available from table data")
    
    def packet_context_menu(self, pos):
        index = self.packet_table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        proto = self.packet_table.item(row, 7).text().upper()
        menu = QtWidgets.QMenu(self)
        if proto == "TCP":
            follow_action = QtWidgets.QAction("Follow TCP Stream", self)
            follow_action.triggered.connect(lambda: self.follow_tcp_stream(row))
            menu.addAction(follow_action)
        menu.exec_(self.packet_table.viewport().mapToGlobal(pos))
    
    def follow_tcp_stream(self, row):
        src = self.packet_table.item(row, 1).text()
        dst = self.packet_table.item(row, 3).text()
        proto = self.packet_table.item(row, 7).text()
        conv_packets = []
        for packet in self.parent().captured_packets:
            details = self.parent().analyzer.analyze_packet(packet)
            if (details.get('src') == src and details.get('dst') == dst and details.get('protocol') == proto):
                conv_packets.append(packet)
        dlg = TCPStreamDialog(conv_packets, self)
        dlg.exec_()
    
    def apply_filter(self):
        text = self.filter_input.text().lower().strip()
        for row in range(self.packet_table.rowCount()):
            hide = True
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item and text in item.text().lower():
                    hide = False
                    break
            self.packet_table.setRowHidden(row, hide)
        self.statusBar.showMessage("Filter applied.", 3000)
    
    def clear_table(self):
        self.packet_table.setRowCount(0)
        self.statusBar.showMessage("Packet table cleared.", 3000)
    
    def add_packet_entry(self, packet_info):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        values = [packet_info.get('time',''),
                  packet_info.get('src',''),
                  packet_info.get('src_domain',''),
                  packet_info.get('dst',''),
                  packet_info.get('dst_domain',''),
                  packet_info.get('src_port',''),
                  packet_info.get('dst_port',''),
                  packet_info.get('protocol',''),
                  packet_info.get('length',''),
                  packet_info.get('info','')]
        for col, val in enumerate(values):
            item = QtWidgets.QTableWidgetItem(val)
            self.packet_table.setItem(row, col, item)
        proto = packet_info.get('protocol','').upper()
        if proto == "TCP":
            color = QtGui.QColor(70, 130, 180)
        elif proto == "UDP":
            color = QtGui.QColor(60, 179, 113)
        elif proto == "ICMP":
            color = QtGui.QColor(255, 165, 0)
        else:
            color = QtGui.QColor(169, 169, 169)
        for col in range(self.packet_table.columnCount()):
            self.packet_table.item(row, col).setBackground(color)
        self.traffic_data.append(1)
        if len(self.traffic_data) > self.max_data_points:
            self.traffic_data.pop(0)
    
    def update_charts(self, protocol_counts, packet_lengths, captured_packets, analyzer):
        self.traffic_ax.clear()
        self.traffic_ax.plot(self.traffic_data, color='cyan')
        self.traffic_ax.set_title("Traffic Volume (packets/sec)", color="#ffffff")
        self.traffic_ax.tick_params(colors="#ffffff")
        self.traffic_canvas.draw()
        self.pie_ax.clear()
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())
        if sizes and sum(sizes) > 0:
            self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, textprops={'color':'w'})
        self.pie_ax.set_title("Protocol Breakdown", color="#ffffff")
        self.pie_canvas.draw()
        self.hist_ax.clear()
        if packet_lengths:
            self.hist_ax.hist(packet_lengths, bins=20, color='magenta')
            self.hist_ax.set_title("Packet Length Distribution", color="#ffffff")
            self.hist_ax.tick_params(colors="#ffffff")
        self.hist_canvas.draw()
        self.update_conversation_view(captured_packets, analyzer)
    
    def update_conversation_view(self, captured_packets, analyzer):
        conv_dict = {}
        for packet in captured_packets:
            details = analyzer.analyze_packet(packet)
            key = (details.get('src',''), details.get('dst',''), details.get('protocol',''))
            conv_dict[key] = conv_dict.get(key, 0) + 1
        self.conv_table.setRowCount(0)
        for (src, dst, proto), count in conv_dict.items():
            row = self.conv_table.rowCount()
            self.conv_table.insertRow(row)
            self.conv_table.setItem(row, 0, QtWidgets.QTableWidgetItem(src))
            self.conv_table.setItem(row, 1, QtWidgets.QTableWidgetItem(dst))
            self.conv_table.setItem(row, 2, QtWidgets.QTableWidgetItem(proto))
            self.conv_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(count)))
        self.conv_table.resizeColumnsToContents()
    
    def show_packet_details(self, row):
        details = {}
        for col in range(self.packet_table.columnCount()):
            header = self.packet_table.horizontalHeaderItem(col).text()
            details[header] = self.packet_table.item(row, col).text()
        dlg = PacketDetailsTreeDialog("\n".join(f"{k}: {v}" for k, v in details.items()), None, self)
        dlg.exec_()
        # Also update the embedded details panel
        try:
            packet = self.parent().captured_packets[row]
            self.update_details_panel(row, packet)
        except Exception as e:
            logging.error(f"Error updating details panel: {e}")
    
    def set_blocked_ips(self, ips):
        self.blocked_table.setRowCount(0)
        for ip, ts in ips:
            row = self.blocked_table.rowCount()
            self.blocked_table.insertRow(row)
            self.blocked_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ip))
            self.blocked_table.setItem(row, 1, QtWidgets.QTableWidgetItem(ts))
        self.blocked_table.resizeColumnsToContents()
    
    def reset_stats(self):
        self.traffic_data = []
        self.statusBar.showMessage("Statistics reset.", 3000)
    
    def export_table_csv(self, filepath):
        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                headers = [self.packet_table.horizontalHeaderItem(col).text() for col in range(self.packet_table.columnCount())]
                writer.writerow(headers)
                for row in range(self.packet_table.rowCount()):
                    if self.packet_table.isRowHidden(row):
                        continue
                    rowdata = []
                    for col in range(self.packet_table.columnCount()):
                        item = self.packet_table.item(row, col)
                        rowdata.append(item.text() if item else "")
                    writer.writerow(rowdata)
            self.statusBar.showMessage(f"Exported table to {filepath}", 3000)
        except Exception as e:
            self.statusBar.showMessage(f"Error exporting CSV: {e}", 3000)
    
    def save_pcap(self, packets, filepath):
        from scapy.all import wrpcap
        try:
            wrpcap(filepath, packets)
            self.statusBar.showMessage(f"Saved {len(packets)} packets to {filepath}", 3000)
        except Exception as e:
            self.statusBar.showMessage(f"Error saving PCAP: {e}", 3000)
    
    def update_details_panel(self, row, packet):
        try:
            info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i+32] for i in range(0, len(hex_dump), 32))
            self.details_panel.info_text.setText(info)
            self.details_panel.hex_text.setText(formatted_hex)
        except Exception as e:
            self.details_panel.info_text.setText(f"Error: {e}")
            self.details_panel.hex_text.setText("")
    
    # End of AdvancedDashboard

###########################################
# Main Orchestrator
###########################################
class RealTimeDDOSMonitor:
    def __init__(self, config_file='config.ini'):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.config = ConfigLoader(config_file)
        self.interface = self.config.get('Network', 'Interface', fallback='eth0')
        self.filter_str = self.config.get('Network', 'Filter', fallback=None)
        self.packet_rate_limit = int(self.config.get('Mitigation', 'RateLimit', fallback='50'))
        self.block_duration = int(self.config.get('Mitigation', 'BlockDuration', fallback='600'))
        self.email_alert = self.config.get('Alerts', 'EmailAlert', fallback='no')
        self.sms_alert = self.config.get('Alerts', 'SMSAlert', fallback='no')
        self.smtp_server = self.config.get('Alerts', 'SMTPServer', fallback='')
        self.smtp_port = self.config.get('Alerts', 'SMTPPort', fallback='25')
        self.email_from = self.config.get('Alerts', 'EmailFrom', fallback='')
        self.email_to = self.config.get('Alerts', 'EmailTo', fallback='')
        self.email_user = self.config.get('Alerts', 'EmailUser', fallback='')
        self.email_pass = self.config.get('Alerts', 'EmailPass', fallback='')
        self.threat_feed_url = self.config.get('ThreatIntel', 'FeedURL', fallback='').strip()
        self.update_interval = self.config.get('ThreatIntel', 'UpdateInterval', fallback='3600')
        self.refresh_interval = int(self.config.get('GUI', 'RefreshInterval', fallback='1000'))
        self.analyzer = PacketAnalyzer()
        self.detector = AnomalyDetector(self.packet_rate_limit)
        self.mitigation = MitigationEngine()
        self.threat_intel = ThreatIntelligence(self.threat_feed_url, self.update_interval)
        self.alert_manager = AlertManager(self.email_alert, self.sms_alert,
                                          self.smtp_server, self.smtp_port,
                                          self.email_from, self.email_to,
                                          self.email_user, self.email_pass)
        self.protocol_counts = {}
        self.captured_packets = []
        self.packet_lengths = []
        self.app = QtWidgets.QApplication(sys.argv)
        self.dashboard = AdvancedDashboard(self.refresh_interval)
        self.dashboard.startCaptureRequested.connect(self.start_live_capture)
        self.dashboard.pauseCaptureRequested.connect(self.pause_live_capture)
        self.dashboard.stopCaptureRequested.connect(self.stop_live_capture)
        self.dashboard.openFileRequested.connect(self.open_file_and_analyze)
        self.dashboard.clearTableRequested.connect(self.clear_all)
        self.dashboard.refreshBlockedRequested.connect(self.update_blocked_ips)
        self.dashboard.packetDoubleClicked.connect(self.show_packet_details)
        self.dashboard.packet_signal.connect(self.dashboard.add_packet_entry)
        self.live_capture = None
        self.paused = False
        self.start_live_capture()
        self.chart_timer = QtCore.QTimer()
        self.chart_timer.setInterval(1000)
        self.chart_timer.timeout.connect(self.update_charts)
        self.chart_timer.start()
    def process_packet(self, packet):
        try:
            details = self.analyzer.analyze_packet(packet)
            details['time'] = datetime.datetime.now().strftime("%H:%M:%S")
            src_ip = details.get('src', '')
            proto = details.get('protocol', 'Other').upper()
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
            self.packet_lengths.append(int(details.get('length', '0')))
            if src_ip:
                if self.threat_intel.is_malicious(src_ip):
                    self.alert_manager.send_alert(f"Known malicious IP detected: {src_ip}")
                    self.mitigation.block_ip(src_ip)
                if self.detector.update_and_check(src_ip):
                    self.alert_manager.send_alert(f"Anomalous traffic from IP: {src_ip}")
                    self.mitigation.block_ip(src_ip)
            self.captured_packets.append(packet)
            self.dashboard.packet_signal.emit(details)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    def start_live_capture(self):
        if self.live_capture is None or not self.live_capture.is_alive():
            self.paused = False
            self.live_capture = PacketCapture(interface=self.interface,
                                              bpf_filter=self.filter_str,
                                              callback=self.process_packet)
            self.live_capture.daemon = True
            self.live_capture.start()
            self.dashboard.statusBar.showMessage("Live capture started.", 3000)
        else:
            self.dashboard.statusBar.showMessage("Live capture already running.", 3000)
    def pause_live_capture(self):
        if self.live_capture is not None and not self.paused:
            self.live_capture.stop()
            self.paused = True
            self.dashboard.statusBar.showMessage("Live capture paused.", 3000)
    def stop_live_capture(self):
        if self.live_capture is not None:
            self.live_capture.stop()
            self.paused = False
            self.dashboard.statusBar.showMessage("Live capture stopped.", 3000)
    def open_file_and_analyze(self):
        self.stop_live_capture()
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if filename:
            self.dashboard.statusBar.showMessage(f"Analyzing file: {filename}", 3000)
            try:
                packets = rdpcap(filename)
                for packet in packets:
                    self.process_packet(packet)
                self.dashboard.statusBar.showMessage(f"File analysis complete: {len(packets)} packets", 5000)
            except Exception as e:
                logging.error(f"Error reading file: {e}")
                self.dashboard.statusBar.showMessage("Error reading PCAP file.", 5000)
    def update_charts(self):
        self.dashboard.update_charts(self.protocol_counts, self.packet_lengths, self.captured_packets, self.analyzer)
        self.update_blocked_ips()
    def update_blocked_ips(self):
        blocked = []
        now = datetime.datetime.now().strftime("%H:%M:%S")
        for ip in sorted(self.mitigation.blocked_ips):
            blocked.append((ip, now))
        self.dashboard.set_blocked_ips(blocked)
    def show_packet_details(self, row):
        try:
            packet = self.captured_packets[row]
            layered_info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i+32] for i in range(0, len(hex_dump), 32))
            details = layered_info + "\n\nHex Dump:\n" + formatted_hex
            dlg = PacketDetailsTreeDialog(details, packet, self.dashboard)
            dlg.exec_()
            self.dashboard.update_details_panel(row, packet)
        except Exception as e:
            logging.error(f"Error showing packet details: {e}")
    def clear_all(self):
        self.dashboard.clear_table()
        self.captured_packets = []
        self.packet_lengths = []
        self.protocol_counts.clear()
    def export_table_to_csv(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Export Table to CSV", "", "CSV Files (*.csv)")
        if filepath:
            try:
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    headers = [self.dashboard.packet_table.horizontalHeaderItem(col).text() for col in range(self.dashboard.packet_table.columnCount())]
                    writer.writerow(headers)
                    for row in range(self.dashboard.packet_table.rowCount()):
                        if self.dashboard.packet_table.isRowHidden(row):
                            continue
                        rowdata = []
                        for col in range(self.dashboard.packet_table.columnCount()):
                            item = self.dashboard.packet_table.item(row, col)
                            rowdata.append(item.text() if item else "")
                        writer.writerow(rowdata)
                self.dashboard.statusBar.showMessage(f"Exported table to {filepath}", 3000)
            except Exception as e:
                self.dashboard.statusBar.showMessage(f"Error exporting CSV: {e}", 3000)
    def save_pcap_file(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Save PCAP File", "", "PCAP Files (*.pcap)")
        if filepath:
            try:
                from scapy.all import wrpcap
                wrpcap(filepath, self.captured_packets)
                self.dashboard.statusBar.showMessage(f"Saved {len(self.captured_packets)} packets to {filepath}", 3000)
            except Exception as e:
                self.dashboard.statusBar.showMessage(f"Error saving PCAP: {e}", 3000)
    def run(self):
        export_menu = QtWidgets.QMenu("Export", self.dashboard)
        export_csv_action = QtWidgets.QAction("Export Table to CSV", self.dashboard)
        export_csv_action.triggered.connect(self.export_table_to_csv)
        save_pcap_action = QtWidgets.QAction("Save PCAP", self.dashboard)
        save_pcap_action.triggered.connect(self.save_pcap_file)
        export_menu.addAction(export_csv_action)
        export_menu.addAction(save_pcap_action)
        self.dashboard.menuBar().addMenu(export_menu)
        self.dashboard.show()
        sys.exit(self.app.exec_())
    def stop(self):
        if self.live_capture is not None:
            self.live_capture.stop()

###########################################
# Extend AdvancedDashboard with Details Panel update method
###########################################
def update_details_panel(self, row, packet):
    try:
        info = packet.show(dump=True)
        hex_dump = raw(packet).hex()
        formatted_hex = "\n".join(hex_dump[i:i+32] for i in range(0, len(hex_dump), 32))
        self.details_panel.info_text.setText(info)
        self.details_panel.hex_text.setText(formatted_hex)
    except Exception as e:
        self.details_panel.info_text.setText(f"Error: {e}")
        self.details_panel.hex_text.setText("")
AdvancedDashboard.update_details_panel = update_details_panel

def handle_packet_selection(self):
    selected_items = self.packet_table.selectedItems()
    if selected_items:
        row = selected_items[0].row()
        details = {}
        for col in range(self.packet_table.columnCount()):
            header = self.packet_table.horizontalHeaderItem(col).text()
            item = self.packet_table.item(row, col)
            details[header] = item.text() if item else ""
        self.details_panel.info_text.setText("\n".join(f"{k}: {v}" for k, v in details.items()))
        self.details_panel.hex_text.setText("Hex dump not available from table data")
AdvancedDashboard.handle_packet_selection = handle_packet_selection
# Connect the selection signal after table creation in init_ui:
# (Add the following line in AdvancedDashboard.init_ui() after self.packet_table is created)
# self.packet_table.itemSelectionChanged.connect(self.handle_packet_selection)

###########################################
# Entry Point
###########################################
if __name__ == '__main__':
    monitor = RealTimeDDOSMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
