import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QLabel)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor

import sniffer_core

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analizador de Paquetes (Sniffer) - Pybind11 & Npcap")
        self.resize(1000, 600)
        self.core = sniffer_core.PacketCapture()
        
        self.init_ui()
        self.apply_dark_mode()
        self.populate_interfaces()
        
        # Timer para consumir paquetes (100ms)
        self.timer = QTimer()
        self.timer.timeout.connect(self.consume_packets)
        
    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # --- Top Bar ---
        top_bar = QHBoxLayout()
        
        self.lbl_iface = QLabel("Interfaz:")
        top_bar.addWidget(self.lbl_iface)
        
        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(400)
        top_bar.addWidget(self.combo_iface)
        
        self.btn_start = QPushButton("Iniciar Captura")
        self.btn_start.clicked.connect(self.toggle_capture)
        top_bar.addWidget(self.btn_start)
        
        top_bar.addStretch()
        layout.addLayout(top_bar)
        
        # --- Table ---
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["No.", "Protocolo", "IP Origen", "Puerto Origen", "IP Destino", "Puerto Destino", "Longitud"]
        )
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.table)
        
        # Estado
        self.packet_count = 0
        self.is_capturing = False

    def populate_interfaces(self):
        interfaces = self.core.get_interfaces()
        if not interfaces:
            self.combo_iface.addItem("No se encontraron interfaces funcionales")
            self.btn_start.setEnabled(False)
            return
            
        for iface in interfaces:
            self.combo_iface.addItem(iface)
            
        # Intentar preseleccionar una realtek/intel/ethernet/wifi
        for i in range(self.combo_iface.count()):
            text = self.combo_iface.itemText(i).lower()
            if "ethernet" in text or "wi-fi" in text or "realtek" in text or "intel" in text:
                self.combo_iface.setCurrentIndex(i)
                break
                
    def toggle_capture(self):
        if not self.is_capturing:
            # Start
            iface = self.combo_iface.currentText()
            print(f"Iniciando captura en: {iface}")
            self.core.start_capture(iface)
            self.is_capturing = True
            
            self.btn_start.setText("Detener Captura")
            self.btn_start.setStyleSheet("background-color: #d32f2f; color: white;")
            self.combo_iface.setEnabled(False)
            
            self.timer.start(100) # Checar C++ cada 100 ms
        else:
            # Stop
            self.timer.stop()
            self.core.stop_capture()
            self.is_capturing = False
            
            self.btn_start.setText("Iniciar Captura")
            self.btn_start.setStyleSheet("background-color: #388e3c; color: white;")
            self.combo_iface.setEnabled(True)
            self.consume_packets() # Vaciar últimos paquetes
            
    def consume_packets(self):
        batch = self.core.get_packet_batch()
        if not batch:
            return
            
        # Evitar sobrecargar la UI deteniendo updates graficos
        self.table.setUpdatesEnabled(False)
        
        for packet in batch:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.packet_count += 1
            
            self.table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
            self.table.setItem(row, 1, QTableWidgetItem(packet.protocol))
            self.table.setItem(row, 2, QTableWidgetItem(packet.src_ip))
            self.table.setItem(row, 3, QTableWidgetItem(str(packet.src_port) if packet.src_port > 0 else "-"))
            self.table.setItem(row, 4, QTableWidgetItem(packet.dst_ip))
            self.table.setItem(row, 5, QTableWidgetItem(str(packet.dst_port) if packet.dst_port > 0 else "-"))
            self.table.setItem(row, 6, QTableWidgetItem(str(packet.length)))
            
            color = QColor("#222222")
            if packet.protocol == "TCP":
                color = QColor("#1b2f42")
            elif packet.protocol == "UDP":
                color = QColor("#2e4024")
                
            for col in range(7):
                self.table.item(row, col).setBackground(color)
                
        # Auto-scroll on append
        self.table.scrollToBottom()
        self.table.setUpdatesEnabled(True)

    def closeEvent(self, event):
        if self.is_capturing:
            self.toggle_capture()
        event.accept()

    def apply_dark_mode(self):
        # QSS Básico y moderno
        dark_stylesheet = """
        QMainWindow {
            background-color: #121212;
        }
        QLabel {
            color: #eeeeee;
            font-size: 14px;
        }
        QPushButton {
            background-color: #388e3c;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #4caf50;
        }
        QComboBox {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #333333;
            padding: 5px;
            border-radius: 4px;
        }
        QTableWidget {
            background-color: #1e1e1e;
            color: #dddddd;
            gridline-color: #333333;
            selection-background-color: #3f51b5;
        }
        QHeaderView::section {
            background-color: #2c2c2c;
            color: white;
            padding: 4px;
            border: 1px solid #333333;
        }
        """
        self.setStyleSheet(dark_stylesheet)
