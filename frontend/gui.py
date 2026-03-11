"""
gui.py — Interfaz gráfica principal del Analizador de Paquetes.

Implementa una ventana de tres paneles estilo Wireshark:
  1. Tabla superior:  Lista de paquetes capturados en tiempo real.
  2. Árbol central:   Detalles decodificados por capa OSI del paquete seleccionado.
  3. Visor inferior:  Dump hexadecimal de los bytes crudos del paquete.

Incluye filtrado por protocolo, barra de estado con contador,
y tema oscuro (Dark Mode) moderno.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QStatusBar, QTreeWidget, QTreeWidgetItem,
    QTextEdit
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor, QFont

import sniffer_core


# =============================================================================
# CONSTANTES
# =============================================================================

_KEYWORDS_INTERFAZ_FISICA = ("ethernet", "wi-fi", "realtek", "intel", "broadcom")

_COLOR_TCP     = QColor("#1b2f42")
_COLOR_UDP     = QColor("#2e4024")
_COLOR_DEFAULT = QColor("#222222")

_TIMER_INTERVAL_MS = 100

_FUENTE_MONO = QFont("Consolas", 10)

_DARK_THEME_QSS = """
QMainWindow {
    background-color: #121212;
}
QLabel {
    color: #eeeeee;
    font-size: 13px;
}
QPushButton {
    background-color: #388e3c;
    color: white;
    border: none;
    padding: 7px 14px;
    border-radius: 4px;
    font-size: 13px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #4caf50;
}
QPushButton:disabled {
    background-color: #555555;
    color: #999999;
}
QComboBox {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    padding: 5px;
    border-radius: 4px;
    font-size: 13px;
}
QComboBox QAbstractItemView {
    background-color: #2c2c2c;
    color: #ffffff;
    selection-background-color: #3f51b5;
}
QTableWidget {
    background-color: #1e1e1e;
    color: #dddddd;
    gridline-color: #333333;
    selection-background-color: #3f51b5;
    font-size: 12px;
}
QHeaderView::section {
    background-color: #2c2c2c;
    color: white;
    padding: 4px;
    border: 1px solid #333333;
    font-weight: bold;
}
QTreeWidget {
    background-color: #1a1a1a;
    color: #cccccc;
    border: 1px solid #333333;
    font-size: 12px;
}
QTreeWidget::item:selected {
    background-color: #3f51b5;
}
QTextEdit {
    background-color: #0a0a0a;
    color: #66bb6a;
    border: 1px solid #333333;
    font-size: 11px;
}
QStatusBar {
    background-color: #1a1a1a;
    color: #aaaaaa;
    font-size: 12px;
}
QSplitter::handle {
    background-color: #333333;
    height: 3px;
}
"""


# =============================================================================
# VENTANA PRINCIPAL
# =============================================================================

class SnifferApp(QMainWindow):
    """
    Ventana principal del Analizador de Paquetes de Red.

    Layout de tres paneles verticales (estilo Wireshark):
      - Panel 1: Tabla de paquetes capturados.
      - Panel 2: Árbol de detalles por capa OSI.
      - Panel 3: Visor hexadecimal de bytes crudos.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analizador de Paquetes — Pybind11 & Npcap")
        self.resize(1200, 750)

        self._core = sniffer_core.PacketCapture()
        self._is_capturing = False
        self._packet_count = 0
        self._packets = []           # Almacén local de paquetes para inspección
        self._filtered_indices = []  # Índices visibles tras filtrado

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._consume_packets)

        self._init_ui()
        self._populate_interfaces()
        self.setStyleSheet(_DARK_THEME_QSS)

    # =========================================================================
    # CONSTRUCCIÓN DE LA INTERFAZ
    # =========================================================================

    def _init_ui(self):
        """Construye los tres paneles y la barra de controles."""
        contenedor = QWidget()
        self.setCentralWidget(contenedor)
        layout_principal = QVBoxLayout(contenedor)
        layout_principal.setContentsMargins(6, 6, 6, 6)
        layout_principal.setSpacing(4)

        # --- Barra superior de controles ---
        barra = QHBoxLayout()
        barra.setSpacing(8)

        barra.addWidget(QLabel("Interfaz:"))
        self._combo_interfaz = QComboBox()
        self._combo_interfaz.setMinimumWidth(400)
        barra.addWidget(self._combo_interfaz)

        self._btn_captura = QPushButton("▶  Iniciar Captura")
        self._btn_captura.clicked.connect(self._toggle_capture)
        self._btn_captura.setMinimumWidth(155)
        barra.addWidget(self._btn_captura)

        # Filtro de protocolo
        barra.addWidget(QLabel("Filtro:"))
        self._combo_filtro = QComboBox()
        self._combo_filtro.addItems(["Todos", "TCP", "UDP"])
        self._combo_filtro.currentTextChanged.connect(self._apply_filter)
        self._combo_filtro.setMinimumWidth(80)
        barra.addWidget(self._combo_filtro)

        self._btn_limpiar = QPushButton("🗑 Limpiar")
        self._btn_limpiar.clicked.connect(self._clear_table)
        barra.addWidget(self._btn_limpiar)

        barra.addStretch()
        layout_principal.addLayout(barra)

        # --- Splitter vertical con 3 paneles ---
        self._splitter = QSplitter(Qt.Orientation.Vertical)

        # Panel 1: Tabla de paquetes
        columnas = [
            "No.", "Hora", "Protocolo",
            "IP Origen", "Puerto Orig.",
            "IP Destino", "Puerto Dest.",
            "Longitud", "Info"
        ]
        self._tabla = QTableWidget(0, len(columnas))
        self._tabla.setHorizontalHeaderLabels(columnas)
        header = self._tabla.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for col_fijo in (0, 1, 2, 7):
            header.setSectionResizeMode(col_fijo, QHeaderView.ResizeMode.ResizeToContents)
        self._tabla.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tabla.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabla.verticalHeader().setVisible(False)
        self._tabla.currentCellChanged.connect(self._on_packet_selected)
        self._splitter.addWidget(self._tabla)

        # Panel 2: Árbol de detalles por capa
        self._tree_detalles = QTreeWidget()
        self._tree_detalles.setHeaderLabels(["Campo", "Valor"])
        self._tree_detalles.setColumnWidth(0, 280)
        self._tree_detalles.setRootIsDecorated(True)
        self._tree_detalles.setAlternatingRowColors(False)
        self._splitter.addWidget(self._tree_detalles)

        # Panel 3: Visor hexadecimal
        self._hex_viewer = QTextEdit()
        self._hex_viewer.setReadOnly(True)
        self._hex_viewer.setFont(_FUENTE_MONO)
        self._hex_viewer.setPlaceholderText(
            "Selecciona un paquete para ver el dump hexadecimal..."
        )
        self._splitter.addWidget(self._hex_viewer)

        # Proporciones iniciales de los paneles (60% tabla, 25% árbol, 15% hex)
        self._splitter.setSizes([420, 180, 110])
        layout_principal.addWidget(self._splitter)

        # --- Barra de estado ---
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("Listo — Selecciona una interfaz y presiona Iniciar Captura")

    # =========================================================================
    # INTERFACES DE RED
    # =========================================================================

    def _populate_interfaces(self):
        """Llena el combo box con las interfaces detectadas por Npcap."""
        interfaces = self._core.get_interfaces()
        if not interfaces:
            self._combo_interfaz.addItem("⚠ No se encontraron interfaces")
            self._btn_captura.setEnabled(False)
            return

        for iface in interfaces:
            self._combo_interfaz.addItem(iface)

        for i in range(self._combo_interfaz.count()):
            texto = self._combo_interfaz.itemText(i).lower()
            if any(kw in texto for kw in _KEYWORDS_INTERFAZ_FISICA):
                self._combo_interfaz.setCurrentIndex(i)
                break

    # =========================================================================
    # CONTROL DE CAPTURA
    # =========================================================================

    def _toggle_capture(self):
        if not self._is_capturing:
            self._start_capture()
        else:
            self._stop_capture()

    def _start_capture(self):
        self._core.start_capture(self._combo_interfaz.currentText())
        self._is_capturing = True
        self._btn_captura.setText("⏹  Detener Captura")
        self._btn_captura.setStyleSheet("background-color: #d32f2f; color: white;")
        self._combo_interfaz.setEnabled(False)
        self._btn_limpiar.setEnabled(False)
        self._status_bar.showMessage("Capturando paquetes...")
        self._timer.start(_TIMER_INTERVAL_MS)

    def _stop_capture(self):
        self._timer.stop()
        self._core.stop_capture()
        self._is_capturing = False
        self._consume_packets()
        self._btn_captura.setText("▶  Iniciar Captura")
        self._btn_captura.setStyleSheet("background-color: #388e3c; color: white;")
        self._combo_interfaz.setEnabled(True)
        self._btn_limpiar.setEnabled(True)
        self._status_bar.showMessage(
            f"Captura detenida — {self._packet_count} paquetes capturados"
        )

    # =========================================================================
    # CONSUMO DE PAQUETES
    # =========================================================================

    def _consume_packets(self):
        """Extrae paquetes del buffer C++ y los agrega a la tabla."""
        batch = self._core.get_packet_batch()
        if not batch:
            return

        filtro = self._combo_filtro.currentText()
        self._tabla.setUpdatesEnabled(False)

        for paquete in batch:
            idx = len(self._packets)
            self._packets.append(paquete)
            self._packet_count += 1

            # Respetar filtro activo
            if filtro != "Todos" and paquete.protocol != filtro:
                continue

            self._filtered_indices.append(idx)
            self._insert_packet_row(paquete)

        self._tabla.scrollToBottom()
        self._tabla.setUpdatesEnabled(True)
        self._status_bar.showMessage(f"Capturando... {self._packet_count} paquetes")

    def _insert_packet_row(self, paquete):
        """Inserta una fila en la tabla para un paquete dado."""
        fila = self._tabla.rowCount()
        self._tabla.insertRow(fila)

        # Columna "Info": resumen breve estilo Wireshark
        info_text = self._build_info_text(paquete)

        celdas = [
            str(self._packet_count),
            paquete.timestamp,
            paquete.protocol,
            paquete.src_ip,
            str(paquete.src_port) if paquete.src_port > 0 else "—",
            paquete.dst_ip,
            str(paquete.dst_port) if paquete.dst_port > 0 else "—",
            str(paquete.length),
            info_text,
        ]

        color = _COLOR_DEFAULT
        if paquete.protocol == "TCP":
            color = _COLOR_TCP
        elif paquete.protocol == "UDP":
            color = _COLOR_UDP

        for col, texto in enumerate(celdas):
            item = QTableWidgetItem(texto)
            item.setBackground(color)
            self._tabla.setItem(fila, col, item)

    @staticmethod
    def _build_info_text(paquete):
        """Construye un texto resumen estilo Wireshark para la columna Info."""
        if paquete.protocol == "TCP":
            return (
                f"{paquete.src_port} → {paquete.dst_port} "
                f"[{paquete.tcp_flags}] "
                f"Seq={paquete.tcp_seq} Ack={paquete.tcp_ack} "
                f"Win={paquete.tcp_window}"
            )
        elif paquete.protocol == "UDP":
            return (
                f"{paquete.src_port} → {paquete.dst_port} "
                f"Len={paquete.udp_length}"
            )
        return ""

    # =========================================================================
    # PANEL DE DETALLES (ESTILO WIRESHARK)
    # =========================================================================

    def _on_packet_selected(self, current_row, _col, _prev_row, _prev_col):
        """Callback cuando el usuario selecciona una fila en la tabla."""
        if current_row < 0 or current_row >= len(self._filtered_indices):
            return

        idx = self._filtered_indices[current_row]
        if idx >= len(self._packets):
            return

        paquete = self._packets[idx]
        self._fill_detail_tree(paquete)
        self._fill_hex_viewer(paquete)

    def _fill_detail_tree(self, paquete):
        """Llena el árbol de detalles con la información decodificada por capa."""
        self._tree_detalles.clear()

        # --- Capa 2: Ethernet ---
        eth_node = QTreeWidgetItem(self._tree_detalles,
                                   ["▸ Ethernet II", ""])
        eth_node.setExpanded(True)
        eth_node.setForeground(0, QColor("#82b1ff"))
        QTreeWidgetItem(eth_node, ["MAC Destino", paquete.dst_mac])
        QTreeWidgetItem(eth_node, ["MAC Origen", paquete.src_mac])
        QTreeWidgetItem(eth_node, ["Tipo", f"0x{paquete.ether_type:04X} (IPv4)"])

        # --- Capa 3: IPv4 ---
        ip_node = QTreeWidgetItem(self._tree_detalles,
                                  ["▸ Internet Protocol v4", ""])
        ip_node.setExpanded(True)
        ip_node.setForeground(0, QColor("#c5e1a5"))
        QTreeWidgetItem(ip_node, ["Versión", str(paquete.ip_version)])
        QTreeWidgetItem(ip_node, ["Longitud de Cabecera", f"{paquete.ip_header_len} bytes"])
        QTreeWidgetItem(ip_node, ["Longitud Total", f"{paquete.length} bytes"])
        QTreeWidgetItem(ip_node, ["Tiempo de Vida (TTL)", str(paquete.ttl)])
        proto_name = {6: "TCP (6)", 17: "UDP (17)"}.get(paquete.ip_protocol,
                                                         str(paquete.ip_protocol))
        QTreeWidgetItem(ip_node, ["Protocolo", proto_name])
        QTreeWidgetItem(ip_node, ["IP Origen", paquete.src_ip])
        QTreeWidgetItem(ip_node, ["IP Destino", paquete.dst_ip])

        # --- Capa 4: TCP o UDP ---
        if paquete.protocol == "TCP":
            tcp_node = QTreeWidgetItem(self._tree_detalles,
                                       ["▸ Transmission Control Protocol", ""])
            tcp_node.setExpanded(True)
            tcp_node.setForeground(0, QColor("#ffcc80"))
            QTreeWidgetItem(tcp_node, ["Puerto Origen", str(paquete.src_port)])
            QTreeWidgetItem(tcp_node, ["Puerto Destino", str(paquete.dst_port)])
            QTreeWidgetItem(tcp_node, ["Número de Secuencia", str(paquete.tcp_seq)])
            QTreeWidgetItem(tcp_node, ["Número de ACK", str(paquete.tcp_ack)])
            QTreeWidgetItem(tcp_node, ["Flags", paquete.tcp_flags])
            QTreeWidgetItem(tcp_node, ["Tamaño de Ventana", str(paquete.tcp_window)])

        elif paquete.protocol == "UDP":
            udp_node = QTreeWidgetItem(self._tree_detalles,
                                       ["▸ User Datagram Protocol", ""])
            udp_node.setExpanded(True)
            udp_node.setForeground(0, QColor("#b39ddb"))
            QTreeWidgetItem(udp_node, ["Puerto Origen", str(paquete.src_port)])
            QTreeWidgetItem(udp_node, ["Puerto Destino", str(paquete.dst_port)])
            QTreeWidgetItem(udp_node, ["Longitud", f"{paquete.udp_length} bytes"])

    def _fill_hex_viewer(self, paquete):
        """
        Genera un dump hexadecimal estilo Wireshark de los bytes crudos.

        Formato por línea:
          OFFSET   HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  |ASCII REPR.|
        """
        raw = paquete.raw_bytes
        if not raw:
            self._hex_viewer.setPlainText("(sin datos crudos disponibles)")
            return

        lines = []
        bytes_per_line = 16

        for offset in range(0, len(raw), bytes_per_line):
            chunk = raw[offset:offset + bytes_per_line]

            # Offset
            offset_str = f"{offset:08X}"

            # Hexadecimal con separador en el medio
            hex_parts = []
            for i, b in enumerate(chunk):
                hex_parts.append(f"{b:02X}")
                if i == 7:
                    hex_parts.append("")  # Espacio extra en el medio
            hex_str = " ".join(hex_parts).ljust(49)

            # Representación ASCII (reemplazar no-imprimibles con '.')
            ascii_str = ""
            for b in chunk:
                ascii_str += chr(b) if 32 <= b < 127 else "."

            lines.append(f"{offset_str}   {hex_str}  |{ascii_str}|")

        self._hex_viewer.setPlainText("\n".join(lines))

    # =========================================================================
    # FILTRADO
    # =========================================================================

    def _apply_filter(self, filtro_texto):
        """Reconstruye la tabla aplicando el filtro de protocolo seleccionado."""
        self._tabla.setUpdatesEnabled(False)
        self._tabla.setRowCount(0)
        self._filtered_indices.clear()

        count = 0
        for idx, paquete in enumerate(self._packets):
            if filtro_texto != "Todos" and paquete.protocol != filtro_texto:
                continue
            self._filtered_indices.append(idx)
            count += 1
            fila = self._tabla.rowCount()
            self._tabla.insertRow(fila)
            info_text = self._build_info_text(paquete)
            celdas = [
                str(count),
                paquete.timestamp,
                paquete.protocol,
                paquete.src_ip,
                str(paquete.src_port) if paquete.src_port > 0 else "—",
                paquete.dst_ip,
                str(paquete.dst_port) if paquete.dst_port > 0 else "—",
                str(paquete.length),
                info_text,
            ]
            color = _COLOR_DEFAULT
            if paquete.protocol == "TCP":
                color = _COLOR_TCP
            elif paquete.protocol == "UDP":
                color = _COLOR_UDP
            for col, texto in enumerate(celdas):
                item = QTableWidgetItem(texto)
                item.setBackground(color)
                self._tabla.setItem(fila, col, item)

        self._tabla.setUpdatesEnabled(True)
        self._tree_detalles.clear()
        self._hex_viewer.clear()
        self._status_bar.showMessage(
            f"Mostrando {count} de {len(self._packets)} paquetes (filtro: {filtro_texto})"
        )

    # =========================================================================
    # UTILIDADES
    # =========================================================================

    def _clear_table(self):
        """Limpia todos los paquetes almacenados y reinicia la interfaz."""
        self._tabla.setRowCount(0)
        self._packets.clear()
        self._filtered_indices.clear()
        self._packet_count = 0
        self._tree_detalles.clear()
        self._hex_viewer.clear()
        self._status_bar.showMessage("Tabla limpiada")

    def closeEvent(self, event):
        """Detiene la captura antes de cerrar la ventana."""
        if self._is_capturing:
            self._stop_capture()
        event.accept()
