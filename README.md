# 🌐 Analizador de Paquetes de Redes (Sniffer)

> Herramienta de análisis de tráfico de red en tiempo real para Windows, con inspección profunda de paquetes estilo Wireshark. Motor de alto rendimiento en **C++** (Npcap) e interfaz gráfica moderna en **Python** (PyQt6).

---

## 📸 Características

| Característica | Detalle |
| --- | --- |
| **Captura en tiempo real** | Motor C++ multihilo que captura paquetes sin bloquear la interfaz |
| **Decodificación completa** | Ethernet (MAC), IPv4 (TTL, IHL), TCP (Seq, Ack, Flags), UDP |
| **Inspección estilo Wireshark** | Árbol de protocolos por capa OSI + visor hexadecimal |
| **Filtrado por protocolo** | TCP, UDP o Todos — en tiempo real |
| **Interfaz de 3 paneles** | Tabla de paquetes ↕ Detalle por capas ↕ Dump hexadecimal |
| **Columna Info** | Resumen tipo Wireshark (flags, seq, ack, ventana) |
| **Dark Mode** | Tema oscuro moderno con colores por protocolo |
| **Ejecutable standalone** | Empaquetado con PyInstaller como `.exe` portátil |
| **Elevación UAC** | Solicita permisos de administrador automáticamente |

---

## 🏗️ Arquitectura

```text
┌──────────────────────────────────────────────────────────────┐
│                  Frontend (Python / PyQt6)                     │
│  ┌──────────┐  ┌─────────────────────────────────────────┐   │
│  │ main.py  │  │  gui.py                                 │   │
│  │ (entrada)│  │  ┌──────────────────────────────────┐   │   │
│  └────┬─────┘  │  │ Panel 1: Tabla de paquetes       │   │   │
│       │        │  ├──────────────────────────────────┤   │   │
│       │        │  │ Panel 2: Árbol de detalles (OSI) │   │   │
│       │        │  ├──────────────────────────────────┤   │   │
│       │        │  │ Panel 3: Visor hexadecimal       │   │   │
│       │        │  └──────────────────────────────────┘   │   │
│       │        └──────────────────┬──────────────────────┘   │
│       └───────────────────────────┤ QTimer 100ms             │
├───────────────────────────────────┼──────────────────────────┤
│                    Pybind11       │                           │
├───────────────────────────────────┼──────────────────────────┤
│                 Backend (C++ / Npcap)                         │
│  ┌────────────────┐  ┌───────────────────┐  ┌────────────┐  │
│  │ core.cpp       │  │ packet_capture    │  │ protocol   │  │
│  │ (wrapper)      │  │ .cpp / .hpp       │  │ headers    │  │
│  └────────────────┘  └───────────────────┘  └────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 Requisitos Previos

| Componente | Versión mínima | Enlace |
| --- | --- | --- |
| **Windows** | 10 / 11 | — |
| **Python** | 3.10+ | [python.org](https://www.python.org/) |
| **CMake** | 3.15+ | [cmake.org](https://cmake.org/) |
| **Compilador C++** | MinGW-w64 / MSVC | [MSYS2](https://www.msys2.org/) |
| **Npcap SDK** | 1.13+ | [npcap.com](https://npcap.com/#download) |
| **Npcap Driver** | Instalado en el sistema | [npcap.com](https://npcap.com/#download) |

### Dependencias Python

```bash
pip install PyQt6
```

---

## 🚀 Compilación y Ejecución

### 1. Compilar el motor C++

```bash
cd backend
mkdir build && cd build
cmake .. -G "Ninja" -DNPCAP_SDK_DIR="C:/Npcap-SDK"
cmake --build . --config Release
```

### 2. Ejecutar la aplicación

```bash
python frontend/main.py
```

> **⚠ Se requiere ejecutar como Administrador** para que Npcap pueda acceder a las interfaces de red en modo promiscuo.

### 3. Generar el ejecutable (.exe)

```bash
pip install pyinstaller
cd frontend
pyinstaller --noconfirm --onefile --windowed ^
  --add-binary "../backend/build/sniffer_core.*.pyd;." ^
  --manifest "sniffer.manifest" ^
  --name "AnalizadorDeRedes" main.py
```

El ejecutable estará en `frontend/dist/AnalizadorDeRedes.exe`.

---

## 📁 Estructura del Proyecto

```text
├── backend/                        # Motor de captura (C++)
│   ├── CMakeLists.txt              # Sistema de compilación CMake
│   └── src/
│       ├── core.cpp                # Wrapper Pybind11
│       ├── packet_capture.cpp      # Lógica de captura y decodificación
│       ├── packet_capture.hpp      # Declaraciones de la clase
│       └── protocol_headers.hpp    # Structs de protocolos + DTO
├── frontend/                       # Interfaz gráfica (Python)
│   ├── main.py                     # Punto de entrada de la aplicación
│   ├── gui.py                      # Ventana principal con 3 paneles
│   ├── sniffer.manifest            # Manifiesto UAC de Windows
│   └── AnalizadorDeRedes.spec      # Configuración de PyInstaller
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🔧 Detalles Técnicos

### Patrón Productor-Consumidor

El motor C++ captura paquetes en un hilo dedicado y los almacena en un `std::vector<PacketInfo>` protegido con `std::mutex`. Python consume estos datos cada 100 ms mediante un `QTimer`, evitando bloqueos en la interfaz gráfica.

### Optimizaciones de Rendimiento

- **`snprintf`** en lugar de `std::stringstream` para formatear IPs y MACs.
- **`emplace_back(std::move())`** para evitar copias de structs.
- **`setUpdatesEnabled(False)`** durante inserciones masivas en la tabla.
- **Bytes crudos** se copian una sola vez para el visor hexadecimal.

---

## 🔒 Notas de Seguridad

- La captura en **modo promiscuo** requiere permisos de administrador.
- El ejecutable incluye un **manifiesto UAC** que solicita elevación de privilegios automáticamente.
- Algunos antivirus pueden marcarlo como falso positivo. Agrega una excepción si es necesario.

---

## 📄 Licencia

Licenciado bajo la [Licencia MIT](LICENSE).
