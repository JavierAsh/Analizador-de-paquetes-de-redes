"""
main.py — Punto de entrada principal de la aplicación.

Este módulo se encarga de:
  1. Configurar las rutas de búsqueda para localizar el módulo C++ compilado.
  2. Registrar los directorios de DLLs necesarios en Windows (MinGW).
  3. Importar el módulo nativo `sniffer_core` (compilado con Pybind11).
  4. Inicializar la aplicación PyQt6 y mostrar la ventana principal.

Ejecución:
    python frontend/main.py

Nota:
    Se requiere ejecutar como Administrador para que Npcap pueda
    acceder a las interfaces de red en modo promiscuo.
"""

import sys
import os

# =============================================================================
# CONFIGURACIÓN DE RUTAS PARA EL MÓDULO C++
# =============================================================================

# Agregar las posibles rutas donde se encuentra el módulo compilado (.pyd)
_backend_build_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'backend', 'build')
)
for _subdir in ('Release', 'Debug', ''):
    _path = os.path.join(_backend_build_dir, _subdir) if _subdir else _backend_build_dir
    if _path not in sys.path:
        sys.path.append(_path)

# En Windows, registrar el directorio de DLLs de MinGW si está disponible
if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
    _mingw_paths = [
        "C:/msys64/mingw64/bin",
        "C:/msys64/ucrt64/bin",
    ]
    for _dll_path in _mingw_paths:
        if os.path.isdir(_dll_path):
            try:
                os.add_dll_directory(_dll_path)
            except OSError:
                pass

# =============================================================================
# IMPORTACIÓN DEL MÓDULO NATIVO
# =============================================================================

try:
    import sniffer_core  # noqa: F401 — se usa indirectamente en gui.py
except ImportError as e:
    print(
        f"[Error] No se pudo importar el módulo C++ 'sniffer_core': {e}\n"
        f"  Asegúrate de haber compilado el backend con CMake primero.\n"
        f"  Rutas buscadas: {_backend_build_dir}"
    )
    sys.exit(1)


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def main():
    """Inicializa la aplicación PyQt6 y muestra la ventana del analizador."""
    from PyQt6.QtWidgets import QApplication
    from gui import SnifferApp

    app = QApplication(sys.argv)
    app.setApplicationName("Analizador de Paquetes")
    app.setApplicationVersion("1.0.0")

    ventana = SnifferApp()
    ventana.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
