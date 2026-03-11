import sys
import os
import time

backend_build_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend', 'build'))
sys.path.append(os.path.join(backend_build_dir, 'Release'))
sys.path.append(os.path.join(backend_build_dir, 'Debug'))
sys.path.append(backend_build_dir) 

if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
    try:
        os.add_dll_directory("C:/msys64/mingw64/bin")
    except Exception:
        pass

try:
    import sniffer_core
except ImportError as e:
    print(f"Error importando sniffer_core: {e}")
    sys.exit(1)

def main():
    print("Iniciando aplicación PyQt6...")
    try:
        from PyQt6.QtWidgets import QApplication
        from gui import SnifferApp
        
        app = QApplication(sys.argv)
        window = SnifferApp()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error fatal iniciando UI: {e}")

if __name__ == '__main__':
    main()
