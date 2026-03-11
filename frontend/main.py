import sys
import os

# Determinar el directorio donde se encuentra el backend compilado
backend_build_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend', 'build'))

sys.path.append(os.path.join(backend_build_dir, 'Release'))
sys.path.append(os.path.join(backend_build_dir, 'Debug'))
sys.path.append(backend_build_dir) 

if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
    try:
        os.add_dll_directory("C:/msys64/mingw64/bin")
    except Exception as e:
        pass

try:
    import sniffer_core
except ImportError as e:
    print(f"Error importando sniffer_core: {e}")
    print("Asegúrate de haber compilado el backend C++ ejecutando CMake.")
    print(f"Rutas buscadas: {sys.path[-3:]}")
    sys.exit(1)

def main():
    print("Iniciando Analizador de Paquetes (Python Frontend)...")
    try:
        mensaje = sniffer_core.hello_world()
        print(f"Mensaje del core C++: {mensaje}")
    except Exception as e:
        print(f"Error ejecutando hello_world(): {e}")

if __name__ == '__main__':
    main()
