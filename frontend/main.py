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
    print("Iniciando Fase 2: Prueba de captura (Python Frontend)...")
    
    cap = sniffer_core.PacketCapture()
    
    interfaces = cap.get_interfaces()
    if not interfaces:
        print("No se encontraron interfaces de red Npcap válidas. Instalaste o corriste el script como admin?")
        return
    
    print("Interfaces Npcap disponibles:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
        
    # Buscar una interfaz que suene a tarjeta de red física o Loopback activo
    selected_idx = 0
    for i, iface in enumerate(interfaces):
        iname = iface.lower()
        if "ethernet" in iname or "wi-fi" in iname or "realtek" in iname or "intel" in iname:
            selected_idx = i
            break
        elif "loopback" in iname: # Fallback a loopback si no encuentra una física
            selected_idx = i
    
    # Force selection of Realtek (index 4 in previous run) if available to guarantee physical egress traffic
    for i, iface in enumerate(interfaces):
        if "realtek" in iface.lower():
            selected_idx = i
            break
            
    iface_to_use = interfaces[selected_idx]
    
    print(f"\nIniciando captura en la interfaz seleccionada por 5 segundos: {iface_to_use}")
    
    cap.start_capture(iface_to_use)
    
    # Generar tráfico intencionalmente
    try:
        import urllib.request
        print("Enviando petición HTTP para forzar tráfico...")
        urllib.request.urlopen("http://example.com", timeout=2)
    except Exception as e:
        print(f"Error en petición HTTP de prueba (ignorando): {e}")
        
    time.sleep(4)
    
    cap.stop_capture()
    print("Prueba de Fase 2 completada.")

if __name__ == '__main__':
    main()
