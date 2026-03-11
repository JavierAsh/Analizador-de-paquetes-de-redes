# Fase 1: Planificación e Infraestructura

Se creará la estructura base del proyecto para cumplir con los requerimientos técnicos descritos en el documento, estableciendo el puente de comunicación entre C++ y Python.

## User Review Required
> [!IMPORTANT]
> - ¿El SDK de Npcap ya está descargado en alguna ruta específica de tu sistema (ej. `C:/Npcap-SDK`)? En el `CMakeLists.txt` propuesto usaremos una variable `NPCAP_SDK_DIR` que podrías necesitar ajustar.
> - Descargaremos `pybind11` automáticamente a través de `FetchContent` en CMake para facilitar la compilación.

## Proposed Changes

### Estructura de Directorios
Se construirá el siguiente esqueleto de directorios:
```text
C:\Analizador de paquetes de redes\
├── backend\
│   ├── src\
│   │   └── core.cpp       # Código C++ con Pybind11
│   └── CMakeLists.txt     # Configuración de compilación para C++
└── frontend\
    └── main.py            # Script en Python que importa el módulo C++
```

### [backend]
#### [NEW] [CMakeLists.txt](file:///c:/Analizador de paquetes de redes/backend/CMakeLists.txt)
Archivo de compilación oficial del proyecto. Descargará Pybind11, buscará el SDK de Npcap y generará el módulo `.pyd` dinámico que Python importará.

#### [NEW] [core.cpp](file:///c:/Analizador de paquetes de redes/backend/src/core.cpp)
Archivo C++ que expondrá una función `hello_world()` usando Pybind11 para demostrar la conexión.

### [frontend]
#### [NEW] [main.py](file:///c:/Analizador de paquetes de redes/frontend/main.py)
Añadirá la ruta del módulo compilado a `sys.path`, importará `sniffer_core` y ejecutará la función `hello_world()` escrita en C++.

## Verification Plan

### Manual Verification
1. Compilar el backend C++:
   ```cmd
   cd backend
   mkdir build && cd build
   cmake .. -DNPCAP_SDK_DIR="Ruta/Al/SDK"
   cmake --build . --config Release
   ```
2. Ejecutar la prueba de Python:
   ```cmd
   python frontend\main.py
   ```
   Se debe observar en la consola el mensaje generado desde C++, probando que el puente Pybind11 funciona correctamente.
