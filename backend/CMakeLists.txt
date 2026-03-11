# ==============================================================================
# CMakeLists.txt — Sistema de compilación del motor de captura (Backend C++)
# ==============================================================================
#
# Este archivo configura CMake para compilar el módulo de extensión Python
# `sniffer_core` (.pyd) que integra:
#   - Pybind11 (descargado automáticamente via FetchContent)
#   - Npcap SDK (ruta configurable, por defecto C:/Npcap-SDK)
#   - Winsock2 (ws2_32) para funciones de red como ntohs()
#
# Uso:
#   cd backend && mkdir build && cd build
#   cmake .. -G "MinGW Makefiles" -DNPCAP_SDK_DIR="C:/Npcap-SDK"
#   cmake --build . --config Release
#
# ==============================================================================

cmake_minimum_required(VERSION 3.15)
project(SnifferCore
    VERSION     1.0.0
    DESCRIPTION "Motor de captura de paquetes de red con Npcap y Pybind11"
    LANGUAGES   CXX
)

# Estándar C++17 obligatorio (requerido por Pybind11 y std::optional, etc.)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==============================================================================
# Dependencia: Pybind11 (descarga automática desde GitHub)
# ==============================================================================
include(FetchContent)
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.13.6
)
set(PYBIND11_FINDPYTHON ON)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
FetchContent_MakeAvailable(pybind11)

# ==============================================================================
# Dependencia: Npcap SDK
# ==============================================================================
if(NOT NPCAP_SDK_DIR)
    set(NPCAP_SDK_DIR "C:/Npcap-SDK" CACHE PATH "Ruta al directorio del Npcap SDK")
endif()

message(STATUS "Usando Npcap SDK desde: ${NPCAP_SDK_DIR}")

# Verificar que existan los directorios del SDK
if(EXISTS "${NPCAP_SDK_DIR}/Include")
    include_directories(${NPCAP_SDK_DIR}/Include)
else()
    message(FATAL_ERROR "No se encontró ${NPCAP_SDK_DIR}/Include — verifica la ruta del Npcap SDK")
endif()

if(EXISTS "${NPCAP_SDK_DIR}/Lib/x64")
    link_directories(${NPCAP_SDK_DIR}/Lib/x64)
else()
    message(FATAL_ERROR "No se encontró ${NPCAP_SDK_DIR}/Lib/x64 — verifica la ruta del Npcap SDK")
endif()

# ==============================================================================
# Módulo de extensión Python (.pyd)
# ==============================================================================
pybind11_add_module(sniffer_core
    src/core.cpp
    src/packet_capture.cpp
)

# Enlazar las librerías de Npcap y Winsock2
target_link_libraries(sniffer_core PRIVATE
    wpcap       # Librería principal de captura de Npcap
    Packet      # Librería de acceso a paquetes de Npcap
    ws2_32      # Windows Sockets 2 (ntohs, htons, etc.)
)
