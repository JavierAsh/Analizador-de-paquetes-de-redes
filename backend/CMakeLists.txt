cmake_minimum_required(VERSION 3.15)
project(SnifferCore VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch pybind11
include(FetchContent)
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v2.13.6
)
set(PYBIND11_FINDPYTHON ON)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
FetchContent_MakeAvailable(pybind11)

# Npcap config
if(NOT NPCAP_SDK_DIR)
    set(NPCAP_SDK_DIR "C:/Npcap-SDK" CACHE PATH "Path to Npcap SDK")
endif()

message(STATUS "Usando Npcap SDK desde: ${NPCAP_SDK_DIR}")

if(EXISTS "${NPCAP_SDK_DIR}/Include")
    include_directories(${NPCAP_SDK_DIR}/Include)
else()
    message(WARNING "El directorio Include de Npcap no se encontro en ${NPCAP_SDK_DIR}/Include")
endif()

if(EXISTS "${NPCAP_SDK_DIR}/Lib/x64")
    link_directories(${NPCAP_SDK_DIR}/Lib/x64)
else()
    message(WARNING "El directorio Lib/x64 de Npcap no se encontro en ${NPCAP_SDK_DIR}/Lib/x64")
endif()

# Create module
pybind11_add_module(sniffer_core src/core.cpp src/packet_capture.cpp)

# Link wpcap and Packet (Librerias de Npcap)
# Windows sockets implementation is needed (ws2_32)
target_link_libraries(sniffer_core PRIVATE wpcap Packet ws2_32)
