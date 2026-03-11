# Contexto del Proyecto: Analizador de Paquetes (Sniffer)

## Arquitectura

- **Backend:** Desarrollado estrictamente en C++. Se encarga de la captura de red a bajo nivel utilizando el SDK de Npcap.
- **Frontend:** Desarrollado en Python. Se encarga de la interfaz gráfica utilizando PyQt6 y del procesamiento visual de los datos.
- **Integración:** C++ y Python se comunican mediante la librería Pybind11. El código C++ se compilará como un módulo dinámico (.pyd en Windows) que Python importará.

## Reglas para la generación de código

1. Todo el código de inspección de paquetes (capas OSI, extracción de IPs y puertos) debe generarse en C++ por razones de rendimiento.
2. Al generar código C++, prioriza la gestión segura de la memoria y evita las fugas de memoria (memory leaks), ya que estaremos procesando miles de paquetes por segundo.
3. La interfaz en Python debe tener un diseño moderno (Dark Mode) y no debe bloquearse mientras el motor C++ captura datos en segundo plano.
4. El sistema de compilación oficial del proyecto es CMake.
