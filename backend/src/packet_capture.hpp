/**
 * @file packet_capture.hpp
 * @brief Declaración de la clase PacketCapture para la captura de paquetes de red.
 *
 * Esta clase encapsula toda la funcionalidad de Npcap:
 *   - Enumeración de interfaces de red disponibles.
 *   - Inicio/detención de la captura en un hilo independiente.
 *   - Almacenamiento thread-safe de paquetes decodificados.
 *   - Extracción atómica de lotes de paquetes para consumo desde Python.
 *
 * @note El patrón utilizado es Productor-Consumidor:
 *       - Productor: el hilo de captura (C++) escribe en `packet_buffer_`.
 *       - Consumidor: Python llama a `get_packet_batch()` cada ~100 ms.
 *       La sincronización se realiza mediante `std::mutex`.
 */

#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <pcap.h>

#include "protocol_headers.hpp"

/**
 * @class PacketCapture
 * @brief Motor principal de captura de paquetes usando Npcap.
 *
 * Gestiona el ciclo de vida completo de una sesión de captura:
 * apertura de la interfaz, hilo de captura, decodificación de paquetes,
 * almacenamiento thread-safe, y limpieza de recursos.
 */
class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    // Evitar copias accidentales de la clase (recurso no copiable)
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    /**
     * @brief Obtiene la lista de interfaces de red disponibles en el sistema.
     * @return Vector de strings con formato "nombre_dispositivo (descripción)".
     */
    std::vector<std::string> get_interfaces();

    /**
     * @brief Inicia la captura de paquetes en la interfaz especificada.
     *
     * Abre la interfaz con Npcap en modo promiscuo y lanza un hilo
     * independiente que ejecuta el bucle de captura.
     *
     * @param interface_name Nombre de la interfaz (puede incluir descripción).
     */
    void start_capture(const std::string& interface_name);

    /**
     * @brief Detiene la captura de paquetes de forma segura.
     *
     * Interrumpe el bucle de pcap, espera a que el hilo termine (join),
     * y libera el handle de Npcap.
     */
    void stop_capture();

    /**
     * @brief Extrae todos los paquetes almacenados desde la última llamada.
     *
     * Esta operación es atómica (protegida por mutex). Mueve el contenido
     * del buffer interno al vector de retorno, vaciando el buffer.
     *
     * @return Vector de PacketInfo con los paquetes acumulados.
     */
    std::vector<PacketInfo> get_packet_batch();

private:
    std::atomic<bool>        is_running_;       ///< Bandera atómica de estado de captura
    std::thread              capture_thread_;   ///< Hilo dedicado para el bucle de captura
    pcap_t*                  pcap_handle_;      ///< Handle de sesión Npcap

    std::vector<PacketInfo>  packet_buffer_;    ///< Buffer de paquetes (zona crítica)
    std::mutex               buffer_mutex_;     ///< Mutex para proteger el buffer

    /**
     * @brief Bucle principal de captura (ejecutado en hilo separado).
     *
     * Invoca `pcap_loop()` que bloquea hasta que se llame a `pcap_breakloop()`.
     */
    void capture_loop();

    /**
     * @brief Callback estático requerido por la API C de Npcap.
     *
     * Npcap requiere un puntero a función C (sin `this`). Este método
     * estático recibe el puntero a la instancia via `user_data` y
     * delega la lógica al método `process_packet()`.
     */
    static void packet_handler(u_char* user_data,
                               const struct pcap_pkthdr* pkthdr,
                               const u_char* packet);

    /**
     * @brief Decodifica un paquete crudo y lo almacena en el buffer.
     *
     * Analiza las capas Ethernet → IPv4 → TCP/UDP, extrae la información
     * relevante y la encapsula en un PacketInfo.
     *
     * @param pkthdr  Metadatos del paquete (tamaño, timestamp).
     * @param packet  Puntero a los bytes crudos del paquete.
     */
    void process_packet(const struct pcap_pkthdr* pkthdr,
                        const u_char* packet);
};
