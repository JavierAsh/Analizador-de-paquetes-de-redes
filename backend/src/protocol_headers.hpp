/**
 * @file protocol_headers.hpp
 * @brief Definiciones de cabeceras de protocolos de red y DTO de transferencia.
 *
 * Contiene los structs empaquetados que mapean directamente los bytes crudos
 * recibidos desde Npcap, y la estructura PacketInfo que transfiere datos
 * decodificados al frontend Python a través de Pybind11.
 *
 * Protocolos soportados:
 *   - Capa 2 (Enlace):     Ethernet II
 *   - Capa 3 (Red):        IPv4
 *   - Capa 4 (Transporte): TCP, UDP
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// CABECERAS DE PROTOCOLOS DE RED (empaquetadas sin padding)
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Cabecera Ethernet II (Capa 2 - Enlace de Datos). Tamaño: 14 bytes.
 */
struct EthernetHeader {
    uint8_t  dest_mac[6];   ///< Dirección MAC destino
    uint8_t  src_mac[6];    ///< Dirección MAC origen
    uint16_t ether_type;    ///< Tipo (0x0800 = IPv4, 0x86DD = IPv6)
};

/**
 * @brief Cabecera IPv4 (Capa 3 - Red). Tamaño mínimo: 20 bytes.
 *
 * @note Se usa uint8_t para `ver_ihl` en lugar de bitfields para
 *       portabilidad entre compiladores (GCC vs MSVC).
 */
struct IPv4Header {
    uint8_t  ver_ihl;       ///< Versión (4 bits altos) + IHL (4 bits bajos)
    uint8_t  tos;           ///< Tipo de Servicio (DSCP + ECN)
    uint16_t tot_len;       ///< Longitud total del datagrama
    uint16_t id;            ///< Identificador del fragmento
    uint16_t frag_off;      ///< Flags + Desplazamiento del fragmento
    uint8_t  ttl;           ///< Tiempo de Vida (TTL)
    uint8_t  protocol;      ///< Protocolo (6 = TCP, 17 = UDP)
    uint16_t checksum;      ///< Suma de verificación
    uint8_t  src_addr[4];   ///< IP origen (4 bytes)
    uint8_t  dst_addr[4];   ///< IP destino (4 bytes)
};

/**
 * @brief Cabecera TCP (Capa 4 - Transporte). Tamaño mínimo: 20 bytes.
 */
struct TCPHeader {
    uint16_t src_port;          ///< Puerto origen
    uint16_t dst_port;          ///< Puerto destino
    uint32_t seq_num;           ///< Número de secuencia
    uint32_t ack_num;           ///< Número de confirmación
    uint16_t data_offset_flags; ///< Data Offset + Flags (combinados)
    uint16_t window;            ///< Tamaño de ventana
    uint16_t checksum;          ///< Suma de verificación
    uint16_t urg_ptr;           ///< Puntero urgente
};

/**
 * @brief Cabecera UDP (Capa 4 - Transporte). Tamaño: 8 bytes.
 */
struct UDPHeader {
    uint16_t src_port;      ///< Puerto origen
    uint16_t dst_port;      ///< Puerto destino
    uint16_t length;        ///< Longitud total
    uint16_t checksum;      ///< Suma de verificación
};

#pragma pack(pop)

// ============================================================================
// DTO (Data Transfer Object) — información decodificada por paquete
// ============================================================================

/**
 * @brief Información completa de un paquete capturado para transferir a Python.
 *
 * Incluye campos resumidos para la tabla principal y campos detallados
 * para el panel de inspección estilo Wireshark (capas decodificadas,
 * bytes crudos, MAC addresses, TTL, flags TCP, etc.).
 */
struct PacketInfo {
    // --- Campos de la tabla principal ---
    std::string timestamp;      ///< Marca de tiempo (HH:MM:SS.mmm)
    std::string protocol;       ///< Protocolo ("TCP", "UDP")
    std::string src_ip;         ///< IP origen
    std::string dst_ip;         ///< IP destino
    int         src_port = 0;   ///< Puerto origen
    int         dst_port = 0;   ///< Puerto destino
    int         length   = 0;   ///< Longitud total en bytes

    // --- Campos detallados: Capa 2 (Ethernet) ---
    std::string src_mac;        ///< MAC origen (ej: "AA:BB:CC:DD:EE:FF")
    std::string dst_mac;        ///< MAC destino
    int         ether_type = 0; ///< Tipo Ethernet (ej: 0x0800)

    // --- Campos detallados: Capa 3 (IPv4) ---
    int         ip_version    = 0;  ///< Versión IP (4)
    int         ip_header_len = 0;  ///< Longitud de la cabecera IP en bytes
    int         ttl           = 0;  ///< Tiempo de vida
    int         ip_protocol   = 0;  ///< Número de protocolo IP (6=TCP, 17=UDP)

    // --- Campos detallados: Capa 4 (TCP) ---
    uint32_t    tcp_seq       = 0;  ///< Número de secuencia TCP
    uint32_t    tcp_ack       = 0;  ///< Número de acknowledgement TCP
    std::string tcp_flags;          ///< Flags TCP legibles (ej: "SYN ACK")
    int         tcp_window    = 0;  ///< Tamaño de ventana TCP

    // --- Campos detallados: Capa 4 (UDP) ---
    int         udp_length    = 0;  ///< Longitud del datagrama UDP

    // --- Bytes crudos del paquete (para el visor hexadecimal) ---
    std::vector<uint8_t> raw_bytes; ///< Copia de los bytes crudos del paquete
};
