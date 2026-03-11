#pragma once

#include <cstdint>

#pragma pack(push, 1) // Empaquetar bytes exactamente como llegan de Npcap, sin padding del compilador

// Capa de Enlace: Ethernet
struct ether_header {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type; // 0x0800 para IPv4, 0x86DD para IPv6
};

// Capa de Red: IPv4
struct ip_header {
    uint8_t  ihl:4, version:4;  // En un struct simple esto puede variar por el endianness, ver nota abajo.
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;    // 6 para TCP, 17 para UDP
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// Nota: GCC/Clang y MSVC a veces empaquetan los bitfields diferentes.
// Para seguridad, a nivel de bitfield en C/C++ crossplatform, es mejor un uint8_t y enmascarar:
struct ip_header_safe {
    uint8_t  ver_ihl;     // version (4 bits) e IHL (4 bits)
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint8_t  saddr[4];    // Byte array es más fácil para imprimir 192.168.x.x sin preocuparse por el endianness de uint32_t
    uint8_t  daddr[4];
};

// Capa de Transporte: TCP
struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1_doff_flags; // Mezclado para evitar problemas de bitfield portabilidad
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// Capa de Transporte: UDP
struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

#pragma pack(pop)
