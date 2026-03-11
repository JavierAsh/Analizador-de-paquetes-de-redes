/**
 * @file packet_capture.cpp
 * @brief Implementación del motor de captura de paquetes de red.
 *
 * Contiene la lógica de interacción con Npcap y la decodificación
 * completa de paquetes para alimentar el panel de detalles estilo Wireshark.
 */

#include "packet_capture.hpp"
#include "protocol_headers.hpp"

#include <iostream>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

PacketCapture::PacketCapture()
    : is_running_(false)
    , pcap_handle_(nullptr)
{
}

PacketCapture::~PacketCapture() {
    stop_capture();
}

// ============================================================================
// ENUMERACIÓN DE INTERFACES
// ============================================================================

std::vector<std::string> PacketCapture::get_interfaces() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[Error] No se pudieron enumerar las interfaces: "
                  << errbuf << std::endl;
        return devices;
    }

    int count = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) ++count;
    devices.reserve(static_cast<size_t>(count));

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        if (d->name) {
            std::string name_desc = d->name;
            if (d->description) {
                name_desc += " (" + std::string(d->description) + ")";
            }
            devices.push_back(std::move(name_desc));
        }
    }

    pcap_freealldevs(alldevs);
    return devices;
}

// ============================================================================
// CONTROL DE CAPTURA
// ============================================================================

void PacketCapture::start_capture(const std::string& interface_name) {
    if (is_running_) return;

    std::string real_name = interface_name;
    const size_t pos = real_name.find(" (");
    if (pos != std::string::npos) {
        real_name = real_name.substr(0, pos);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(real_name.c_str(), 65536, 1, 1000, errbuf);

    if (pcap_handle_ == nullptr) {
        std::cerr << "[Error] No se pudo abrir '" << real_name
                  << "': " << errbuf << std::endl;
        return;
    }

    is_running_ = true;
    capture_thread_ = std::thread(&PacketCapture::capture_loop, this);
}

void PacketCapture::stop_capture() {
    if (!is_running_) return;
    is_running_ = false;

    if (pcap_handle_) pcap_breakloop(pcap_handle_);
    if (capture_thread_.joinable()) capture_thread_.join();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

// ============================================================================
// BUCLE DE CAPTURA
// ============================================================================

void PacketCapture::capture_loop() {
    pcap_loop(pcap_handle_, -1, PacketCapture::packet_handler,
              reinterpret_cast<u_char*>(this));
}

void PacketCapture::packet_handler(u_char* user_data,
                                    const struct pcap_pkthdr* pkthdr,
                                    const u_char* packet)
{
    auto* instance = reinterpret_cast<PacketCapture*>(user_data);
    if (instance && instance->is_running_) {
        instance->process_packet(pkthdr, packet);
    }
}

// ============================================================================
// FUNCIONES AUXILIARES (helpers internos)
// ============================================================================

namespace {

/**
 * @brief Formatea una dirección MAC en formato legible (AA:BB:CC:DD:EE:FF).
 */
inline std::string format_mac(const uint8_t mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

/**
 * @brief Formatea una dirección IPv4 como string.
 */
inline std::string format_ip(const uint8_t addr[4]) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                  addr[0], addr[1], addr[2], addr[3]);
    return std::string(buf);
}

/**
 * @brief Decodifica los flags TCP del campo data_offset_flags.
 *
 * El campo de 16 bits tiene la estructura:
 *   [4 bits data offset] [3 bits reservados] [9 bits flags]
 * Los flags (9 bits bajos) son: NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN.
 */
inline std::string decode_tcp_flags(uint16_t raw_flags) {
    const uint16_t flags = ntohs(raw_flags) & 0x01FF; // 9 bits bajos
    std::string result;

    if (flags & 0x002) result += "SYN ";
    if (flags & 0x010) result += "ACK ";
    if (flags & 0x001) result += "FIN ";
    if (flags & 0x004) result += "RST ";
    if (flags & 0x008) result += "PSH ";
    if (flags & 0x020) result += "URG ";
    if (flags & 0x040) result += "ECE ";
    if (flags & 0x080) result += "CWR ";

    // Eliminar espacio final
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result.empty() ? "---" : result;
}

} // namespace anónimo

// ============================================================================
// DECODIFICACIÓN COMPLETA DE PAQUETES
// ============================================================================

void PacketCapture::process_packet(const struct pcap_pkthdr* pkthdr,
                                    const u_char* packet)
{
    // --- Capa 2: Ethernet ---
    if (pkthdr->len < sizeof(EthernetHeader)) return;

    const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);
    const uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != 0x0800) return; // Solo IPv4

    // --- Capa 3: IPv4 ---
    const int ip_offset = static_cast<int>(sizeof(EthernetHeader));
    if (pkthdr->len < ip_offset + static_cast<int>(sizeof(IPv4Header))) return;

    const auto* ip = reinterpret_cast<const IPv4Header*>(packet + ip_offset);
    const uint8_t ihl = ip->ver_ihl & 0x0F;
    const int ip_header_len = ihl * 4;
    if (ip_header_len < 20) return;

    const int transport_offset = ip_offset + ip_header_len;

    // Timestamp real del paquete
    char ts_buf[16];
    const long secs  = static_cast<long>(pkthdr->ts.tv_sec);
    const long usecs = static_cast<long>(pkthdr->ts.tv_usec);
    std::snprintf(ts_buf, sizeof(ts_buf), "%02d:%02d:%02d.%03d",
                  static_cast<int>((secs % 86400) / 3600),
                  static_cast<int>((secs % 3600) / 60),
                  static_cast<int>(secs % 60),
                  static_cast<int>(usecs / 1000));

    // Construir PacketInfo con información completa
    PacketInfo info;

    // Campos principales (tabla)
    info.timestamp = ts_buf;
    info.src_ip    = format_ip(ip->src_addr);
    info.dst_ip    = format_ip(ip->dst_addr);
    info.length    = static_cast<int>(pkthdr->len);

    // Capa 2: Ethernet
    info.src_mac    = format_mac(eth->src_mac);
    info.dst_mac    = format_mac(eth->dest_mac);
    info.ether_type = eth_type;

    // Capa 3: IPv4
    info.ip_version    = (ip->ver_ihl >> 4) & 0x0F;
    info.ip_header_len = ip_header_len;
    info.ttl           = ip->ttl;
    info.ip_protocol   = ip->protocol;

    // Bytes crudos (copia completa para el visor hexadecimal)
    const size_t copy_len = static_cast<size_t>(pkthdr->caplen);
    info.raw_bytes.assign(packet, packet + copy_len);

    // --- Capa 4: TCP o UDP ---
    bool has_transport = false;

    if (ip->protocol == 6) { // TCP
        if (pkthdr->len >= static_cast<unsigned>(transport_offset + static_cast<int>(sizeof(TCPHeader)))) {
            const auto* tcp = reinterpret_cast<const TCPHeader*>(packet + transport_offset);
            info.protocol   = "TCP";
            info.src_port   = ntohs(tcp->src_port);
            info.dst_port   = ntohs(tcp->dst_port);
            info.tcp_seq    = ntohl(tcp->seq_num);
            info.tcp_ack    = ntohl(tcp->ack_num);
            info.tcp_flags  = decode_tcp_flags(tcp->data_offset_flags);
            info.tcp_window = ntohs(tcp->window);
            has_transport   = true;
        }
    }
    else if (ip->protocol == 17) { // UDP
        if (pkthdr->len >= static_cast<unsigned>(transport_offset + static_cast<int>(sizeof(UDPHeader)))) {
            const auto* udp = reinterpret_cast<const UDPHeader*>(packet + transport_offset);
            info.protocol   = "UDP";
            info.src_port   = ntohs(udp->src_port);
            info.dst_port   = ntohs(udp->dst_port);
            info.udp_length = ntohs(udp->length);
            has_transport   = true;
        }
    }

    if (has_transport) {
        std::lock_guard<std::mutex> lock(buffer_mutex_);
        packet_buffer_.emplace_back(std::move(info));
    }
}

// ============================================================================
// EXTRACCIÓN DE PAQUETES
// ============================================================================

std::vector<PacketInfo> PacketCapture::get_packet_batch() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    std::vector<PacketInfo> batch = std::move(packet_buffer_);
    packet_buffer_.clear();
    return batch;
}
