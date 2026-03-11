#include "packet_capture.hpp"
#include "protocol_headers.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h> // Para ntohs (Network to Host Short)
#else
#include <arpa/inet.h>
#endif

PacketCapture::PacketCapture() : is_running(false), pcap_handle(nullptr) {}

PacketCapture::~PacketCapture() {
    stop_capture();
}

std::vector<std::string> PacketCapture::get_interfaces() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error buscando interfaces: " << errbuf << std::endl;
        return devices;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (d->name) {
            std::string name_desc = d->name;
            if (d->description) {
                name_desc += " (" + std::string(d->description) + ")";
            }
            devices.push_back(name_desc);
        }
    }

    pcap_freealldevs(alldevs);
    return devices;
}

void PacketCapture::start_capture(const std::string& interface_name) {
    if (is_running) return;

    // Extraer solo el identificador de la interfaz, cortando la descripción "(...)"
    std::string real_name = interface_name;
    size_t pos = real_name.find(" (");
    if (pos != std::string::npos) {
        real_name = real_name.substr(0, pos);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Modo promiscuo = 1, timeout = 1000ms
    pcap_handle = pcap_open_live(real_name.c_str(), 65536, 1, 1000, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "No se pudo abrir la interfaz " << real_name << ": " << errbuf << std::endl;
        return;
    }

    is_running = true;
    capture_thread = std::thread(&PacketCapture::capture_loop, this);
    std::cout << "[C++] Captura iniciada en hilo separado." << std::endl;
}

void PacketCapture::stop_capture() {
    if (is_running) {
        is_running = false;
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
        }
        if (capture_thread.joinable()) {
            capture_thread.join();
        }
        if (pcap_handle) {
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
        }
        std::cout << "[C++] Captura detenida." << std::endl;
    }
}

void PacketCapture::capture_loop() {
    // pcap_loop bloqueará hasta que ocurra un error, timeout, o pcap_breakloop()
    // -1 significa capturar indefinidamente paquetes.
    pcap_loop(pcap_handle, -1, PacketCapture::packet_handler, reinterpret_cast<u_char*>(this));
}

void PacketCapture::packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketCapture* instance = reinterpret_cast<PacketCapture*>(user_data);
    if (instance && instance->is_running) {
        instance->process_packet(pkthdr, packet);
    }
}

void PacketCapture::process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->len < sizeof(ether_header)) return;

    const ether_header* eth = reinterpret_cast<const ether_header*>(packet);
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type == 0x0800) { // IPv4
        int ip_offset = sizeof(ether_header);
        if (pkthdr->len < ip_offset + sizeof(ip_header_safe)) return;

        const ip_header_safe* ip = reinterpret_cast<const ip_header_safe*>(packet + ip_offset);
        
        // Calcular longitud del encabezado IP (IHL * 4)
        uint8_t ihl = ip->ver_ihl & 0x0F;
        int ip_header_len = ihl * 4;

        if (ip_header_len < 20) return; // Header IP inválido

        std::stringstream ss;
        ss << (int)ip->saddr[0] << "." << (int)ip->saddr[1] << "." << (int)ip->saddr[2] << "." << (int)ip->saddr[3];
        std::string src_ip_str = ss.str();
        
        std::stringstream ss2;
        ss2 << (int)ip->daddr[0] << "." << (int)ip->daddr[1] << "." << (int)ip->daddr[2] << "." << (int)ip->daddr[3];
        std::string dst_ip_str = ss2.str();

        int transport_offset = ip_offset + ip_header_len;

        PacketInfo info;
        info.timestamp = "Now"; // Idealmente datetime, simplificado para fase 3
        info.src_ip = src_ip_str;
        info.dst_ip = dst_ip_str;
        info.length = pkthdr->len;

        bool has_transport = false;
        
        if (ip->protocol == 6 && pkthdr->len >= transport_offset + sizeof(tcp_header)) { // TCP
            const tcp_header* tcp = reinterpret_cast<const tcp_header*>(packet + transport_offset);
            info.protocol = "TCP";
            info.src_port = ntohs(tcp->source);
            info.dst_port = ntohs(tcp->dest);
            has_transport = true;
        } 
        else if (ip->protocol == 17 && pkthdr->len >= transport_offset + sizeof(udp_header)) { // UDP
            const udp_header* udp = reinterpret_cast<const udp_header*>(packet + transport_offset);
            info.protocol = "UDP";
            info.src_port = ntohs(udp->source);
            info.dst_port = ntohs(udp->dest);
            has_transport = true;
        }

        if (has_transport) {
            std::lock_guard<std::mutex> lock(buffer_mutex);
            packet_buffer.push_back(info);
        }
    }
}

std::vector<PacketInfo> PacketCapture::get_packet_batch() {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    std::vector<PacketInfo> batch = std::move(packet_buffer);
    packet_buffer.clear(); // Garantizar que se limpia (move a veces deja indefinido el size)
    return batch;
}
