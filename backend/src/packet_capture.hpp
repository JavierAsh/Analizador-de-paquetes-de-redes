#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <pcap.h>

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    // Obtiene una lista de los nombres de interfaces de red con Npcap
    std::vector<std::string> get_interfaces();

    // Inicia la captura en un hilo separado
    void start_capture(const std::string& interface_name);

    // Detiene la captura
    void stop_capture();

private:
    std::atomic<bool> is_running;
    std::thread capture_thread;
    pcap_t* pcap_handle;

    void capture_loop();

    // Callback de Npcap estático (Requerido por C-API) que delega al objeto de clase
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    
    void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
