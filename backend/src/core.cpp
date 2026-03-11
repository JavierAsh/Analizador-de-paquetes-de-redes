/**
 * @file core.cpp
 * @brief Módulo de enlace Pybind11 — expone el motor C++ a Python.
 *
 * Registra PacketInfo (con todos los campos detallados) y PacketCapture.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "packet_capture.hpp"

namespace py = pybind11;

PYBIND11_MODULE(sniffer_core, m) {
    m.doc() = "Módulo del motor de captura de paquetes de red (C++ / Npcap)";

    // ---- PacketInfo: todos los campos disponibles para Python ----
    py::class_<PacketInfo>(m, "PacketInfo")
        .def(py::init<>())
        // Tabla principal
        .def_readwrite("timestamp",     &PacketInfo::timestamp)
        .def_readwrite("protocol",      &PacketInfo::protocol)
        .def_readwrite("src_ip",        &PacketInfo::src_ip)
        .def_readwrite("dst_ip",        &PacketInfo::dst_ip)
        .def_readwrite("src_port",      &PacketInfo::src_port)
        .def_readwrite("dst_port",      &PacketInfo::dst_port)
        .def_readwrite("length",        &PacketInfo::length)
        // Capa 2: Ethernet
        .def_readwrite("src_mac",       &PacketInfo::src_mac)
        .def_readwrite("dst_mac",       &PacketInfo::dst_mac)
        .def_readwrite("ether_type",    &PacketInfo::ether_type)
        // Capa 3: IPv4
        .def_readwrite("ip_version",    &PacketInfo::ip_version)
        .def_readwrite("ip_header_len", &PacketInfo::ip_header_len)
        .def_readwrite("ttl",           &PacketInfo::ttl)
        .def_readwrite("ip_protocol",   &PacketInfo::ip_protocol)
        // Capa 4: TCP
        .def_readwrite("tcp_seq",       &PacketInfo::tcp_seq)
        .def_readwrite("tcp_ack",       &PacketInfo::tcp_ack)
        .def_readwrite("tcp_flags",     &PacketInfo::tcp_flags)
        .def_readwrite("tcp_window",    &PacketInfo::tcp_window)
        // Capa 4: UDP
        .def_readwrite("udp_length",    &PacketInfo::udp_length)
        // Bytes crudos
        .def_readwrite("raw_bytes",     &PacketInfo::raw_bytes);

    // ---- PacketCapture: controlador principal ----
    py::class_<PacketCapture>(m, "PacketCapture")
        .def(py::init<>())
        .def("get_interfaces",   &PacketCapture::get_interfaces,
             "Devuelve la lista de interfaces de red disponibles")
        .def("start_capture",    &PacketCapture::start_capture,
             py::arg("interface_name"),
             "Inicia la captura en la interfaz indicada")
        .def("stop_capture",     &PacketCapture::stop_capture,
             "Detiene la captura y libera recursos")
        .def("get_packet_batch", &PacketCapture::get_packet_batch,
             "Extrae todos los paquetes acumulados desde la última llamada");
}
