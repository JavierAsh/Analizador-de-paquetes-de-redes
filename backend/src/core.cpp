#include <pybind11/pybind11.h>
#include <pybind11/stl.h> // Necesario para enlazar std::vector
#include "packet_capture.hpp"

namespace py = pybind11;

PYBIND11_MODULE(sniffer_core, m) {
    m.doc() = "Sniffer Core module written in C++ using Pybind11 and Npcap";

    // Registrar un C++ Struct como un Python object (dict o property access)
    py::class_<PacketInfo>(m, "PacketInfo")
        .def(py::init<>())
        .def_readwrite("timestamp", &PacketInfo::timestamp)
        .def_readwrite("protocol", &PacketInfo::protocol)
        .def_readwrite("src_ip", &PacketInfo::src_ip)
        .def_readwrite("dst_ip", &PacketInfo::dst_ip)
        .def_readwrite("src_port", &PacketInfo::src_port)
        .def_readwrite("dst_port", &PacketInfo::dst_port)
        .def_readwrite("length", &PacketInfo::length);

    // Registrar la clase PacketCapture y sus métodos para que Python pueda usarlos
    py::class_<PacketCapture>(m, "PacketCapture")
        .def(py::init<>())
        .def("get_interfaces", &PacketCapture::get_interfaces, "Returns a list of available network interfaces")
        .def("start_capture", &PacketCapture::start_capture, "Starts packet capture on a given interface in a background thread")
        .def("stop_capture", &PacketCapture::stop_capture, "Stops the packet capture thread")
        .def("get_packet_batch", &PacketCapture::get_packet_batch, "Extract all cached packets since last call");
}
