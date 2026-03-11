#include <pybind11/pybind11.h>
#include <pybind11/stl.h> // Necesario para enlazar std::vector
#include "packet_capture.hpp"

namespace py = pybind11;

PYBIND11_MODULE(sniffer_core, m) {
    m.doc() = "Sniffer Core module written in C++ using Pybind11 and Npcap";

    // Registrar la clase PacketCapture y sus métodos para que Python pueda usarlos
    py::class_<PacketCapture>(m, "PacketCapture")
        .def(py::init<>())
        .def("get_interfaces", &PacketCapture::get_interfaces, "Returns a list of available network interfaces")
        .def("start_capture", &PacketCapture::start_capture, "Starts packet capture on a given interface in a background thread")
        .def("stop_capture", &PacketCapture::stop_capture, "Stops the packet capture thread");
}
