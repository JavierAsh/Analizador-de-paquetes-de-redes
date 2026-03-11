#include <pybind11/pybind11.h>
#include <iostream>

namespace py = pybind11;

std::string hello_world() {
    return "Hello from C++ Sniffer Core!";
}

PYBIND11_MODULE(sniffer_core, m) {
    m.doc() = "Sniffer Core module written in C++ using Pybind11";
    m.def("hello_world", &hello_world, "A function that returns a hello world string");
}
