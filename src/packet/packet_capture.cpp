#include "packet/packet_capture.hpp"

#include <chrono>

#include <fstream>

#include <iostream>

#include <thread>

std::vector<Packet>
PacketCapture::capture(
    const std::string& interfaceName,
    int seconds
) const
{
    std::cout
        << "\nPACKET CAPTURE\n"
        << "==============\n";

    std::cout
        << "Interface: "
        << interfaceName
        << '\n';

    std::cout
        << "Duration : "
        << seconds
        << " seconds\n\n";

    std::cout
        << "[*] Starting capture session...\n";

    /*
        This v0.1 engine establishes the capture
        session interface.

        The production packet backend will use
        libpcap to receive actual frames.
    */

    std::this_thread::sleep_for(
        std::chrono::seconds(seconds)
    );

    std::ofstream output(
        "data/last_capture.txt"
    );

    output
        << "interface="
        << interfaceName
        << '\n';

    output
        << "duration="
        << seconds
        << '\n';

    output.close();

    std::cout
        << "[+] Capture session finished.\n";

    return {};
}