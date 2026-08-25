#include "platform/ping.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <string>

#pragma comment(lib, "ws2_32.lib")

namespace slipnet::platform
{

namespace
{

/*
 * MinGW/UCRT64 may not expose the Windows ICMP API
 * declarations even though the functions exist in
 * iphlpapi.dll.
 *
 * We therefore define only the structures/functions
 * that SlipNet needs and resolve them dynamically.
 */

using IcmpCreateFileFn =
    HANDLE (WINAPI*)();

using IcmpCloseHandleFn =
    BOOL (WINAPI*)(
        HANDLE
    );

using IcmpSendEchoFn =
    DWORD (WINAPI*)(
        HANDLE,
        DWORD,
        LPVOID,
        WORD,
        LPVOID,
        LPVOID,
        DWORD,
        DWORD
    );


#pragma pack(push, 1)

struct IcmpEchoReply
{
    DWORD address;
    DWORD status;
    DWORD roundTripTime;
    WORD dataSize;
    WORD reserved;
    LPVOID data;
    struct
    {
        BYTE ttl;
        BYTE tos;
        BYTE flags;
        BYTE optionsSize;
        BYTE optionsData[1];
    } options;
};

#pragma pack(pop)


constexpr DWORD ICMP_STATUS_SUCCESS = 0;


/*
 * Resolve the required ICMP functions from
 * Windows' IP Helper API DLL.
 */
bool loadIcmpApi(
    HMODULE& module,
    IcmpCreateFileFn& createFile,
    IcmpCloseHandleFn& closeHandle,
    IcmpSendEchoFn& sendEcho
)
{
    module =
        LoadLibraryA(
            "iphlpapi.dll"
        );

    if (module == nullptr)
    {
        return false;
    }


    createFile =
        reinterpret_cast<IcmpCreateFileFn>(
            GetProcAddress(
                module,
                "IcmpCreateFile"
            )
        );

    closeHandle =
        reinterpret_cast<IcmpCloseHandleFn>(
            GetProcAddress(
                module,
                "IcmpCloseHandle"
            )
        );

    sendEcho =
        reinterpret_cast<IcmpSendEchoFn>(
            GetProcAddress(
                module,
                "IcmpSendEcho"
            )
        );


    if (
        createFile == nullptr ||
        closeHandle == nullptr ||
        sendEcho == nullptr
    )
    {
        FreeLibrary(module);

        module = nullptr;

        createFile = nullptr;
        closeHandle = nullptr;
        sendEcho = nullptr;

        return false;
    }


    return true;
}

} // namespace


PingResult pingHost(
    const std::string& ip
)
{
    PingResult result;


    /*
     * --------------------------------------------------------
     * Validate IPv4 address
     * --------------------------------------------------------
     */

    IN_ADDR destination{};

    if (
        InetPtonA(
            AF_INET,
            ip.c_str(),
            &destination
        ) != 1
    )
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Load Windows ICMP API
     * --------------------------------------------------------
     */

    HMODULE iphlpapi = nullptr;

    IcmpCreateFileFn createFile = nullptr;

    IcmpCloseHandleFn closeHandle = nullptr;

    IcmpSendEchoFn sendEcho = nullptr;


    if (
        !loadIcmpApi(
            iphlpapi,
            createFile,
            closeHandle,
            sendEcho
        )
    )
    {
        return result;
    }


    /*
     * --------------------------------------------------------
     * Create ICMP handle
     * --------------------------------------------------------
 */

    HANDLE handle =
        createFile();


    if (
        handle == INVALID_HANDLE_VALUE ||
        handle == nullptr
    )
    {
        FreeLibrary(iphlpapi);

        return result;
    }


    /*
     * --------------------------------------------------------
     * Prepare ICMP payload
     * --------------------------------------------------------
     */

    const char payload[] =
        "SlipNet ICMP probe";


    constexpr DWORD replyBufferSize =
        sizeof(IcmpEchoReply)
        + sizeof(payload)
        + 64;


    auto* replyBuffer =
        new std::uint8_t[
            replyBufferSize
        ];


    /*
     * --------------------------------------------------------
     * Send ICMP Echo request
     * --------------------------------------------------------
     */

    const auto start =
        std::chrono::steady_clock::now();


    const DWORD replyCount =
        sendEcho(
            handle,
            destination.S_un.S_addr,
            const_cast<char*>(
                payload
            ),
            static_cast<WORD>(
                sizeof(payload)
            ),
            nullptr,
            replyBuffer,
            replyBufferSize,
            1000
        );


    const auto end =
        std::chrono::steady_clock::now();


    /*
     * --------------------------------------------------------
     * Process reply
     * --------------------------------------------------------
     */

    if (replyCount > 0)
    {
        const auto* reply =
            reinterpret_cast<
                const IcmpEchoReply*
            >(
                replyBuffer
            );


        if (
            reply->status ==
            ICMP_STATUS_SUCCESS
        )
        {
            result.reachable = true;


            /*
             * Windows provides the measured
             * round-trip time directly.
             */
            result.latencyMs =
                static_cast<double>(
                    reply->roundTripTime
                );


            /*
             * Extremely fast responses may
             * report zero milliseconds.
             *
             * Use our local measurement as
             * a fallback.
             */
            if (
                result.latencyMs <= 0.0
            )
            {
                result.latencyMs =
                    std::chrono::duration<
                        double,
                        std::milli
                    >(
                        end - start
                    ).count();
            }
        }
    }


    /*
     * --------------------------------------------------------
     * Cleanup
     * --------------------------------------------------------
     */

    delete[] replyBuffer;

    closeHandle(handle);

    FreeLibrary(iphlpapi);


    return result;
}

} // namespace slipnet::platform

#endif