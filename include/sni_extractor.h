#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace DPI {

// ============================================================================
// Deep Packet Inspection Extractor
// ============================================================================
//
// Extracts application-identifying information from packet payloads.
//
// Supported in this stage:
//
//   TLS ClientHello -> Server Name Indication (SNI)
//   HTTP request    -> Host header
//
// The extractor does not make blocking decisions.
// It only extracts protocol/application information.
//
// ============================================================================

class SNIExtractor {
public:

    // ------------------------------------------------------------------------
    // TLS
    // ------------------------------------------------------------------------

    // Extract SNI from a TLS ClientHello payload.
    //
    // Returns an empty string when:
    //   - payload is not TLS
    //   - payload is not a ClientHello
    //   - SNI extension is not present
    //   - payload is malformed/incomplete
    static std::string extractTLS_SNI(
        const uint8_t* payload,
        size_t length
    );

    // Convenience overload for std::string.
    static std::string extractTLS_SNI(
        const std::string& payload
    );

    // ------------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------------

    // Extract Host header from an HTTP request.
    //
    // Returns an empty string when:
    //   - payload does not look like HTTP
    //   - Host header is absent
    //   - payload is malformed
    static std::string extractHTTP_Host(
        const uint8_t* payload,
        size_t length
    );

    // Convenience overload for std::string.
    static std::string extractHTTP_Host(
        const std::string& payload
    );

    // ------------------------------------------------------------------------
    // Protocol detection
    // ------------------------------------------------------------------------

    static bool isTLS(
        const uint8_t* payload,
        size_t length
    );

    static bool isHTTP(
        const uint8_t* payload,
        size_t length
    );

    // ------------------------------------------------------------------------
    // Application classification
    // ------------------------------------------------------------------------

    // Convert an extracted SNI/host into an AppType.
    static AppType classifyHost(
        const std::string& host
    );

private:

    static std::string normalizeHost(
        const std::string& host
    );

    static bool startsWithHTTPMethod(
        const uint8_t* payload,
        size_t length
    );

    static uint16_t readBE16(
        const uint8_t* data
    );

    static uint32_t readBE24(
        const uint8_t* data
    );
};

} // namespace DPI

#endif // SNI_EXTRACTOR_H