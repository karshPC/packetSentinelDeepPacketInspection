#include "sni_extractor.h"

#include <iostream>
#include <string>

int main() {

    // ================================================================
    // HTTP Host test
    // ================================================================

    const std::string http_request =
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "User-Agent: DPI-Test\r\n"
        "\r\n";

    const std::string host =
        DPI::SNIExtractor::extractHTTP_Host(
            http_request
        );

    if (host != "www.google.com") {

        std::cerr
            << "HTTP Host extraction failed: "
            << host
            << "\n";

        return 1;
    }

    if (
        DPI::SNIExtractor::classifyHost(host)
        != DPI::AppType::GOOGLE
    ) {

        std::cerr
            << "Google classification failed\n";

        return 1;
    }

    // ================================================================
    // HTTP detection
    // ================================================================

    if (
        !DPI::SNIExtractor::isHTTP(
            reinterpret_cast<const uint8_t*>(
                http_request.data()
            ),
            http_request.size()
        )
    ) {

        std::cerr
            << "HTTP detection failed\n";

        return 1;
    }

    // ================================================================
    // Invalid TLS test
    // ================================================================

    const std::string invalid_tls =
        "not a TLS packet";

    if (
        DPI::SNIExtractor::isTLS(
            reinterpret_cast<const uint8_t*>(
                invalid_tls.data()
            ),
            invalid_tls.size()
        )
    ) {

        std::cerr
            << "Invalid TLS was detected as TLS\n";

        return 1;
    }

    // ================================================================
    // Empty payload tests
    // ================================================================

    if (
        !DPI::SNIExtractor::extractTLS_SNI(
            nullptr,
            0
        ).empty()
    ) {

        std::cerr
            << "Empty TLS payload test failed\n";

        return 1;
    }

    if (
        !DPI::SNIExtractor::extractHTTP_Host(
            nullptr,
            0
        ).empty()
    ) {

        std::cerr
            << "Empty HTTP payload test failed\n";

        return 1;
    }

    std::cout
        << "SNI extractor test passed\n";

    return 0;
}