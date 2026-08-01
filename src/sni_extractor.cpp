#include "sni_extractor.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace DPI {

// ============================================================================
// Helpers
// ============================================================================

uint16_t SNIExtractor::readBE16(
    const uint8_t* data
) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1])
    );
}

uint32_t SNIExtractor::readBE24(
    const uint8_t* data
) {
    return
        (static_cast<uint32_t>(data[0]) << 16) |
        (static_cast<uint32_t>(data[1]) << 8) |
        static_cast<uint32_t>(data[2]);
}

// ============================================================================
// TLS Detection
// ============================================================================

bool SNIExtractor::isTLS(
    const uint8_t* payload,
    size_t length
) {
    if (!payload || length < 5) {
        return false;
    }

    // TLS record:
    //
    // byte 0 : content type
    // bytes 1-2 : version
    // bytes 3-4 : record length
    //
    // Handshake = 0x16.

    if (payload[0] != 0x16) {
        return false;
    }

    // TLS 1.0 - TLS 1.3 commonly use 0x03 as major version.
    if (payload[1] != 0x03) {
        return false;
    }

    return true;
}

// ============================================================================
// HTTP Detection
// ============================================================================

bool SNIExtractor::startsWithHTTPMethod(
    const uint8_t* payload,
    size_t length
) {
    static const char* methods[] = {
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        "HEAD ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE "
    };

    for (const char* method : methods) {

        const size_t method_length =
            std::strlen(method);

        if (length >= method_length &&
            std::memcmp(
                payload,
                method,
                method_length
            ) == 0) {

            return true;
        }
    }

    return false;
}

bool SNIExtractor::isHTTP(
    const uint8_t* payload,
    size_t length
) {
    if (!payload || length == 0) {
        return false;
    }

    return startsWithHTTPMethod(
        payload,
        length
    );
}

// ============================================================================
// TLS SNI Extraction
// ============================================================================

std::string SNIExtractor::extractTLS_SNI(
    const uint8_t* payload,
    size_t length
) {
    if (!payload || length < 5) {
        return "";
    }

    if (!isTLS(payload, length)) {
        return "";
    }

    // TLS record length.
    const uint16_t record_length =
        readBE16(payload + 3);

    if (record_length + 5 > length) {
        return "";
    }

    // TLS record payload starts at byte 5.
    const uint8_t* handshake =
        payload + 5;

    const size_t handshake_length =
        record_length;

    // Handshake header:
    //
    // byte 0      = handshake type
    // bytes 1-3   = handshake length
    //
    // ClientHello = 0x01.

    if (handshake_length < 4) {
        return "";
    }

    if (handshake[0] != 0x01) {
        return "";
    }

    const uint32_t client_hello_length =
        readBE24(handshake + 1);

    if (client_hello_length + 4 > handshake_length) {
        return "";
    }

    const uint8_t* hello =
        handshake + 4;

    size_t remaining =
        client_hello_length;

    // ClientHello:
    //
    // legacy_version       2 bytes
    // random               32 bytes
    // session_id_length    1 byte
    // session_id           variable
    // cipher_suites_length 2 bytes
    // cipher_suites        variable
    // compression_length   1 byte
    // compression_methods  variable
    // extensions_length    2 bytes
    // extensions           variable

    if (remaining < 2 + 32 + 1) {
        return "";
    }

    // legacy_version
    hello += 2;
    remaining -= 2;

    // random
    if (remaining < 32) {
        return "";
    }

    hello += 32;
    remaining -= 32;

    // Session ID
    if (remaining < 1) {
        return "";
    }

    const uint8_t session_id_length =
        hello[0];

    hello += 1;
    remaining -= 1;

    if (session_id_length > remaining) {
        return "";
    }

    hello += session_id_length;
    remaining -= session_id_length;

    // Cipher suites
    if (remaining < 2) {
        return "";
    }

    const uint16_t cipher_suites_length =
        readBE16(hello);

    hello += 2;
    remaining -= 2;

    if (cipher_suites_length > remaining) {
        return "";
    }

    hello += cipher_suites_length;
    remaining -= cipher_suites_length;

    // Compression methods
    if (remaining < 1) {
        return "";
    }

    const uint8_t compression_length =
        hello[0];

    hello += 1;
    remaining -= 1;

    if (compression_length > remaining) {
        return "";
    }

    hello += compression_length;
    remaining -= compression_length;

    // Extensions may be absent.
    if (remaining < 2) {
        return "";
    }

    const uint16_t extensions_length =
        readBE16(hello);

    hello += 2;
    remaining -= 2;

    if (extensions_length > remaining) {
        return "";
    }

    size_t extensions_remaining =
        extensions_length;

    // ------------------------------------------------------------------------
    // Iterate TLS extensions.
    // ------------------------------------------------------------------------

    while (extensions_remaining >= 4) {

        const uint16_t extension_type =
            readBE16(hello);

        const uint16_t extension_length =
            readBE16(hello + 2);

        hello += 4;
        extensions_remaining -= 4;

        if (extension_length > extensions_remaining) {
            return "";
        }

        // Server Name extension.
        //
        // Extension type 0 = server_name.

        if (extension_type == 0x0000) {

            if (extension_length < 2) {
                return "";
            }

            const uint8_t* server_names =
                hello;

            const uint16_t server_name_list_length =
                readBE16(server_names);

            server_names += 2;

            if (
                server_name_list_length >
                extension_length - 2
            ) {
                return "";
            }

            size_t names_remaining =
                server_name_list_length;

            while (names_remaining >= 3) {

                const uint8_t name_type =
                    server_names[0];

                const uint16_t name_length =
                    readBE16(server_names + 1);

                server_names += 3;
                names_remaining -= 3;

                if (name_length > names_remaining) {
                    return "";
                }

                // host_name = type 0.
                if (name_type == 0) {

                    return std::string(
                        reinterpret_cast<
                            const char*
                        >(server_names),
                        name_length
                    );
                }

                server_names += name_length;
                names_remaining -= name_length;
            }

            return "";
        }

        hello += extension_length;
        extensions_remaining -= extension_length;
    }

    return "";
}

// ============================================================================
// HTTP Host Extraction
// ============================================================================

std::string SNIExtractor::extractHTTP_Host(
    const uint8_t* payload,
    size_t length
) {
    if (!payload || length == 0) {
        return "";
    }

    if (!isHTTP(payload, length)) {
        return "";
    }

    const std::string request(
        reinterpret_cast<const char*>(payload),
        length
    );

    size_t position = 0;

    while (position < request.size()) {

        const size_t line_end =
            request.find(
                "\r\n",
                position
            );

        if (line_end == std::string::npos) {
            break;
        }

        const std::string line =
            request.substr(
                position,
                line_end - position
            );

        position = line_end + 2;

        const std::string prefix =
            "Host:";

        if (line.size() >= prefix.size()) {

            bool matches = true;

            for (size_t i = 0;
                 i < prefix.size();
                 ++i) {

                if (
                    std::tolower(
                        static_cast<unsigned char>(
                            line[i]
                        )
                    ) !=
                    std::tolower(
                        static_cast<unsigned char>(
                            prefix[i]
                        )
                    )
                ) {
                    matches = false;
                    break;
                }
            }

            if (matches) {

                size_t start =
                    prefix.size();

                while (
                    start < line.size() &&
                    std::isspace(
                        static_cast<unsigned char>(
                            line[start]
                        )
                    )
                ) {
                    ++start;
                }

                size_t end =
                    line.size();

                while (
                    end > start &&
                    std::isspace(
                        static_cast<unsigned char>(
                            line[end - 1]
                        )
                    )
                ) {
                    --end;
                }

                return normalizeHost(
                    line.substr(
                        start,
                        end - start
                    )
                );
            }
        }
    }

    return "";
}

// ============================================================================
// String overloads
// ============================================================================

std::string SNIExtractor::extractTLS_SNI(
    const std::string& payload
) {
    return extractTLS_SNI(
        reinterpret_cast<const uint8_t*>(
            payload.data()
        ),
        payload.size()
    );
}

std::string SNIExtractor::extractHTTP_Host(
    const std::string& payload
) {
    return extractHTTP_Host(
        reinterpret_cast<const uint8_t*>(
            payload.data()
        ),
        payload.size()
    );
}

// ============================================================================
// Host Normalization
// ============================================================================

std::string SNIExtractor::normalizeHost(
    const std::string& host
) {
    std::string result = host;

    while (!result.empty() &&
           std::isspace(
               static_cast<unsigned char>(
                   result.back()
               )
           )) {
        result.pop_back();
    }

    while (!result.empty() &&
           std::isspace(
               static_cast<unsigned char>(
                   result.front()
               )
           )) {
        result.erase(
            result.begin()
        );
    }

    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char c) {
            return static_cast<char>(
                std::tolower(c)
            );
        }
    );

    // Remove HTTP port suffix.
    //
    // Example:
    //
    // google.com:80
    //
    // becomes:
    //
    // google.com

    const size_t colon =
        result.rfind(':');

    if (colon != std::string::npos &&
        result.find(':') == colon) {

        bool numeric_port = true;

        for (
            size_t i = colon + 1;
            i < result.size();
            ++i
        ) {
            if (
                !std::isdigit(
                    static_cast<unsigned char>(
                        result[i]
                    )
                )
            ) {
                numeric_port = false;
                break;
            }
        }

        if (numeric_port) {
            result.erase(colon);
        }
    }

    return result;
}

// ============================================================================
// Application Classification
// ============================================================================

AppType SNIExtractor::classifyHost(
    const std::string& host
) {
    const std::string normalized =
        normalizeHost(host);

    if (normalized.empty()) {
        return AppType::UNKNOWN;
    }

    if (
        normalized == "google.com" ||
        normalized.find(".google.com") !=
            std::string::npos
    ) {
        return AppType::GOOGLE;
    }

    if (
        normalized == "facebook.com" ||
        normalized.find(".facebook.com") !=
            std::string::npos
    ) {
        return AppType::FACEBOOK;
    }

    if (
        normalized == "youtube.com" ||
        normalized.find(".youtube.com") !=
            std::string::npos
    ) {
        return AppType::YOUTUBE;
    }

    if (
        normalized == "twitter.com" ||
        normalized == "x.com" ||
        normalized.find(".twitter.com") !=
            std::string::npos
    ) {
        return AppType::TWITTER;
    }

    if (
        normalized == "instagram.com" ||
        normalized.find(".instagram.com") !=
            std::string::npos
    ) {
        return AppType::INSTAGRAM;
    }

    if (
        normalized == "netflix.com" ||
        normalized.find(".netflix.com") !=
            std::string::npos
    ) {
        return AppType::NETFLIX;
    }

    if (
        normalized == "amazon.com" ||
        normalized.find(".amazon.com") !=
            std::string::npos
    ) {
        return AppType::AMAZON;
    }

    if (
        normalized == "microsoft.com" ||
        normalized.find(".microsoft.com") !=
            std::string::npos
    ) {
        return AppType::MICROSOFT;
    }

    if (
        normalized == "apple.com" ||
        normalized.find(".apple.com") !=
            std::string::npos
    ) {
        return AppType::APPLE;
    }

    if (
        normalized == "whatsapp.com" ||
        normalized.find(".whatsapp.com") !=
            std::string::npos
    ) {
        return AppType::WHATSAPP;
    }

    if (
        normalized == "telegram.org" ||
        normalized.find(".telegram.org") !=
            std::string::npos
    ) {
        return AppType::TELEGRAM;
    }

    if (
        normalized == "tiktok.com" ||
        normalized.find(".tiktok.com") !=
            std::string::npos
    ) {
        return AppType::TIKTOK;
    }

    if (
        normalized == "spotify.com" ||
        normalized.find(".spotify.com") !=
            std::string::npos
    ) {
        return AppType::SPOTIFY;
    }

    if (
        normalized == "zoom.us" ||
        normalized.find(".zoom.us") !=
            std::string::npos
    ) {
        return AppType::ZOOM;
    }

    if (
        normalized == "discord.com" ||
        normalized.find(".discord.com") !=
            std::string::npos
    ) {
        return AppType::DISCORD;
    }

    if (
        normalized == "github.com" ||
        normalized.find(".github.com") !=
            std::string::npos
    ) {
        return AppType::GITHUB;
    }

    if (
        normalized == "cloudflare.com" ||
        normalized.find(".cloudflare.com") !=
            std::string::npos
    ) {
        return AppType::CLOUDFLARE;
    }

    return AppType::UNKNOWN;
}

} // namespace DPI