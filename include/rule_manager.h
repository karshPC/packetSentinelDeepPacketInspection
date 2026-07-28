#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "types.h"

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <vector>
#include <fstream>

namespace DPI {

// ============================================================================
// Rule Manager - Manages blocking/filtering rules
// ============================================================================
//
// Rules can be:
// 1. IP-based
// 2. Application-based
// 3. Domain-based
// 4. Port-based
//
// Rules are thread-safe for concurrent access from FP threads.
// ============================================================================

class RuleManager {
public:

    RuleManager() = default;

    // ================================================================
    // IP Blocking
    // ================================================================

    void blockIP(uint32_t ip);

    void blockIP(
        const std::string& ip
    );

    void unblockIP(uint32_t ip);

    void unblockIP(
        const std::string& ip
    );

    bool isIPBlocked(
        uint32_t ip
    ) const;

    std::vector<std::string> getBlockedIPs() const;

    // ================================================================
    // Application Blocking
    // ================================================================

    void blockApp(
        AppType app
    );

    void unblockApp(
        AppType app
    );

    bool isAppBlocked(
        AppType app
    ) const;

    std::vector<AppType> getBlockedApps() const;

    // ================================================================
    // Domain Blocking
    // ================================================================

    void blockDomain(
        const std::string& domain
    );

    void unblockDomain(
        const std::string& domain
    );

    bool isDomainBlocked(
        const std::string& domain
    ) const;

    std::vector<std::string> getBlockedDomains() const;

    // ================================================================
    // Port Blocking
    // ================================================================

    void blockPort(
        uint16_t port
    );

    void unblockPort(
        uint16_t port
    );

    bool isPortBlocked(
        uint16_t port
    ) const;

    // ================================================================
    // Combined Rule Check
    // ================================================================

    struct BlockReason {

        enum Type {
            IP,
            APP,
            DOMAIN_RULE,
            PORT
        } type;

        std::string detail;
    };

    std::optional<BlockReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain
    ) const;

    // ================================================================
    // Rule Persistence
    // ================================================================

    bool saveRules(
        const std::string& filename
    ) const;

    bool loadRules(
        const std::string& filename
    );

    void clearAll();

    // ================================================================
    // Statistics
    // ================================================================

    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
    };

    RuleStats getStats() const;

private:

    // ================================================================
    // Thread-safe rule containers
    // ================================================================

    mutable std::shared_mutex ip_mutex_;

    std::unordered_set<uint32_t>
        blocked_ips_;

    mutable std::shared_mutex app_mutex_;

    std::unordered_set<AppType>
        blocked_apps_;

    mutable std::shared_mutex domain_mutex_;

    std::unordered_set<std::string>
        blocked_domains_;

    std::vector<std::string>
        domain_patterns_;

    mutable std::shared_mutex port_mutex_;

    std::unordered_set<uint16_t>
        blocked_ports_;

    // ================================================================
    // Helpers
    // ================================================================

    static uint32_t parseIP(
        const std::string& ip
    );

    static std::string ipToString(
        uint32_t ip
    );

    static bool domainMatchesPattern(
        const std::string& domain,
        const std::string& pattern
    );
};

} // namespace DPI

#endif // RULE_MANAGER_H