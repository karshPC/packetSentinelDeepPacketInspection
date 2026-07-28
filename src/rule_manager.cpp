#include "rule_manager.h"

#include <algorithm>
#include <iostream>
#include <mutex>
#include <sstream>

namespace DPI {

// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(
    const std::string& ip
) {
    uint32_t result = 0;

    int octet = 0;
    int shift = 0;

    for (char c : ip) {

        if (c == '.') {

            result |=
                static_cast<uint32_t>(octet)
                << shift;

            shift += 8;
            octet = 0;

        } else if (c >= '0' && c <= '9') {

            octet =
                octet * 10
                + (c - '0');
        }
    }

    result |=
        static_cast<uint32_t>(octet)
        << shift;

    return result;
}

std::string RuleManager::ipToString(
    uint32_t ip
) {
    std::ostringstream ss;

    ss
        << ((ip >> 0) & 0xFF)
        << "."
        << ((ip >> 8) & 0xFF)
        << "."
        << ((ip >> 16) & 0xFF)
        << "."
        << ((ip >> 24) & 0xFF);

    return ss.str();
}

void RuleManager::blockIP(
    uint32_t ip
) {
    std::unique_lock<std::shared_mutex>
        lock(ip_mutex_);

    blocked_ips_.insert(ip);

    std::cout
        << "[RuleManager] Blocked IP: "
        << ipToString(ip)
        << std::endl;
}

void RuleManager::blockIP(
    const std::string& ip
) {
    blockIP(parseIP(ip));
}

void RuleManager::unblockIP(
    uint32_t ip
) {
    std::unique_lock<std::shared_mutex>
        lock(ip_mutex_);

    blocked_ips_.erase(ip);

    std::cout
        << "[RuleManager] Unblocked IP: "
        << ipToString(ip)
        << std::endl;
}

void RuleManager::unblockIP(
    const std::string& ip
) {
    unblockIP(parseIP(ip));
}

bool RuleManager::isIPBlocked(
    uint32_t ip
) const {
    std::shared_lock<std::shared_mutex>
        lock(ip_mutex_);

    return blocked_ips_.count(ip) > 0;
}

std::vector<std::string>
RuleManager::getBlockedIPs() const {

    std::shared_lock<std::shared_mutex>
        lock(ip_mutex_);

    std::vector<std::string> result;

    for (uint32_t ip : blocked_ips_) {
        result.push_back(
            ipToString(ip)
        );
    }

    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(
    AppType app
) {
    std::unique_lock<std::shared_mutex>
        lock(app_mutex_);

    blocked_apps_.insert(app);

    std::cout
        << "[RuleManager] Blocked app: "
        << appTypeToString(app)
        << std::endl;
}

void RuleManager::unblockApp(
    AppType app
) {
    std::unique_lock<std::shared_mutex>
        lock(app_mutex_);

    blocked_apps_.erase(app);

    std::cout
        << "[RuleManager] Unblocked app: "
        << appTypeToString(app)
        << std::endl;
}

bool RuleManager::isAppBlocked(
    AppType app
) const {
    std::shared_lock<std::shared_mutex>
        lock(app_mutex_);

    return blocked_apps_.count(app) > 0;
}

std::vector<AppType>
RuleManager::getBlockedApps() const {

    std::shared_lock<std::shared_mutex>
        lock(app_mutex_);

    return std::vector<AppType>(
        blocked_apps_.begin(),
        blocked_apps_.end()
    );
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(
    const std::string& domain
) {
    std::unique_lock<std::shared_mutex>
        lock(domain_mutex_);

    if (domain.find('*') != std::string::npos) {

        domain_patterns_.push_back(domain);

    } else {

        blocked_domains_.insert(domain);
    }

    std::cout
        << "[RuleManager] Blocked domain: "
        << domain
        << std::endl;
}

void RuleManager::unblockDomain(
    const std::string& domain
) {
    std::unique_lock<std::shared_mutex>
        lock(domain_mutex_);

    if (domain.find('*') != std::string::npos) {

        auto it =
            std::find(
                domain_patterns_.begin(),
                domain_patterns_.end(),
                domain
            );

        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }

    } else {

        blocked_domains_.erase(domain);
    }

    std::cout
        << "[RuleManager] Unblocked domain: "
        << domain
        << std::endl;
}

bool RuleManager::domainMatchesPattern(
    const std::string& domain,
    const std::string& pattern
) {
    // Supports patterns such as:
    //
    // *.example.com

    if (
        pattern.size() >= 2 &&
        pattern[0] == '*' &&
        pattern[1] == '.'
    ) {

        std::string suffix =
            pattern.substr(1);

        if (
            domain.size() >= suffix.size() &&
            domain.compare(
                domain.size() - suffix.size(),
                suffix.size(),
                suffix
            ) == 0
        ) {
            return true;
        }

        // Also match bare domain.
        if (
            domain ==
            pattern.substr(2)
        ) {
            return true;
        }
    }

    return false;
}

bool RuleManager::isDomainBlocked(
    const std::string& domain
) const {

    std::shared_lock<std::shared_mutex>
        lock(domain_mutex_);

    if (
        blocked_domains_.count(domain) > 0
    ) {
        return true;
    }

    for (
        const auto& pattern :
        domain_patterns_
    ) {

        if (
            domainMatchesPattern(
                domain,
                pattern
            )
        ) {
            return true;
        }
    }

    return false;
}

std::vector<std::string>
RuleManager::getBlockedDomains() const {

    std::shared_lock<std::shared_mutex>
        lock(domain_mutex_);

    std::vector<std::string> result;

    for (
        const auto& domain :
        blocked_domains_
    ) {
        result.push_back(domain);
    }

    for (
        const auto& pattern :
        domain_patterns_
    ) {
        result.push_back(pattern);
    }

    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(
    uint16_t port
) {
    std::unique_lock<std::shared_mutex>
        lock(port_mutex_);

    blocked_ports_.insert(port);

    std::cout
        << "[RuleManager] Blocked port: "
        << port
        << std::endl;
}

void RuleManager::unblockPort(
    uint16_t port
) {
    std::unique_lock<std::shared_mutex>
        lock(port_mutex_);

    blocked_ports_.erase(port);

    std::cout
        << "[RuleManager] Unblocked port: "
        << port
        << std::endl;
}

bool RuleManager::isPortBlocked(
    uint16_t port
) const {
    std::shared_lock<std::shared_mutex>
        lock(port_mutex_);

    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason>
RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain
) const {

    if (isIPBlocked(src_ip)) {

        return BlockReason{
            BlockReason::IP,
            ipToString(src_ip)
        };
    }

    if (isAppBlocked(app)) {

        return BlockReason{
            BlockReason::APP,
            appTypeToString(app)
        };
    }

    if (isDomainBlocked(domain)) {

        return BlockReason{
            BlockReason::DOMAIN_RULE,
            domain
        };
    }

    if (isPortBlocked(dst_port)) {

        return BlockReason{
            BlockReason::PORT,
            std::to_string(dst_port)
        };
    }

    return std::nullopt;
}

// ============================================================================
// Rule Persistence
// ============================================================================

bool RuleManager::saveRules(
    const std::string& filename
) const {

    std::ofstream file(filename);

    if (!file.is_open()) {
        return false;
    }

    // IP rules
    for (
        const auto& ip :
        getBlockedIPs()
    ) {
        file << "IP " << ip << "\n";
    }

    // Application rules
    for (
        const auto& app :
        getBlockedApps()
    ) {
        file
            << "APP "
            << appTypeToString(app)
            << "\n";
    }

    // Domain rules
    for (
        const auto& domain :
        getBlockedDomains()
    ) {
        file
            << "DOMAIN "
            << domain
            << "\n";
    }

    // Port rules
    {
        std::shared_lock<std::shared_mutex>
            lock(port_mutex_);

        for (
            uint16_t port :
            blocked_ports_
        ) {
            file
                << "PORT "
                << port
                << "\n";
        }
    }

    return file.good();
}

bool RuleManager::loadRules(
    const std::string& filename
) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        return false;
    }

    std::string type;
    std::string value;

    while (
        file >> type >> value
    ) {

        if (type == "IP") {

            blockIP(value);

        } else if (type == "APP") {

            for (
                int i = 0;
                i < static_cast<int>(
                    AppType::APP_COUNT
                );
                ++i
            ) {

                AppType app =
                    static_cast<AppType>(i);

                if (
                    appTypeToString(app)
                    == value
                ) {
                    blockApp(app);
                    break;
                }
            }

        } else if (type == "DOMAIN") {

            blockDomain(value);

        } else if (type == "PORT") {

            blockPort(
                static_cast<uint16_t>(
                    std::stoi(value)
                )
            );
        }
    }

    return true;
}

void RuleManager::clearAll() {

    {
        std::unique_lock<std::shared_mutex>
            lock(ip_mutex_);

        blocked_ips_.clear();
    }

    {
        std::unique_lock<std::shared_mutex>
            lock(app_mutex_);

        blocked_apps_.clear();
    }

    {
        std::unique_lock<std::shared_mutex>
            lock(domain_mutex_);

        blocked_domains_.clear();
        domain_patterns_.clear();
    }

    {
        std::unique_lock<std::shared_mutex>
            lock(port_mutex_);

        blocked_ports_.clear();
    }
}

// ============================================================================
// Statistics
// ============================================================================

RuleManager::RuleStats
RuleManager::getStats() const {

    RuleStats stats{};

    {
        std::shared_lock<std::shared_mutex>
            lock(ip_mutex_);

        stats.blocked_ips =
            blocked_ips_.size();
    }

    {
        std::shared_lock<std::shared_mutex>
            lock(app_mutex_);

        stats.blocked_apps =
            blocked_apps_.size();
    }

    {
        std::shared_lock<std::shared_mutex>
            lock(domain_mutex_);

        stats.blocked_domains =
            blocked_domains_.size()
            + domain_patterns_.size();
    }

    {
        std::shared_lock<std::shared_mutex>
            lock(port_mutex_);

        stats.blocked_ports =
            blocked_ports_.size();
    }

    return stats;
}

} // namespace DPI