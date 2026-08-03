#include "connection_tracker.h"

#include <cassert>
#include <iostream>
#include <string>

using namespace DPI;

int main() {

std::cout << "\n================================\n";
std::cout << "Global Connection Table Test\n";
std::cout << "================================\n";

// ------------------------------------------------------------
// Create two independent FastPath connection trackers.
// ------------------------------------------------------------

ConnectionTracker fp0(0);
ConnectionTracker fp1(1);

GlobalConnectionTable global(2);

global.registerTracker(0, &fp0);
global.registerTracker(1, &fp1);

// ------------------------------------------------------------
// FP0: two connections
// ------------------------------------------------------------

FiveTuple google_connection{
    0x0A000001,     // 10.0.0.1
    0x08080808,     // 8.8.8.8
    50000,
    443,
    6               // TCP
};

FiveTuple github_connection{
    0x0A000002,     // 10.0.0.2
    0x0C63A8C8,
    50001,
    443,
    6
};

Connection* google =
    fp0.getOrCreateConnection(google_connection);

Connection* github =
    fp0.getOrCreateConnection(github_connection);

assert(google != nullptr);
assert(github != nullptr);

fp0.classifyConnection(
    google,
    AppType::GOOGLE,
    "www.google.com"
);

fp0.classifyConnection(
    github,
    AppType::GITHUB,
    "github.com"
);

// ------------------------------------------------------------
// FP1: two connections
// ------------------------------------------------------------

FiveTuple youtube_connection{
    0x0A000003,
    0x0E0E0E0E,
    50002,
    443,
    6
};

FiveTuple google_connection_2{
    0x0A000004,
    0x08080808,
    50003,
    443,
    6
};

Connection* youtube =
    fp1.getOrCreateConnection(youtube_connection);

Connection* google2 =
    fp1.getOrCreateConnection(google_connection_2);

assert(youtube != nullptr);
assert(google2 != nullptr);

fp1.classifyConnection(
    youtube,
    AppType::YOUTUBE,
    "youtube.com"
);

fp1.classifyConnection(
    google2,
    AppType::GOOGLE,
    "www.google.com"
);

// ------------------------------------------------------------
// Verify global statistics.
// ------------------------------------------------------------

auto stats = global.getGlobalStats();

assert(stats.total_active_connections == 4);
assert(stats.total_connections_seen == 4);

std::cout
    << "Total active connections: "
    << stats.total_active_connections
    << "\n";

std::cout
    << "Total connections seen: "
    << stats.total_connections_seen
    << "\n";

// ------------------------------------------------------------
// Verify application distribution.
// ------------------------------------------------------------

assert(
    stats.app_distribution[AppType::GOOGLE] == 2
);

assert(
    stats.app_distribution[AppType::GITHUB] == 1
);

assert(
    stats.app_distribution[AppType::YOUTUBE] == 1
);

std::cout << "Application distribution: PASS\n";

// ------------------------------------------------------------
// Verify top domains.
// ------------------------------------------------------------

bool found_google = false;
bool found_github = false;
bool found_youtube = false;

for (const auto& entry : stats.top_domains) {

    if (entry.first == "www.google.com" &&
        entry.second == 2) {
        found_google = true;
    }

    if (entry.first == "github.com" &&
        entry.second == 1) {
        found_github = true;
    }

    if (entry.first == "youtube.com" &&
        entry.second == 1) {
        found_youtube = true;
    }
}

assert(found_google);
assert(found_github);
assert(found_youtube);

std::cout << "Top domains: PASS\n";

// ------------------------------------------------------------
// Verify generated report.
// ------------------------------------------------------------

std::string report =
    global.generateReport();

assert(
    report.find("CONNECTION STATISTICS REPORT")
    != std::string::npos
);

assert(
    report.find("APPLICATION BREAKDOWN")
    != std::string::npos
);

assert(
    report.find("TOP DOMAINS")
    != std::string::npos
);

assert(
    report.find("GOOGLE")
    != std::string::npos
);

assert(
    report.find("www.google.com")
    != std::string::npos
);

std::cout << "Generated report: PASS\n";

// ------------------------------------------------------------
// Print report.
// ------------------------------------------------------------

std::cout << report;

std::cout << "\n================================\n";
std::cout << "Global Connection Table test passed\n";
std::cout << "================================\n";

return 0;

}