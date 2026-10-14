//
// Firewall: every generated firewall endpoint plus value helpers for schedules and services.
//

#ifndef FORTI_API_FIREWALL_HPP
#define FORTI_API_FIREWALL_HPP

#include "gen/firewall.hpp"

#include <cstdint>
#include <format>
#include <initializer_list>
#include <string>

namespace fortiapi::firewall {

    enum class Weekday { sunday, monday, tuesday, wednesday, thursday, friday, saturday };

    // The value of RecurringSchedule::day: "monday wednesday friday".
    inline std::string days(std::initializer_list<Weekday> weekdays) {
        static constexpr std::string_view names[] = {"sunday", "monday", "tuesday", "wednesday", "thursday",
                                                      "friday", "saturday"};
        std::string out;
        for (auto day: weekdays) {
            if (!out.empty()) out += ' ';
            out += names[static_cast<int>(day)];
        }
        return out;
    }

    // One destination port range of a custom service; high == 0 means a single port.
    struct PortRange {
        std::uint16_t low = 0;
        std::uint16_t high = 0;
    };

    // The value of Service::tcp_portrange / udp_portrange / sctp_portrange: "80 443 8000-8080".
    inline std::string port_ranges(std::initializer_list<PortRange> ranges) {
        std::string out;
        for (const auto& range: ranges) {
            if (!out.empty()) out += ' ';
            out += range.high > range.low ? std::format("{}-{}", range.low, range.high) : std::to_string(range.low);
        }
        return out;
    }

}  // namespace fortiapi::firewall

#endif //FORTI_API_FIREWALL_HPP
