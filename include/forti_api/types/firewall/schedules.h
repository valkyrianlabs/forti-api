//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_SCHEDULES_H
#define FORTI_API_SCHEDULES_H

#include "nlohmann/json.hpp"
#include "../response.h"
#include "../colors.h"

enum ScheduleDays {
    SUNDAY,
    MONDAY,
    TUESDAY,
    WEDNESDAY,
    THURSDAY,
    FRIDAY,
    SATURDAY
};

struct FirewallSchedule {
    inline static std::string endpoint = "/cmdb/firewall.schedule/recurring";
    std::string name, q_origin_key, start, end, day, fabric_object;
    unsigned int color{};

    FirewallSchedule() = default;
    explicit FirewallSchedule(std::string name, const std::string& vdom="root") : name(std::move(name)) {
        set_all_day();
        add(vdom);
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallSchedule, name, q_origin_key, start, end, day, fabric_object, color);

    void update(const std::string& vdom="root") {
        FortiAPI::put(std::format("{}/{}?vdom={}", endpoint, name, vdom), *this);
    }

    void del(const std::string& vdom="root") {
        FortiAPI::del(std::format("{}/{}?vdom={}", endpoint, name, vdom));
    }

    void add(const std::string& vdom="root") {
        FortiAPI::post(std::format("{}?vdom={}", endpoint, vdom), *this);
    }

    void set_time(const std::string& start_time, const std::string& end_time) {
        start = start_time;
        end = end_time;
        update();
    }

    void set_all_day() {
        start = "00:00";
        end = "00:00";
        update();
    }

    void set_start_time(const std::string& start_time) {
        start = start_time;
        update();
    }

    void set_end_time(const std::string& end_time) {
        end = end_time;
        update();
    }

    void set_days(const std::vector<ScheduleDays>& days) {
        day = "";
        for (unsigned int i = 0; i < days.size(); ++i) {
            day += std::to_string(days[i]);
            if (i != days.size() - 1) day += ",";
        }
        std::transform(day.begin(), day.end(), day.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        update();
    }

    void set_color(const Color& new_color) {
        color = new_color;
        update();
    }
};

struct FirewallSchedulesResponse : public Response {
    std::vector<FirewallSchedule> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallSchedulesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version, build, results);
};

#endif //FORTI_API_SCHEDULES_H
