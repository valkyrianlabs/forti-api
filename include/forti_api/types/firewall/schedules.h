//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_SCHEDULES_H
#define FORTI_API_SCHEDULES_H

#include "nlohmann/json.hpp"
#include "include/forti_api/types/response.h"

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

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallSchedule, name, q_origin_key, start, end, day, fabric_object, color);
};

struct FirewallSchedulesResponse : public Response {
    std::vector<FirewallSchedule> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallSchedulesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version, build, results);
};

#endif //FORTI_API_SCHEDULES_H
