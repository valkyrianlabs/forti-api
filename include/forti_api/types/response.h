//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_RESPONSE_H
#define FORTI_API_RESPONSE_H

#include "nlohmann/json.hpp"

struct Response {
    unsigned int size{}, matched_count{}, next_idx{}, http_status{}, build{};
    std::string http_method, revision, vdom, path, name, status, serial, version;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Response, http_method, size, matched_count, next_idx, revision,
            vdom, path, name, status, http_status, serial, version, build)
};

#endif //FORTI_API_RESPONSE_H
