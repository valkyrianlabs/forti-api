//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_EXT_CONNECTOR_H
#define FORTI_API_EXT_CONNECTOR_H

#include "nlohmann/json.hpp"
#include "../response.h"

struct PushThreatFeed {
    std::string name,
            status = "enable",
            type = "domain",
            update_method = "push",
            server_identity_check = "none",
            comments = "This threat feed is automatically managed by forti-api";
    unsigned int category{};

    PushThreatFeed() = default;
    PushThreatFeed(std::string  name, unsigned int category) : name(std::move(name)), category(category) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(PushThreatFeed, name, status, type, update_method,
            server_identity_check, category, comments)
};

struct FeedThreatFeed : public PushThreatFeed {
    std::string resource;
    unsigned int refresh_rate{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FeedThreatFeed, name, status, type, update_method,
            server_identity_check, category, comments, resource, refresh_rate)
};

struct ExternalResourcesResponse : public Response {
    std::vector<PushThreatFeed> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourcesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version,
            build, results)
};

struct Entry {
    std::string entry, valid;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Entry, entry, valid);
};

struct ExternalResourceEntryList {
    std::string status, resource_file_status;
    unsigned long last_content_update_time{};
    std::vector<Entry> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourceEntryList, status, resource_file_status,
            last_content_update_time, entries);
};

struct ExternalResourceEntryListResponse : public Response {
    ExternalResourceEntryList results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourceEntryListResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version,
            build, results)
};

struct CommandEntry {
    std::string name, command = "snapshot";
    std::vector<std::string> entries;

    CommandEntry() = default;
    CommandEntry(std::string name, const std::vector<std::string>& entries) : name(std::move(name)), entries(entries) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(CommandEntry, name, entries, command)
};

struct CommandsRequest {
    std::vector<CommandEntry> commands;

    CommandsRequest() = default;
    CommandsRequest(const CommandEntry& initialEntry) : commands() { commands.push_back(initialEntry); }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(CommandsRequest, commands)
};

#endif //FORTI_API_EXT_CONNECTOR_H
