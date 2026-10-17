// ChildTable: one entry of a table attribute (cmdb/<path>/<parent key>/<attribute>/<entry key>),
// against a scripted transport.

#include <gtest/gtest.h>
#include "fake_transport.hpp"
#include <forti_api/gen/firewall/address.hpp>
#include <forti_api/gen/firewall/policy.hpp>
#include <forti_api/gen/system/dhcp/server.hpp>

#include <type_traits>

using namespace fortiapi;
using fortiapi::testing::FakeTransport;
using fortiapi::testing::envelope;
using fortiapi::testing::test_config;
using nlohmann::json;

namespace {

    using Server = system::dhcp::Server;
    using Reservation = Server::ReservedAddressEntry;
    using Reservations = system::dhcp::Servers::child<&Server::reserved_address>;
    using Tags = ChildTable<firewall::AddressSpec, &firewall::Address::tagging>;
    using SourceAddresses = firewall::Policies::child<&firewall::Policy::srcaddr>;

    static_assert(std::is_same_v<Reservations, ChildTable<system::dhcp::ServerSpec, &Server::reserved_address>>);
    static_assert(std::is_same_v<Reservations::type, Reservation>);
    static_assert(std::is_same_v<Reservations::key_type, std::uint32_t>);
    static_assert(std::is_same_v<Reservations::parent_key_type, std::uint32_t>);
    static_assert(Reservations::key == &Reservation::id);
    static_assert(std::is_same_v<Tags::key_type, std::string>);
    static_assert(std::is_same_v<Tags::parent_key_type, std::string>);
    static_assert(std::is_same_v<SourceAddresses::type, Ref>);   // member tables of names
    static_assert(SourceAddresses::key == &Ref::name);

    struct ChildTableTest : ::testing::Test {
        std::shared_ptr<FakeTransport> fake = std::make_shared<FakeTransport>();
        Client client{test_config(), fake};

        [[nodiscard]] std::string url(std::size_t i) const { return fake->requests.at(i).url; }
        [[nodiscard]] Method method(std::size_t i) const { return fake->requests.at(i).method; }
        [[nodiscard]] json body(std::size_t i) const { return json::parse(fake->requests.at(i).body); }
    };

    // Write replies on a child path, shaped as FortiOS 7.4.8 answers them (observed live on
    // router/access-list rule and firewall/addrgrp member, tests/live/test_child_table.cpp). `mkey`
    // means something different per method: the new entry's key on POST (no child_mkey), the parent's
    // key on PUT, the entry's key on DELETE; PUT and DELETE also report the entry key as text in
    // `child_mkey`.
    json write_reply(const char* method, json mkey, json child_mkey = nullptr) {
        json reply = {{"http_method", method}, {"status", "success"}, {"http_status", 200}, {"action", ""},
                      {"revision", "def"}, {"old_revision", "abc"}, {"revision_changed", true},
                      {"path", "system.dhcp"}, {"name", "server"}, {"mkey", std::move(mkey)},
                      {"child_path", "reserved-address"}, {"vdom", "root"}};
        if (!child_mkey.is_null()) reply["child_mkey"] = std::move(child_mkey);
        return reply;
    }

    json post_reply(json entry_key) { return write_reply("POST", std::move(entry_key)); }
    json put_reply(json parent_key, json entry_key) { return write_reply("PUT", std::move(parent_key), std::move(entry_key)); }
    json delete_reply(json entry_key) {
        auto text = entry_key.is_string() ? entry_key : json(entry_key.dump());
        return write_reply("DELETE", std::move(entry_key), std::move(text));
    }

    json reservation(std::uint32_t id, const char* ip, const char* mac, const char* description) {
        return {{"id", id}, {"type", "mac"}, {"ip", ip}, {"mac", mac}, {"action", "reserved"},
                {"circuit-id-type", "string"}, {"circuit-id", ""}, {"remote-id-type", "string"},
                {"remote-id", ""}, {"description", description}};
    }

    // A 404 on a child path (7.4.8): no FortiOS error code; `child_path` only when the parent exists.
    json not_found() {
        return {{"http_method", "GET"}, {"status", "error"}, {"http_status", 404}, {"path", "system.dhcp"},
                {"name", "server"}, {"mkey", "1"}, {"child_path", "reserved-address"}};
    }

    const std::string base = "https://fortigate.test:8443/api/v2/";

}  // namespace

TEST_F(ChildTableTest, AttributeAndPaths) {
    EXPECT_EQ(Reservations::attribute(), "reserved-address");
    EXPECT_EQ(Reservations::path(1), "cmdb/system.dhcp/server/1/reserved-address");
    EXPECT_EQ(Reservations::path(1, 7), "cmdb/system.dhcp/server/1/reserved-address/7");
    EXPECT_EQ(Tags::attribute(), "tagging");
    EXPECT_EQ(SourceAddresses::attribute(), "srcaddr");
    EXPECT_TRUE(fake->requests.empty());
}

TEST_F(ChildTableTest, ListDecodesEveryEntry) {
    fake->reply(200, envelope(json::array({reservation(1, "192.0.2.10", "00:00:5e:00:53:01", "printer"),
                                           reservation(2, "192.0.2.11", "00:00:5e:00:53:02", "")})));
    auto entries = Reservations::list(1, Query().vdom("root"), client);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(*entries[0].id, 1u);
    EXPECT_EQ(*entries[0].mac, "00:00:5e:00:53:01");
    EXPECT_EQ(*entries[1].ip, "192.0.2.11");
    EXPECT_EQ(entries[0].ip.state(), FieldState::populated);
    EXPECT_EQ(method(0), Method::Get);
    EXPECT_EQ(url(0), base + "cmdb/system.dhcp/server/1/reserved-address?vdom=root");
}

TEST_F(ChildTableTest, ListOfAnEmptyChildTable) {
    fake->reply(200, envelope(json::array()));
    EXPECT_TRUE(Reservations::list(4, {}, client).empty());
}

TEST_F(ChildTableTest, ListNamesTheChildPathOnDecodeFailure) {
    fake->reply(200, envelope(json::array({json{{"id", "not a number"}}})));
    try {
        Reservations::list(1, {}, client);
        FAIL();
    } catch (const DecodeError& error) {
        EXPECT_NE(std::string(error.what()).find("cmdb/system.dhcp/server/1/reserved-address: attribute id"),
                  std::string::npos) << error.what();
    }
}

TEST_F(ChildTableTest, ListOfAMissingParentThrowsNotFound) {
    fake->reply(404, not_found());
    try {
        Reservations::list(9, {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_TRUE(error.not_found());
        EXPECT_EQ(error.path(), "cmdb/system.dhcp/server/9/reserved-address");
    }
}

TEST_F(ChildTableTest, GetAddressesOneEntry) {
    fake->reply(200, envelope(json::array({reservation(7, "192.0.2.17", "00:00:5e:00:53:07", "nas")})));
    auto entry = Reservations::get(1, 7, {}, client);
    EXPECT_EQ(*entry.id, 7u);
    EXPECT_EQ(*entry.description, "nas");
    EXPECT_FALSE(dirty(entry));
    EXPECT_EQ(url(0), base + "cmdb/system.dhcp/server/1/reserved-address/7");
}

TEST_F(ChildTableTest, GetAcceptsAnObjectResult) {
    fake->reply(200, envelope(reservation(7, "192.0.2.17", "00:00:5e:00:53:07", "")));
    EXPECT_EQ(*Reservations::get(1, 7, {}, client).ip, "192.0.2.17");
}

TEST_F(ChildTableTest, GetThrowsNotFound) {
    fake->reply(404, not_found());
    try {
        Reservations::get(1, 99, {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_TRUE(error.not_found());
        EXPECT_EQ(error.method(), Method::Get);
        EXPECT_EQ(error.path(), "cmdb/system.dhcp/server/1/reserved-address/99");
    }
    fake->reply(200, envelope(json::array()));
    EXPECT_THROW(Reservations::get(1, 99, {}, client), ApiError);
}

TEST_F(ChildTableTest, FindAndContainsTreat404AsAbsent) {
    fake->reply(404, not_found());
    EXPECT_FALSE(Reservations::find(1, 99, {}, client).has_value());
    fake->reply(404, not_found());
    EXPECT_FALSE(Reservations::contains(1, 99, {}, client));
    fake->reply(200, envelope(json::array({reservation(7, "192.0.2.17", "00:00:5e:00:53:07", "")})));
    EXPECT_TRUE(Reservations::contains(1, 7, {}, client));
    fake->reply(500, json{{"status", "error"}, {"http_status", 500}});
    EXPECT_THROW(Reservations::find(1, 7, {}, client), ApiError);
}

TEST_F(ChildTableTest, AddPostsOneEntryToTheChildTable) {
    fake->reply(200, post_reply(12));
    Reservation entry;
    entry.id = 0u;   // the device assigns the next id
    entry.ip = "192.0.2.12";
    entry.mac = "00:00:5e:00:53:0c";
    entry.description = "forti-vlan-mac";
    auto reply = Reservations::add(1, entry, {}, client);

    EXPECT_EQ(method(0), Method::Post);
    EXPECT_EQ(url(0), base + "cmdb/system.dhcp/server/1/reserved-address");
    EXPECT_EQ(body(0), (json{{"id", 0}, {"ip", "192.0.2.12"}, {"mac", "00:00:5e:00:53:0c"},
                             {"description", "forti-vlan-mac"}}));
    EXPECT_EQ(reply.http_method, "POST");
    EXPECT_EQ(reply.revision, "def");
    EXPECT_EQ(reply.old_revision, "abc");
    EXPECT_TRUE(reply.revision_changed);
    EXPECT_EQ(reply.mkey, 12);   // the new entry's key, on a child POST
    EXPECT_EQ(reply.child_path, "reserved-address");
    EXPECT_TRUE(reply.child_mkey.is_null());
    EXPECT_EQ(*entry.id, 12u);
    EXPECT_FALSE(dirty(entry));
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(ChildTableTest, AddReadsAnEntryKeyReportedAsText) {
    fake->reply(200, post_reply("13"));
    Reservation entry;
    entry.ip = "192.0.2.13";
    Reservations::add(1, entry, {}, client);
    EXPECT_EQ(*entry.id, 13u);
}

TEST_F(ChildTableTest, AddPrefersChildMkey) {
    fake->reply(200, write_reply("POST", "1", 14));
    Reservation entry;
    entry.ip = "192.0.2.14";
    Reservations::add(1, entry, {}, client);
    EXPECT_EQ(*entry.id, 14u);
}

// `mkey` names the parent in PUT, GET and error replies: it is taken only from a reply that says it
// answers a POST to this child table, so the entry never gets the parent's id (a later update or
// delete would address another entry). Unusable keys leave the entry's key alone.
TEST_F(ChildTableTest, AddTakesMkeyOnlyFromAChildPostReply) {
    json not_a_child = post_reply(3);
    not_a_child.erase("child_path");
    json other_child = post_reply(3);
    other_child["child_path"] = "ip-range";
    json no_method = post_reply(3);
    no_method.erase("http_method");
    fake->reply(200, not_a_child)
        .reply(200, other_child)
        .reply(200, no_method)
        .reply(200, write_reply("PUT", 3))
        .reply(200, post_reply("not a number"))
        .reply(200, post_reply(-1))
        .reply(200, post_reply(4294967296ull))
        .reply(200, post_reply(nullptr));
    for (int i = 0; i < 8; ++i) {
        Reservation entry;
        entry.id = 0u;
        entry.ip = "192.0.2.12";
        Reservations::add(3, entry, {}, client);
        EXPECT_EQ(*entry.id, 0u) << i;
        EXPECT_FALSE(dirty(entry));
    }
    fake->reply(200, post_reply(nullptr));
    Reservation unreported;
    unreported.ip = "192.0.2.12";
    Reservations::add(1, unreported, {}, client);
    EXPECT_FALSE(unreported.id.has_value());
}

TEST_F(ChildTableTest, AddKeepsAKeyTheCallerSet) {
    fake->reply(200, post_reply(9));   // whatever the reply reports, id 5 stays
    Reservation entry;
    entry.id = 5u;
    entry.ip = "192.0.2.5";
    entry.mac = "00:00:5e:00:53:05";
    Reservations::add(1, entry, {}, client);
    EXPECT_EQ(*entry.id, 5u);
    EXPECT_EQ(body(0)["id"], 5);
}

// An existing key: FortiOS refuses the POST (error -5) and keeps the entry as it was.
TEST_F(ChildTableTest, AddOfAnExistingEntryThrows) {
    fake->reply(500, json{{"http_method", "POST"}, {"status", "error"}, {"http_status", 500}, {"error", -5},
                          {"cli_error", json::array()}, {"revision", "abc"}, {"revision_changed", false},
                          {"mkey", 1}, {"child_path", "reserved-address"}});
    Reservation entry;
    entry.id = 5u;
    entry.ip = "192.0.2.5";
    try {
        Reservations::add(1, entry, {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_EQ(error.http_status(), 500);
        EXPECT_EQ(error.fortios_error(), -5);
    }
    EXPECT_TRUE(dirty(entry));
}

TEST_F(ChildTableTest, AddIsNeverResent) {
    fake->fail(CURLE_RECV_ERROR, false);
    Reservation entry;
    entry.ip = "192.0.2.12";
    entry.mac = "00:00:5e:00:53:0c";
    EXPECT_THROW(Reservations::add(1, entry, {}, client), TransportError);
    EXPECT_EQ(fake->requests.size(), 1u);
    EXPECT_TRUE(dirty(entry));
}

TEST_F(ChildTableTest, UpdatePutsOnlyTheEntrysChanges) {
    fake->reply(200, envelope(json::array({reservation(7, "192.0.2.17", "00:00:5e:00:53:07", "nas")})));
    auto entry = Reservations::get(1, 7, {}, client);
    entry.ip = "192.0.2.27";
    entry.description.clear();

    fake->reply(200, put_reply("1", "7"));
    auto reply = Reservations::update(1, entry, Query().vdom("root"), client);
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->mkey, "1");   // the parent, on a child PUT
    EXPECT_EQ(reply->child_mkey, "7");
    EXPECT_EQ(method(1), Method::Put);
    EXPECT_EQ(url(1), base + "cmdb/system.dhcp/server/1/reserved-address/7?vdom=root");
    EXPECT_EQ(body(1), (json{{"ip", "192.0.2.27"}, {"description", ""}}));   // no id, mac, type, ...
    EXPECT_FALSE(dirty(entry));
}

TEST_F(ChildTableTest, UpdateWithoutChangesSendsNothing) {
    fake->reply(200, envelope(json::array({reservation(7, "192.0.2.17", "00:00:5e:00:53:07", "nas")})));
    auto entry = Reservations::get(1, 7, {}, client);
    EXPECT_FALSE(Reservations::update(1, entry, {}, client).has_value());
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(ChildTableTest, UpdateNeedsTheEntryKey) {
    Reservation entry;
    entry.ip = "192.0.2.27";
    EXPECT_THROW(Reservations::update(1, entry, {}, client), Error);
    EXPECT_TRUE(fake->requests.empty());
}

TEST_F(ChildTableTest, FailedUpdateLeavesTheEntryDirty) {
    fake->reply(404, not_found());
    Reservation entry;
    entry.id = 99u;
    entry.ip = "192.0.2.99";
    try {
        Reservations::update(1, entry, {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_TRUE(error.not_found());
        EXPECT_EQ(error.method(), Method::Put);
    }
    EXPECT_TRUE(dirty(entry));
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(ChildTableTest, DeleteRemovesOneEntry) {
    fake->reply(200, delete_reply(7));
    auto reply = Reservations::del(1, 7, {}, client);
    EXPECT_EQ(reply.status, "success");
    EXPECT_EQ(reply.mkey, 7);   // the entry, on a child DELETE
    EXPECT_EQ(reply.child_mkey, "7");
    EXPECT_EQ(method(0), Method::Delete);
    EXPECT_EQ(url(0), base + "cmdb/system.dhcp/server/1/reserved-address/7");
    EXPECT_TRUE(fake->requests[0].body.empty());
}

TEST_F(ChildTableTest, DeleteOfAMissingEntryThrowsNotFound) {
    fake->reply(404, not_found());
    try {
        Reservations::del(1, 99, {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_TRUE(error.not_found());
        EXPECT_EQ(error.fortios_error(), 0);   // child 404s carry no FortiOS error code
        EXPECT_EQ(error.path(), "cmdb/system.dhcp/server/1/reserved-address/99");
    }
}

// Both keys are one encoded path segment each, string or number.
TEST_F(ChildTableTest, KeysAreEncoded) {
    fake->reply(200, delete_reply("LAN 10.0.0.0/24"))
        .reply(200, envelope(json::array({json{{"name", "a/b"}, {"category", "c"}}})))
        .reply(200, post_reply("LAN 10.0.0.0/24"));
    SourceAddresses::del(5, "LAN 10.0.0.0/24", {}, client);
    EXPECT_EQ(*Tags::get("office?x=1", "a/b", {}, client).name, "a/b");
    Ref ref("LAN 10.0.0.0/24");
    SourceAddresses::add(5, ref, {}, client);

    EXPECT_EQ(url(0), base + "cmdb/firewall/policy/5/srcaddr/LAN%2010.0.0.0%2F24");
    EXPECT_EQ(url(1), base + "cmdb/firewall/address/office%3Fx%3D1/tagging/a%2Fb");
    EXPECT_EQ(url(2), base + "cmdb/firewall/policy/5/srcaddr");
    EXPECT_EQ(body(2), (json{{"name", "LAN 10.0.0.0/24"}}));
    EXPECT_EQ(*ref.name, "LAN 10.0.0.0/24");   // a string key is never taken from the reply
}

// "." and ".." name one object, never the table or its parent (G13), as parent or entry key.
TEST_F(ChildTableTest, DotKeysAddressOneObject) {
    fake->reply(200, delete_reply("."))
        .reply(404, not_found())
        .reply(200, delete_reply(".."));
    Tags::del("..", ".", {}, client);
    EXPECT_FALSE(Tags::contains(".", "..", {}, client));
    SourceAddresses::del(1, "..", {}, client);

    EXPECT_EQ(url(0), base + "cmdb/firewall/address/%2E%2E/tagging/%2E");
    EXPECT_EQ(url(1), base + "cmdb/firewall/address/%2E/tagging/%2E%2E");
    EXPECT_EQ(url(2), base + "cmdb/firewall/policy/1/srcaddr/%2E%2E");
    EXPECT_EQ(Tags::path("..", ".."), "cmdb/firewall/address/%2E%2E/tagging/%2E%2E");
}

// Every generated table entry names its key: the schema's mkey, also for member tables.
TEST_F(ChildTableTest, GeneratedEntriesNameTheirKey) {
    static_assert(Server::IpRangeEntry::mkey == &Server::IpRangeEntry::id);
    static_assert(Server::TftpServerEntry::mkey == &Server::TftpServerEntry::tftp_server);
    static_assert(firewall::Address::MacaddrEntry::mkey == &firewall::Address::MacaddrEntry::macaddr);
    using MacRanges = firewall::Addresses::child<&firewall::Address::macaddr>;
    EXPECT_EQ(MacRanges::path("a", "00:00:5e:00:53:01"), "cmdb/firewall/address/a/macaddr/00%3A00%3A5e%3A00%3A53%3A01");
}
