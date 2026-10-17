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

    // A write reply on a child path, shaped as FortiOS 7.4.8 answers child requests (seen on GETs of
    // cmdb/system.dhcp/server/1/reserved-address[/<id>]): `mkey` is the PARENT's key, as text, and the
    // entry's key is `child_mkey`.
    json write_reply(const char* method, json child_mkey, json parent_mkey = "1") {
        json reply = {{"http_method", method}, {"status", "success"}, {"http_status", 200}, {"revision", "abc"},
                      {"path", "system.dhcp"}, {"name", "server"}, {"mkey", std::move(parent_mkey)},
                      {"child_path", "reserved-address"}, {"vdom", "root"}};
        if (!child_mkey.is_null()) reply["child_mkey"] = std::move(child_mkey);
        return reply;
    }

    json reservation(std::uint32_t id, const char* ip, const char* mac, const char* description) {
        return {{"id", id}, {"type", "mac"}, {"ip", ip}, {"mac", mac}, {"action", "reserved"},
                {"circuit-id-type", "string"}, {"circuit-id", ""}, {"remote-id-type", "string"},
                {"remote-id", ""}, {"description", description}};
    }

    json not_found() { return {{"status", "error"}, {"http_status", 404}, {"error", -3}}; }

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
    fake->reply(200, write_reply("POST", 12));
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
    EXPECT_EQ(reply.revision, "abc");
    EXPECT_EQ(reply.mkey, "1");
    EXPECT_EQ(reply.child_path, "reserved-address");
    EXPECT_EQ(reply.child_mkey, 12);
    EXPECT_EQ(*entry.id, 12u);
    EXPECT_FALSE(dirty(entry));
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(ChildTableTest, AddReadsAnEntryKeyReportedAsText) {
    fake->reply(200, write_reply("POST", "13"));
    Reservation entry;
    entry.ip = "192.0.2.13";
    Reservations::add(1, entry, {}, client);
    EXPECT_EQ(*entry.id, 13u);
}

// `mkey` in a child reply is the parent's key: taking it would give the entry the parent's id, and a
// later update or delete would address another entry.
TEST_F(ChildTableTest, AddNeverTakesTheParentsKey) {
    fake->reply(200, write_reply("POST", nullptr, 3))
        .reply(200, write_reply("POST", "not a number"))
        .reply(200, write_reply("POST", -1))
        .reply(200, write_reply("POST", 4294967296ull));
    Reservation entry;
    entry.id = 0u;
    entry.ip = "192.0.2.12";
    Reservations::add(3, entry, {}, client);
    EXPECT_EQ(*entry.id, 0u);
    EXPECT_FALSE(dirty(entry));
    for (int i = 0; i < 3; ++i) {
        Reservation unreported;
        unreported.ip = "192.0.2.12";
        Reservations::add(1, unreported, {}, client);
        EXPECT_FALSE(unreported.id.has_value());
    }
}

TEST_F(ChildTableTest, AddKeepsAKeyTheCallerSet) {
    fake->reply(200, write_reply("POST", 9));   // whatever the reply reports, id 5 stays
    Reservation entry;
    entry.id = 5u;
    entry.ip = "192.0.2.5";
    entry.mac = "00:00:5e:00:53:05";
    Reservations::add(1, entry, {}, client);
    EXPECT_EQ(*entry.id, 5u);
    EXPECT_EQ(body(0)["id"], 5);
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

    fake->reply(200, write_reply("PUT", 7));
    auto reply = Reservations::update(1, entry, Query().vdom("root"), client);
    ASSERT_TRUE(reply.has_value());
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
    fake->reply(200, write_reply("DELETE", 7));
    auto reply = Reservations::del(1, 7, {}, client);
    EXPECT_EQ(reply.status, "success");
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
        EXPECT_EQ(error.fortios_error(), -3);
        EXPECT_EQ(error.path(), "cmdb/system.dhcp/server/1/reserved-address/99");
    }
}

// Both keys are one encoded path segment each, string or number.
TEST_F(ChildTableTest, KeysAreEncoded) {
    fake->reply(200, write_reply("DELETE", "LAN 10.0.0.0/24"))
        .reply(200, envelope(json::array({json{{"name", "a/b"}, {"category", "c"}}})))
        .reply(200, write_reply("POST", "LAN 10.0.0.0/24"));
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
    fake->reply(200, write_reply("DELETE", "."))
        .reply(404, not_found())
        .reply(200, write_reply("DELETE", ".."));
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
