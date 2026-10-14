// Requirement 1: fields distinguish absent, populated, modified and cleared, and an update never
// serializes anything the caller did not change.
#include <gtest/gtest.h>
#include <forti_api/gen/dnsfilter/profile.hpp>
#include <forti_api/gen/firewall/policy.hpp>

using fortiapi::Field;
using fortiapi::FieldState;
using fortiapi::Write;
using nlohmann::json;

namespace {

    struct Inner {
        Field<std::string> mode;
        Field<std::uint32_t> level;

        template<typename Self, typename Visitor>
        static void visit(Self& self, Visitor&& v) {
            v("mode", self.mode, R"("off")", fortiapi::none);
            v("level", self.level, R"(3)", fortiapi::none);
        }
    };

    struct Thing {
        struct ItemsEntry {
            Field<std::uint32_t> id;
            Field<std::string> note;

            template<typename Self, typename Visitor>
            static void visit(Self& self, Visitor&& v) {
                v("id", self.id, R"(0)", fortiapi::none);
                v("note", self.note, R"("")", fortiapi::none);
            }
        };

        Field<std::string> name;
        Field<std::string> comment;
        Field<std::uint32_t> port;
        Field<std::string> serial;
        Field<Inner> inner;
        Field<std::vector<ItemsEntry>> items;
        Field<std::vector<fortiapi::Ref>> members;

        template<typename Self, typename Visitor>
        static void visit(Self& self, Visitor&& v) {
            v("name", self.name, R"("")", fortiapi::none);
            v("comment", self.comment, R"("")", fortiapi::none);
            v("port", self.port, R"(443)", fortiapi::none);
            v("serial", self.serial, R"("")", fortiapi::read_only);
            v("inner", self.inner, R"({})", fortiapi::none);
            v("items", self.items, R"([])", fortiapi::none);
            v("members", self.members, R"([])", fortiapi::none);
        }
    };

    json device_thing() {
        return {{"name", "a"}, {"comment", "hello"}, {"port", 8443}, {"serial", "FGT60F"},
                {"inner", {{"mode", "on"}, {"level", 5}}},
                {"items", {{{"id", 1}, {"note", "x"}}, {{"id", 2}, {"note", "y"}}}},
                {"members", {{{"name", "lan"}, {"q_origin_key", "lan"}}}},
                {"unknown-key", 1}};
    }

}  // namespace

TEST(FieldState, StartsAbsentAndTracksEveryTransition) {
    Field<std::string> f;
    EXPECT_EQ(f.state(), FieldState::absent);
    EXPECT_FALSE(f.has_value());

    f.load("device");
    EXPECT_EQ(f.state(), FieldState::populated);
    EXPECT_FALSE(f.dirty());

    f = "mine";
    EXPECT_EQ(f.state(), FieldState::modified);
    EXPECT_TRUE(f.dirty());
    EXPECT_EQ(*f, "mine");

    f.clear();
    EXPECT_EQ(f.state(), FieldState::cleared);
    EXPECT_TRUE(f.dirty());
    EXPECT_FALSE(f.has_value());

    f.reset();
    EXPECT_EQ(f.state(), FieldState::absent);
    EXPECT_FALSE(f.dirty());
}

TEST(FieldState, ReadingNeverChangesTheState) {
    Field<std::string> f;
    f.load("device");
    const auto& view = f;
    EXPECT_EQ(view.value(), "device");
    EXPECT_EQ(f->size(), 6u);
    EXPECT_EQ(f.value_or("x"), "device");
    EXPECT_TRUE(f == std::string("device"));
    EXPECT_EQ(f.state(), FieldState::populated);
    EXPECT_THROW((void) Field<int>().value(), std::logic_error);
}

TEST(FieldState, EditMarksModified) {
    Field<std::vector<int>> f;
    f.load({1, 2});
    f.edit().push_back(3);
    EXPECT_EQ(f.state(), FieldState::modified);
    EXPECT_EQ(f->size(), 3u);
}

TEST(Serialize, ReadObjectIsCleanAndUpdatesSendNothing) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    EXPECT_EQ(thing.port.state(), FieldState::populated);
    EXPECT_EQ(thing.inner->mode.state(), FieldState::populated);
    EXPECT_EQ(thing.members->front().name.value(), "lan");
    EXPECT_FALSE(fortiapi::dirty(thing));
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), json::object());
}

TEST(Serialize, UpdateSendsOnlyModifiedAndCleared) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    thing.comment = "changed";
    thing.port.clear();
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), (json{{"comment", "changed"}, {"port", 443}}));
}

TEST(Serialize, AbsentFieldsAreNeverSent) {
    Thing fresh;
    fresh.name = "new";
    EXPECT_EQ(fortiapi::to_json(fresh, Write::create), (json{{"name", "new"}}));
    EXPECT_EQ(fortiapi::to_json(fresh, Write::update), (json{{"name", "new"}}));
}

TEST(Serialize, CreateSendsEverythingKnownExceptReadOnly) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    auto body = fortiapi::to_json(thing, Write::create);
    EXPECT_FALSE(body.contains("serial"));
    EXPECT_FALSE(body.contains("unknown-key"));
    EXPECT_EQ(body["port"], 8443);
    EXPECT_EQ(body["inner"], (json{{"mode", "on"}, {"level", 5}}));
    EXPECT_EQ(body["members"], (json::array({{{"name", "lan"}}})));
}

TEST(Serialize, ReadOnlyIsNeverSentEvenWhenModified) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    thing.serial = "forged";
    EXPECT_FALSE(fortiapi::dirty(thing));
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), json::object());
}

TEST(Serialize, NestedObjectUpdateSendsOnlyItsChangedAttributes) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    thing.inner.edit().level = 9;
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), (json{{"inner", {{"level", 9}}}}));
}

TEST(Serialize, ModifiedTableIsSentWhole) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    Thing::ItemsEntry entry;
    entry.id = 3u;
    entry.note = "z";
    thing.items.edit().push_back(entry);
    auto body = fortiapi::to_json(thing, Write::update);
    ASSERT_EQ(body.size(), 1u);
    EXPECT_EQ(body["items"], (json::array({{{"id", 1}, {"note", "x"}}, {{"id", 2}, {"note", "y"}}, {{"id", 3}, {"note", "z"}}})));
}

TEST(Serialize, ClearedTableAndObjectUseTheirResetValues) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    thing.items.clear();
    thing.inner.clear();
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), (json{{"inner", json::object()}, {"items", json::array()}}));
}

TEST(Serialize, MarkCleanAfterAWrite) {
    auto thing = fortiapi::from_json<Thing>(device_thing());
    thing.comment = "changed";
    thing.port.clear();
    thing.inner.edit().mode = "auto";
    fortiapi::mark_clean(thing);
    EXPECT_EQ(thing.comment.state(), FieldState::populated);
    EXPECT_EQ(thing.port.state(), FieldState::absent);
    EXPECT_EQ(thing.inner->mode.state(), FieldState::populated);
    EXPECT_FALSE(fortiapi::dirty(thing));
}

TEST(Serialize, RefConvertsFromNames) {
    Thing thing;
    thing.members = std::vector<fortiapi::Ref>{"lan", std::string("wan1")};
    EXPECT_EQ(fortiapi::to_json(thing, Write::update), (json{{"members", {{{"name", "lan"}}, {{"name", "wan1"}}}}}));
}

TEST(Serialize, DeviceNumberQuirks) {
    auto thing = fortiapi::from_json<Thing>(json{{"port", ""}, {"inner", {{"level", "7"}}}});
    EXPECT_EQ(thing.port.state(), FieldState::absent);       // unset integer reported as ""
    EXPECT_EQ(thing.inner->level.value(), 7u);                // number reported as text
    EXPECT_THROW(fortiapi::from_json<Thing>(json{{"port", "12x"}}), fortiapi::detail::DecodeFailure);
}

TEST(Serialize, WrongShapesNameTheAttribute) {
    auto where = [](const json& input) {
        try {
            fortiapi::from_json<Thing>(input);
        } catch (const fortiapi::detail::DecodeFailure& failure) {
            return failure.where;
        }
        return std::string("<no error>");
    };
    EXPECT_EQ(where(json{{"port", "not a number"}}), "port");
    EXPECT_EQ(where(json{{"items", "not a list"}}), "items");
    EXPECT_EQ(where(json{{"items", json::array({json::object({{"id", 1}}), json::object({{"id", "x"}})})}}), "items[1].id");
    EXPECT_EQ(where(json{{"inner", json::object({{"level", "high"}})}}), "inner.level");
    EXPECT_THROW(fortiapi::from_json<Thing>(json::array()), json::exception);
}

TEST(Generated, DnsProfileRoundTripsTheDeviceShape) {
    json device = {{"name", "home"}, {"comment", ""}, {"block-action", "redirect"},
                   {"domain-filter", {{"domain-filter-table", 0}}},
                   {"ftgd-dns", {{"options", ""}, {"filters", {{{"id", 1}, {"category", 26}, {"action", "block"}, {"log", "enable"}}}}}},
                   {"dns-translation", json::array()}, {"external-ip-blocklist", json::array()}};
    auto profile = fortiapi::from_json<fortiapi::dnsfilter::Profile>(device);
    EXPECT_EQ(profile.ftgd_dns->filters->front().category.value(), 26u);
    EXPECT_EQ(*profile.block_action, fortiapi::dnsfilter::Profile::BlockAction::redirect);

    profile.comment = "managed";
    EXPECT_EQ(fortiapi::to_json(profile, Write::update), (json{{"comment", "managed"}}));
}

TEST(Generated, PolicyReferencesAreRefs) {
    fortiapi::firewall::Policy policy;
    policy.name = "forti-api-test-p";
    policy.srcintf = std::vector<fortiapi::Ref>{"lan"};
    policy.action = std::string(fortiapi::firewall::Policy::Action::deny);
    EXPECT_EQ(fortiapi::to_json(policy, Write::create),
              (json{{"name", "forti-api-test-p"}, {"srcintf", {{{"name", "lan"}}}}, {"action", "deny"}}));
}

namespace {
    struct Counter {
        Field<std::int64_t> bytes;
        template<typename Self, typename Visitor>
        static void visit(Self& self, Visitor&& v) { v("bytes", self.bytes, R"(0)", fortiapi::none); }
    };
}

TEST(Serialize, StringMapsRoundTrip) {
    using Map = std::map<std::string, Counter>;
    auto map = fortiapi::from_json<Map>(json{{"wan1", {{"bytes", 5}}}, {"lan", {{"bytes", 7}}}});
    EXPECT_EQ(map.at("lan").bytes.value(), 7);
    try {
        fortiapi::from_json<Map>(json{{"wan1", {{"bytes", "x"}}}});
        FAIL();
    } catch (const fortiapi::detail::DecodeFailure& failure) {
        EXPECT_EQ(failure.where, "[wan1].bytes");
    }
    auto vec = fortiapi::from_json<std::vector<Counter>>(json::array({json::object({{"bytes", 1}})}));
    EXPECT_EQ(vec.at(0).bytes.value(), 1);
}
