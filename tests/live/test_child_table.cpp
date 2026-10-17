// ChildTable against the live device: single-entry writes on child paths of forti-api-test-* objects
// in approved collections (guard.hpp admits child paths only below a test parent, and name-keyed
// entries only when they are test objects too), each step checked against a full read of the parent.
//
// Observed on FortiOS 7.4.8 build 2795 (FortiGate-60F), 2026-10-17. Every write reply carries
// http_method, http_status, status, path ("router"), name ("access-list"), vdom, revision and, on
// success, old_revision and revision_changed (true). Child replies add child_path (the attribute).
// What `mkey` names depends on the method:
//
//   POST   <parent>/<attr>          200  mkey = new entry's key (2, or "forti-api-test-..."); no child_mkey
//   PUT    <parent>/<attr>/<entry>  200  mkey = parent key ("forti-api-test-ct-acl"); child_mkey = "10" (text)
//   DELETE <parent>/<attr>/<entry>  200  mkey = entry key (10, typed); child_mkey = "10" (text)
//   POST   existing entry key       500  error -5, cli_error [], mkey = parent key, revision_changed false;
//                                        the existing entry is unchanged (a POST never overwrites)
//   GET/PUT/DELETE missing entry    404  no error code, mkey = parent key, child_path; a PUT never creates
//   any method, missing parent      404  no error code, mkey = parent key, no child_path; a POST never
//                                        creates the parent
//
// Device-assigned ids: POST with id 0 gets max(id) + 1 (rules 1 -> 2; 1,2,3 -> 4 ...), reported only as
// `mkey`. Deleting the last member of an address group succeeds (the group is left with no member).
// `revision` is per cmdb table (all objects of router.access-list share one chain: a write's
// old_revision is the previous write's revision on that table, whichever object it touched), and a GET
// envelope (cmdb/router/access-list/<name>) reports the table's current revision, equal to the last
// write's `revision`.
//
// Concurrency (two Client instances, separate connections):
//   - back-to-back and simultaneous POSTs with id 0: both succeed, distinct ids (the device
//     serializes them: old_revision of the second = revision of the first);
//   - simultaneous POSTs with the same explicit id: the first wins (200), the second fails 500 / -5,
//     nothing is overwritten;
//   - an entry PUT (B) between a parent read and a sparse parent PUT of another attribute (A): both
//     changes survive;
//   - an entry PUT and an entry POST (B) between a parent read and a parent PUT that includes the
//     stale table (A): the parent PUT wins silently (200): B's entry change is reverted and B's new
//     entry deleted. The only trace is old_revision in A's reply differing from the revision of A's
//     read (the GET envelope's `revision`).
//
// Config log (log/memory/event/system): child writes are logged against the PARENT, as an Edit:
// cfgpath = the table ("router.access-list"), cfgobj = the parent's name, cfgattr = "rule:7[action[deny]
// prefix[...]action[deny->permit]...<Delete>]" (add, update and delete of one entry within seconds
// fold into one record, as do edits shortly after the parent's Add). ConfigAudit therefore attributes
// them to the test parent.
#include <gtest/gtest.h>
#include "live.hpp"

#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

using namespace fortiapi;

namespace {

    using Members = firewall::AddressGroups::child<&firewall::AddressGroup::member>;
    using Rules = router::AccessLists::child<&router::AccessList::rule>;
    using RuleEntry = router::AccessList::RuleEntry;

    std::mutex print_mutex;

    // Prints what the device answered to each write and failed read, so a run records the reply shapes.
    void observe(const Exchange& exchange) {
        if (exchange.method == Method::Get && exchange.http_status < 400) return;
        auto at = exchange.url.find("/api/v2/");
        auto path = exchange.url.substr(at == std::string::npos ? 0 : at + 8);
        auto body = nlohmann::json::parse(exchange.response_body, nullptr, false);
        if (body.is_object()) for (const char* noise: {"serial", "version", "build"}) body.erase(noise);
        std::lock_guard lock(print_mutex);
        std::cout << "[observed] " << to_string(exchange.method) << " " << path << " " << exchange.request_body
                  << " -> " << exchange.http_status << " " << (body.is_discarded() ? exchange.response_body : body.dump())
                  << std::endl;
    }

    std::shared_ptr<Client> client() { return live::guarded_client(observe); }

    // The outcome of a request that may fail: HTTP status and FortiOS error code ({200, 0} on success).
    struct Outcome {
        long http_status = 200;
        int fortios_error = 0;
        bool operator==(const Outcome&) const = default;
    };

    std::ostream& operator<<(std::ostream& out, const Outcome& outcome) {
        return out << "HTTP " << outcome.http_status << " error " << outcome.fortios_error;
    }

    template<typename F>
    Outcome attempt(F&& f) {
        try {
            f();
            return {};
        } catch (const ApiError& error) {
            return {error.http_status(), error.fortios_error()};
        }
    }

    const Outcome not_found{404, 0};
    const Outcome entry_exists{500, -5};

    template<typename Endpoint>
    struct Created {   // a test object, removed again on scope exit (also when an assertion fails)
        std::string name;
        Created(typename Endpoint::type object, Client& client) : name(*object.name) {
            EXPECT_TRUE(live::is_test_object(name));
            Endpoint::add(object, {}, client);
        }
        ~Created() { try { live::del_test<Endpoint>(name); } catch (...) {} }
        Created(const Created&) = delete;
        Created& operator=(const Created&) = delete;
    };

    firewall::Address address(std::string_view suffix, std::string_view ip) {
        firewall::Address a;
        a.name = live::name(suffix);
        a.subnet = std::string(ip) + " 255.255.255.255";
        a.comment = std::string(live::comment);
        return a;
    }

    std::vector<std::string> member_names(const firewall::AddressGroup& group) {
        std::vector<std::string> names;
        for (const auto& ref: group.member.value_or(std::vector<Ref>{})) names.push_back(ref.name.value_or(""));
        return names;
    }

    RuleEntry rule(std::uint32_t id, std::string_view prefix, std::string_view action) {
        RuleEntry entry;
        entry.id = id;
        entry.prefix = std::string(prefix);
        entry.action = std::string(action);
        return entry;
    }

    router::AccessList access_list(std::string_view suffix, std::vector<RuleEntry> rules) {
        router::AccessList acl;
        acl.name = live::name(suffix);
        acl.comments = std::string(live::comment);
        acl.rule = std::move(rules);
        return acl;
    }

    // id -> "prefix/action/exact-match" for every rule of the parent, read in full.
    std::map<std::uint32_t, std::string> rules_of(const std::string& acl, Client& client) {
        std::map<std::uint32_t, std::string> out;
        for (const auto& entry: router::AccessLists::get(acl, {}, client).rule.value_or(std::vector<RuleEntry>{}))
            out[entry.id.value_or(0)] = entry.prefix.value_or("") + "/" + entry.action.value_or("") + "/" +
                                        entry.exact_match.value_or("");
        return out;
    }

    void expect_success(const Reply& reply, std::string_view child_path) {
        EXPECT_EQ(reply.http_status, 200);
        EXPECT_EQ(reply.status, "success");
        EXPECT_EQ(reply.child_path, child_path);
        EXPECT_FALSE(reply.revision.empty());
        EXPECT_FALSE(reply.old_revision.empty());
        EXPECT_NE(reply.revision, reply.old_revision);
        EXPECT_TRUE(reply.revision_changed);
    }

}  // namespace

TEST(ChildTable, AddressGroupMembers) {
    auto c = client();
    Created<firewall::Addresses> a(address("ct-member-a", "192.0.2.21"), *c);
    Created<firewall::Addresses> b(address("ct-member-b", "192.0.2.22"), *c);
    Created<firewall::Addresses> outsider(address("ct-member-c", "192.0.2.23"), *c);

    firewall::AddressGroup group;
    group.name = live::name("ct-group");
    group.comment = std::string(live::comment);
    group.member = std::vector<Ref>{a.name};
    const std::string g = *group.name;
    live::Cleanup cleanup([&] { live::del_test<firewall::AddressGroups>(g); });   // before the members
    firewall::AddressGroups::add(group, {}, *c);

    // add: one more member, the existing one untouched.
    Ref second(b.name);
    auto added = Members::add(g, second, {}, *c);
    expect_success(added, "member");
    EXPECT_EQ(added.mkey, b.name);   // POST: the entry's key
    EXPECT_TRUE(added.child_mkey.is_null());
    EXPECT_FALSE(dirty(second));
    auto parent = firewall::AddressGroups::get(g, {}, *c);
    EXPECT_EQ(member_names(parent), (std::vector<std::string>{a.name, b.name}));
    EXPECT_EQ(*parent.comment, live::comment);

    // get / find / contains / list.
    EXPECT_EQ(*Members::get(g, b.name, {}, *c).name, b.name);
    EXPECT_TRUE(Members::contains(g, a.name, {}, *c));
    EXPECT_FALSE(Members::find(g, outsider.name, {}, *c).has_value());
    EXPECT_EQ(attempt([&] { Members::get(g, outsider.name, {}, *c); }), not_found);
    auto listed = Members::list(g, {}, *c);
    ASSERT_EQ(listed.size(), 2u);
    EXPECT_EQ(*listed[0].name, a.name);
    EXPECT_EQ(*listed[1].name, b.name);

    // add of an existing member: refused, nothing changes.
    Ref again(b.name);
    EXPECT_EQ(attempt([&] { Members::add(g, again, {}, *c); }), entry_exists);
    EXPECT_EQ(member_names(firewall::AddressGroups::get(g, {}, *c)), (std::vector<std::string>{a.name, b.name}));

    // del: one member, the other untouched.
    auto removed = Members::del(g, a.name, {}, *c);
    expect_success(removed, "member");
    EXPECT_EQ(removed.mkey, a.name);         // DELETE: the entry's key
    EXPECT_EQ(removed.child_mkey, a.name);
    parent = firewall::AddressGroups::get(g, {}, *c);
    EXPECT_EQ(member_names(parent), (std::vector<std::string>{b.name}));
    EXPECT_EQ(*parent.comment, live::comment);
    EXPECT_EQ(attempt([&] { Members::del(g, a.name, {}, *c); }), not_found);

    // The last member can go too: the group is left empty.
    Members::del(g, b.name, {}, *c);
    EXPECT_TRUE(member_names(firewall::AddressGroups::get(g, {}, *c)).empty());
    EXPECT_TRUE(Members::list(g, {}, *c).empty());

    // A missing parent: 404 for every method, and a POST does not create it.
    const std::string missing = live::name("ct-no-such-group");
    live::Cleanup no_group([&] { live::del_test<firewall::AddressGroups>(missing); });
    EXPECT_FALSE(Members::find(missing, a.name, {}, *c).has_value());
    EXPECT_EQ(attempt([&] { Members::list(missing, {}, *c); }), not_found);
    Ref orphan(a.name);
    EXPECT_EQ(attempt([&] { Members::add(missing, orphan, {}, *c); }), not_found);
    EXPECT_EQ(attempt([&] { Members::del(missing, a.name, {}, *c); }), not_found);
    EXPECT_FALSE(firewall::AddressGroups::contains(missing, {}, *c));
}

TEST(ChildTable, AccessListRules) {
    auto c = client();
    auto first = rule(1, "192.0.2.0 255.255.255.0", "permit");
    first.exact_match = std::string(RuleEntry::ExactMatch::enable);
    auto acl = access_list("ct-acl", {first});
    const std::string n = *acl.name;
    live::Cleanup cleanup([&] { live::del_test<router::AccessLists>(n); });
    router::AccessLists::add(acl, {}, *c);
    const std::string rule1 = "192.0.2.0 255.255.255.0/permit/enable";

    // add with id 0: the device assigns the next id and reports it as mkey; add() stores it.
    auto assigned = rule(0, "198.51.100.0 255.255.255.0", "deny");
    auto reply = Rules::add(n, assigned, {}, *c);
    expect_success(reply, "rule");
    EXPECT_EQ(reply.mkey, 2);
    EXPECT_TRUE(reply.child_mkey.is_null());
    EXPECT_EQ(*assigned.id, 2u);
    EXPECT_FALSE(dirty(assigned));
    EXPECT_EQ(rules_of(n, *c), (std::map<std::uint32_t, std::string>{
            {1, rule1}, {2, "198.51.100.0 255.255.255.0/deny/disable"}}));

    // add with an explicit id.
    auto explicit_id = rule(10, "203.0.113.0 255.255.255.0", "permit");
    explicit_id.exact_match = std::string(RuleEntry::ExactMatch::enable);
    reply = Rules::add(n, explicit_id, {}, *c);
    expect_success(reply, "rule");
    EXPECT_EQ(reply.mkey, 10);
    EXPECT_EQ(*explicit_id.id, 10u);

    // update sends only the modified attribute; the entry's others and the other entries keep theirs.
    auto stored = Rules::get(n, 10, {}, *c);
    EXPECT_EQ(*stored.prefix, "203.0.113.0 255.255.255.0");
    stored.action = std::string(RuleEntry::Action::deny);
    EXPECT_EQ(to_json(stored, Write::update), (nlohmann::json{{"action", "deny"}}));
    auto updated = Rules::update(n, stored, {}, *c);
    ASSERT_TRUE(updated.has_value());
    expect_success(*updated, "rule");
    EXPECT_EQ(updated->mkey, n);        // PUT: the parent's key
    EXPECT_EQ(updated->child_mkey, "10");
    EXPECT_FALSE(Rules::update(n, stored, {}, *c).has_value());   // nothing left to send
    EXPECT_EQ(rules_of(n, *c), (std::map<std::uint32_t, std::string>{
            {1, rule1}, {2, "198.51.100.0 255.255.255.0/deny/disable"}, {10, "203.0.113.0 255.255.255.0/deny/enable"}}));
    EXPECT_EQ(*router::AccessLists::get(n, {}, *c).comments, live::comment);

    // add of an existing id: refused, the entry keeps its values.
    auto duplicate = rule(10, "192.0.2.128 255.255.255.128", "permit");
    EXPECT_EQ(attempt([&] { Rules::add(n, duplicate, {}, *c); }), entry_exists);
    EXPECT_EQ(*Rules::get(n, 10, {}, *c).prefix, "203.0.113.0 255.255.255.0");

    // del.
    reply = Rules::del(n, 10, {}, *c);
    expect_success(reply, "rule");
    EXPECT_EQ(reply.mkey, 10);           // DELETE: the entry's key
    EXPECT_EQ(reply.child_mkey, "10");
    EXPECT_FALSE(Rules::find(n, 10, {}, *c).has_value());
    EXPECT_EQ(rules_of(n, *c), (std::map<std::uint32_t, std::string>{
            {1, rule1}, {2, "198.51.100.0 255.255.255.0/deny/disable"}}));

    // A missing entry: 404, and a PUT does not create it.
    EXPECT_FALSE(Rules::find(n, 999, {}, *c).has_value());
    EXPECT_EQ(attempt([&] { Rules::get(n, 999, {}, *c); }), not_found);
    EXPECT_EQ(attempt([&] { Rules::del(n, 999, {}, *c); }), not_found);
    auto ghost = Rules::get(n, 2, {}, *c);
    ghost.id.load(998);
    ghost.action = std::string(RuleEntry::Action::permit);
    EXPECT_EQ(attempt([&] { Rules::update(n, ghost, {}, *c); }), not_found);
    EXPECT_TRUE(dirty(ghost));
    EXPECT_FALSE(Rules::contains(n, 998, {}, *c));

    // A missing parent: 404 for every method, and a POST does not create it.
    const std::string missing = live::name("ct-no-such-acl");
    live::Cleanup no_acl([&] { live::del_test<router::AccessLists>(missing); });
    EXPECT_FALSE(Rules::find(missing, 1, {}, *c).has_value());
    EXPECT_EQ(attempt([&] { Rules::get(missing, 1, {}, *c); }), not_found);
    EXPECT_EQ(attempt([&] { Rules::list(missing, {}, *c); }), not_found);
    auto orphan = rule(5, "192.0.2.0 255.255.255.0", "deny");
    EXPECT_EQ(attempt([&] { Rules::add(missing, orphan, {}, *c); }), not_found);
    ghost.id.load(5);
    EXPECT_EQ(attempt([&] { Rules::update(missing, ghost, {}, *c); }), not_found);
    EXPECT_EQ(attempt([&] { Rules::del(missing, 1, {}, *c); }), not_found);
    EXPECT_FALSE(router::AccessLists::contains(missing, {}, *c));
}

// How the device logs child writes, which is what ConfigAudit relies on: against the parent object.
// The pause keeps the child writes out of the parent's Add record (FortiOS folds edits made shortly
// after a create into it).
TEST(ChildTable, ChildWritesAreLoggedAgainstTheParent) {
    auto c = client();
    auto acl = access_list("ct-logged", {rule(1, "192.0.2.0 255.255.255.0", "permit")});
    const std::string n = *acl.name;
    live::Cleanup cleanup([&] { live::del_test<router::AccessLists>(n); });
    router::AccessLists::add(acl, {}, *c);
    std::this_thread::sleep_for(std::chrono::seconds(15));

    live::ConfigAudit audit;
    audit.begin(*c);
    auto added = rule(7, "198.51.100.7 255.255.255.255", "deny");
    Rules::add(n, added, {}, *c);
    added.action = std::string(RuleEntry::Action::permit);
    Rules::update(n, added, {}, *c);
    Rules::del(n, 7, {}, *c);

    std::vector<std::string> attributes;
    for (const auto& change: audit.changes(*c)) {
        std::cout << "[log] " << change.value("action", "") << " cfgpath=" << change.value("cfgpath", "")
                  << " cfgobj=" << change.value("cfgobj", "") << " cfgattr=" << change.value("cfgattr", "") << std::endl;
        if (change.value("cfgpath", "").starts_with("router.access-list"))
            EXPECT_TRUE(live::is_test_object(change.value("cfgobj", ""))) << change.dump();
        if (change.value("cfgobj", "") != n) continue;
        EXPECT_EQ(change.value("cfgpath", ""), "router.access-list");
        for (auto& attribute: live::attribute_names(change.value("cfgattr", ""))) attributes.push_back(attribute);
    }
    ASSERT_FALSE(attributes.empty());
    for (const auto& attribute: attributes) EXPECT_EQ(attribute, "rule:7");
}

TEST(ChildTable, Concurrency) {
    auto a = client();
    auto b = client();
    auto acl = access_list("ct-concurrent", {rule(1, "192.0.2.0 255.255.255.0", "permit")});
    const std::string n = *acl.name;
    live::Cleanup cleanup([&] { live::del_test<router::AccessLists>(n); });
    router::AccessLists::add(acl, {}, *a);

    // Back to back from two clients, device-assigned ids: both survive with distinct ids.
    auto ra = rule(0, "198.51.100.1 255.255.255.255", "deny");
    auto rb = rule(0, "198.51.100.2 255.255.255.255", "deny");
    auto reply_a = Rules::add(n, ra, {}, *a);
    auto reply_b = Rules::add(n, rb, {}, *b);
    EXPECT_EQ(*ra.id, 2u);
    EXPECT_EQ(*rb.id, 3u);
    EXPECT_EQ(reply_b.old_revision, reply_a.revision);
    EXPECT_EQ(rules_of(n, *a).size(), 3u);

    // Simultaneous, device-assigned ids: serialized by the device, both survive.
    auto ta = rule(0, "198.51.100.3 255.255.255.255", "deny");
    auto tb = rule(0, "198.51.100.4 255.255.255.255", "deny");
    Outcome oa, ob;
    {
        std::thread ja([&] { oa = attempt([&] { Rules::add(n, ta, {}, *a); }); });
        std::thread jb([&] { ob = attempt([&] { Rules::add(n, tb, {}, *b); }); });
        ja.join();
        jb.join();
    }
    EXPECT_EQ(oa, Outcome{});
    EXPECT_EQ(ob, Outcome{});
    EXPECT_NE(*ta.id, *tb.id);
    auto now = rules_of(n, *a);
    EXPECT_EQ(now.size(), 5u);
    EXPECT_EQ(now[*ta.id], "198.51.100.3 255.255.255.255/deny/disable");
    EXPECT_EQ(now[*tb.id], "198.51.100.4 255.255.255.255/deny/disable");

    // Simultaneous, the same explicit id: one wins, the other is refused; nothing is overwritten.
    auto sa = rule(50, "198.51.100.50 255.255.255.255", "deny");
    auto sb = rule(50, "198.51.100.51 255.255.255.255", "permit");
    {
        std::thread ja([&] { oa = attempt([&] { Rules::add(n, sa, {}, *a); }); });
        std::thread jb([&] { ob = attempt([&] { Rules::add(n, sb, {}, *b); }); });
        ja.join();
        jb.join();
    }
    EXPECT_TRUE((oa == Outcome{} && ob == entry_exists) || (oa == entry_exists && ob == Outcome{})) << oa << ", " << ob;
    auto winner = Rules::get(n, 50, {}, *a);
    EXPECT_EQ(*winner.prefix, oa == Outcome{} ? *sa.prefix : *sb.prefix);

    // A reads the parent; B changes one entry; A writes another attribute of the parent (sparse PUT,
    // Table::update): both changes survive.
    auto snapshot = router::AccessLists::get(n, {}, *a);
    auto entry = Rules::get(n, 1, {}, *b);
    entry.action = std::string(RuleEntry::Action::deny);
    ASSERT_TRUE(Rules::update(n, entry, {}, *b).has_value());
    snapshot.comments = std::string(live::comment) + " Sparse.";
    ASSERT_TRUE(router::AccessLists::update(snapshot, {}, *a).has_value());
    auto parent = router::AccessLists::get(n, {}, *a);
    EXPECT_EQ(*parent.comments, std::string(live::comment) + " Sparse.");
    EXPECT_EQ(rules_of(n, *a)[1], "192.0.2.0 255.255.255.0/deny/disable");

    // A reads the parent; B changes an entry and adds one; A writes the parent including its stale
    // table: last write wins for the whole table, silently. B's change is reverted, B's entry gone.
    auto table_revision = [&](Client& client) {
        auto body = client.get(fortiapi::path(router::AccessLists::path, n));
        return body.value("revision", std::string());
    };
    auto stale = router::AccessLists::get(n, {}, *a);
    const std::string read_revision = table_revision(*a);
    auto changed = Rules::get(n, 1, {}, *b);
    changed.prefix = std::string("192.0.2.64 255.255.255.192");
    ASSERT_TRUE(Rules::update(n, changed, {}, *b).has_value());
    auto late = rule(70, "198.51.100.70 255.255.255.255", "deny");
    Rules::add(n, late, {}, *b);
    stale.comments = std::string(live::comment) + " Full.";
    stale.rule.edit();   // send the whole (stale) table
    auto full = router::AccessLists::update(stale, {}, *a);
    ASSERT_TRUE(full.has_value());
    EXPECT_EQ(full->status, "success");
    now = rules_of(n, *a);
    EXPECT_EQ(now[1], "192.0.2.0 255.255.255.0/deny/disable");   // B's prefix change reverted
    EXPECT_FALSE(now.contains(70));                                // B's entry deleted
    EXPECT_EQ(now.size(), 6u);
    // The trace: the table revision A read is not the one A's write replaced, and a read after the
    // write reports the write's revision.
    EXPECT_FALSE(read_revision.empty());
    EXPECT_NE(full->old_revision, read_revision);
    EXPECT_EQ(table_revision(*a), full->revision);
}
