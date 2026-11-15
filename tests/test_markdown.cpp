#include "tests/test.hpp"
#include "src/report/markdown.hpp"
#include <sstream>

static report::Entry md_entry(report::Kind k, uint64_t va) {
	report::Entry e{};
	e.kind = k;
	char name[32];
	std::snprintf(name, sizeof(name), "%s_%llX", k == report::Kind::Added ? "new" : "sub", static_cast<unsigned long long>(va));
	e.name = name;
	e.old_va = k == report::Kind::Added ? 0 : va;
	e.new_va = k == report::Kind::Removed ? 0 : va + 0x100;
	e.old_size = 0x10; e.new_size = 0x14;
	e.similarity = 0.75f;
	if (k != report::Kind::Added) e.asm_old = { "push rbx", "ret" };
	if (k != report::Kind::Removed) e.asm_new = { "push rbx", "nop", "ret" };
	return e;
}

static std::vector<std::string> split_lines(const std::string& s) {
	std::vector<std::string> out;
	std::stringstream ss(s);
	for (std::string l; std::getline(ss, l);) out.push_back(l);
	return out;
}

static size_t count_of(const std::string& hay, const std::string& needle) {
	size_t n = 0;
	for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1)) ++n;
	return n;
}

static bool line_range(const std::string& agent, const std::string& name, size_t& first, size_t& last) {
	for (auto& l : split_lines(agent)) {
		if (l.find("`" + name + "`") == std::string::npos) continue;
		auto at = l.find("lines ");
		if (at == std::string::npos) continue;
		return std::sscanf(l.c_str() + at, "lines %zu-%zu", &first, &last) == 2;
	}
	return false;
}

TEST(md_full_has_every_entry_with_diffs) {
	report::Data d{};
	auto c = md_entry(report::Kind::Changed, 0x140001000);
	c.c_old = { "int f() {", "  return 1;", "}" };
	c.c_new = { "int f() {", "  return 2;", "}" };
	c.sig_old = "48 89 5C 24 ? 57";
	c.sig_new = "48 89 5C 24 ? 55";
	c.sig_note = "the old signature finds nothing in the new exe";
	c.c_error_new = "";
	d.entries = { c, md_entry(report::Kind::Added, 0x140009000), md_entry(report::Kind::Removed, 0x140005000), md_entry(report::Kind::RefChanged, 0x140003000) };
	auto md = report::markdown(d);
	CHECK(count_of(md.full, "\n## ") == 4);
	CHECK(md.full.find("\n## changed sub_140001000\n") != std::string::npos);
	CHECK(md.full.find("\n## calls changed sub_140003000\n") != std::string::npos);
	CHECK(md.full.find("\n## added new_140009000\n") != std::string::npos);
	CHECK(md.full.find("\n## removed sub_140005000\n") != std::string::npos);
	CHECK(md.full.find("- " "  return 1;") != std::string::npos);
	CHECK(md.full.find("+ " "  return 2;") != std::string::npos);
	CHECK(md.full.find("+ nop") != std::string::npos);
	CHECK(md.full.find("48 89 5C 24 ? 57") != std::string::npos);
	CHECK(md.full.find("the old signature finds nothing in the new exe") != std::string::npos);
	CHECK(md.full.find("```diff") != std::string::npos);
	CHECK(count_of(md.full, "```") % 2 == 0);
}

TEST(md_agent_line_ranges_point_at_entries) {
	report::Data d{};
	for (uint64_t i = 0; i < 5; ++i) d.entries.push_back(md_entry(report::Kind::Changed, 0x140001000 + i * 0x1000));
	d.entries.push_back(md_entry(report::Kind::Added, 0x140009000));
	d.entries.push_back(md_entry(report::Kind::Removed, 0x14000A000));
	auto md = report::markdown(d);
	auto full = split_lines(md.full);
	CHECK(md.agent.find(report::kFullMarkdown) != std::string::npos);
	for (auto& e : d.entries) {
		size_t first = 0, last = 0;
		CHECK(line_range(md.agent, e.name, first, last));
		CHECK(first >= 1 && first <= last && last <= full.size());
		if (first < 1 || last > full.size()) continue;
		CHECK(full[first - 1].starts_with("## ") && full[first - 1].ends_with(" " + e.name));
		CHECK(last == full.size() || full[last].starts_with("## "));
	}
}

TEST(md_agent_caps_long_lists) {
	report::Data d{};
	for (uint64_t i = 0; i < 150; ++i) {
		auto e = md_entry(report::Kind::Changed, 0x140001000 + i * 0x1000);
		for (uint64_t k = 0; k < i; ++k) e.asm_new.push_back("nop");
		d.entries.push_back(e);
	}
	auto md = report::markdown(d);
	CHECK(md.agent.find("100 of 150") != std::string::npos);
	size_t first = 0, last = 0;
	CHECK(line_range(md.agent, "sub_140096000", first, last));
	CHECK(!line_range(md.agent, "sub_140001000", first, last));
	CHECK(md.agent.find("`sub_140096000`") < md.agent.find("`sub_140095000`"));
	CHECK(md.agent.size() < md.full.size());
}

TEST(md_agent_lists_new_and_removed_strings) {
	report::Data d{};
	auto c = md_entry(report::Kind::Changed, 0x140001000);
	c.c_old = { "f(\"kept\");", "g(\"old text\");" };
	c.c_new = { "f(\"kept\");", "g(L\"new \\\"quoted\\\" text\");" };
	d.entries.push_back(c);
	auto a = md_entry(report::Kind::Added, 0x140009000);
	a.c_new = { "h(\"added func string\");" };
	d.entries.push_back(a);
	auto md = report::markdown(d);
	auto added = md.agent.find("## Strings only in the new exe");
	auto removed = md.agent.find("## Strings only in the old exe");
	CHECK(added != std::string::npos && removed != std::string::npos);
	if (added == std::string::npos || removed == std::string::npos) return;
	auto in = [&](size_t from, size_t to, const char* s) { auto at = md.agent.find(s, from); return at != std::string::npos && at < to; };
	size_t end = md.agent.size();
	CHECK(added < removed);
	CHECK(in(added, removed, "\"new \\\"quoted\\\" text\""));
	CHECK(in(added, removed, "\"added func string\""));
	CHECK(in(removed, end, "\"old text\""));
	CHECK(md.agent.find("\"kept\"") == std::string::npos);
}

TEST(md_agent_says_when_c_is_missing) {
	report::Data d{};
	d.entries.push_back(md_entry(report::Kind::Changed, 0x140001000));
	CHECK(report::markdown(d).agent.find("exediff.bat") != std::string::npos);
}
