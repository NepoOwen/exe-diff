#include "tests/test.hpp"
#include "src/report/html.hpp"
#include "src/report/markdown.hpp"
#include "src/report/notes.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

// The architecture and the notes (what an x86 comparison could not see) in the reports

namespace fs = std::filesystem;

static std::string html_of(const report::Data& d) {
	auto dir = fs::temp_directory_path() / "exediff_tests";
	fs::create_directories(dir);
	auto p = dir / "notes.html";
	std::string err;
	CHECK(report::write_html(p.c_str(), d, err));
	std::ifstream f(p, std::ios::binary);
	std::stringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

static bool has(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

TEST(report_notes_appear_in_html) {
	report::Data d{};
	d.notes = { "x86 note one", "note <two>" };
	auto html = html_of(d);
	CHECK(has(html, "x86 note one"));
	CHECK(has(html, "note &lt;two&gt;"));
	CHECK(!has(html, "note <two>"));
}

TEST(report_without_notes_has_no_notes_block) {
	report::Data d{};
	CHECK(!has(html_of(d), "class=\"notes\""));
	auto md = report::markdown(d);
	CHECK(!has(md.full, "- note:") && !has(md.agent, "- note:"));
}

TEST(report_arch_shown_in_html) {
	report::Data d{};
	d.arch = "x86";
	CHECK(has(html_of(d), "architecture: x86"));
	d.arch.clear();
	CHECK(!has(html_of(d), "architecture:"));
}

TEST(report_notes_and_arch_in_markdown) {
	report::Data d{};
	d.arch = "x86";
	d.notes = { "x86 note one" };
	auto md = report::markdown(d);
	CHECK(has(md.full, "- architecture: x86") && has(md.agent, "- architecture: x86"));
	CHECK(has(md.full, "- note: x86 note one") && has(md.agent, "- note: x86 note one"));
}

static func::Set set_with(std::initializer_list<std::pair<uint32_t, uint32_t>> funcs) {
	func::Set s;
	for (auto& f : funcs) { func::Function fn{}; fn.rva = f.first; fn.end = f.second; fn.size = f.second - f.first; s.funcs.push_back(fn); }
	return s;
}

TEST(notes_for_x86_coverage_line) {
	auto img = test::image_from_code_x86({ 0xC3 });
	auto s = set_with({ { 0x1000, 0x1001 } });
	s.exec_bytes = 1000; s.covered_bytes = 900;
	auto n = report::notes_for("old", "a.exe", img, s);
	CHECK(n.size() == 1);
	if (n.size() == 1) {
		CHECK(has(n[0], "old") && has(n[0], "a.exe"));
		CHECK(has(n[0], "1 functions found") || has(n[0], "1 function found"));
		CHECK(has(n[0], "100 of 1000"));
	}
}

TEST(notes_for_x64_has_none) {
	auto img = test::image_from_code({ 0xC3 });
	auto s = set_with({ { 0x1000, 0x1001 } });
	s.exec_bytes = 1000; s.covered_bytes = 900;
	CHECK(report::notes_for("old", "a.exe", img, s).empty());
}

TEST(notes_for_groups_skipped_by_reason) {
	auto img = test::image_from_code_x86({ 0xC3 });
	auto s = set_with({});
	s.skipped = { { 0x1040, "start does not decode" }, { 0x1050, "start does not decode" }, { 0x1060, "start does not decode" },
		{ 0x1070, "start does not decode" }, { 0x1080, "no end inside the section" } };
	auto n = report::notes_for("new", "b.exe", img, s);
	size_t decode_lines = 0, end_lines = 0;
	for (auto& l : n) {
		if (has(l, "start does not decode")) {
			++decode_lines;
			CHECK(has(l, "4"));
			CHECK(has(l, "0x401040") && has(l, "0x401050") && has(l, "0x401060"));
			CHECK(!has(l, "0x401070"));	// only the first three are listed
		}
		if (has(l, "no end inside the section")) { ++end_lines; CHECK(has(l, "0x401080")); }
	}
	CHECK(decode_lines == 1 && end_lines == 1);
}

TEST(notes_for_says_when_there_are_no_relocations) {
	auto img = test::image_from_code_x86({ 0xC3 });
	img.relocs_stripped = true;
	auto s = set_with({ { 0x1000, 0x1001 } });
	auto n = report::notes_for("old", "fixed.exe", img, s);
	bool found = false;
	for (auto& l : n) found |= has(l, "no relocations in fixed.exe: absolute addresses masked by range");
	CHECK(found);
	img.relocs_stripped = false;
	for (auto& l : report::notes_for("old", "fixed.exe", img, s)) CHECK(!has(l, "no relocations"));
}
