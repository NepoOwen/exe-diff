#include "tests/test.hpp"
#include "src/report/html.hpp"
#include "src/report/pair.hpp"
#include "src/util/md5.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

static fs::path temp_file(const char* name) {
	auto dir = fs::temp_directory_path() / "exediff_tests";
	fs::create_directories(dir);
	return dir / name;
}

static std::string slurp(const fs::path& p) {
	std::ifstream f(p, std::ios::binary);
	std::stringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

static size_t count_of(const std::string& hay, const std::string& needle) {
	size_t n = 0;
	for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1)) ++n;
	return n;
}

static report::Entry entry(report::Kind k, const char* name) {
	report::Entry e{};
	e.kind = k;
	e.name = name;
	e.old_va = k == report::Kind::Added ? 0 : 0x140001000;
	e.new_va = k == report::Kind::Removed ? 0 : 0x140002000;
	e.old_size = 0x10; e.new_size = 0x14;
	e.similarity = 0.8f;
	if (k != report::Kind::Added) e.asm_old = { "push rbx", "ret" };
	if (k != report::Kind::Removed) e.asm_new = { "push rbx", "nop", "ret" };
	return e;
}

static std::string write(const report::Data& d) {
	auto p = temp_file("report.html");
	std::string err;
	CHECK(report::write_html(p.c_str(), d, err));
	return slurp(p);
}

TEST(escape_html) {
	CHECK(report::escape("<script>alert(\"x\")&'") == "&lt;script&gt;alert(&quot;x&quot;)&amp;&#39;");
}

TEST(html_escapes_exe_strings) {
	report::Data d{};
	auto e = entry(report::Kind::Changed, "sub_140001000");
	e.asm_new = { "lea rcx, \"<script>alert(1)</script>\"" };
	d.entries.push_back(e);
	auto html = write(d);
	CHECK(html.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
	CHECK(html.find("<script>alert(1)") == std::string::npos);
}

TEST(html_has_every_entry) {
	report::Data d{};
	d.entries = { entry(report::Kind::Removed, "sub_14000AAAA"), entry(report::Kind::Added, "new_14000BBBB"),
		entry(report::Kind::RefChanged, "sub_14000CCCC"), entry(report::Kind::Changed, "sub_14000DDDD") };
	auto html = write(d);
	for (auto n : { "sub_14000AAAA", "new_14000BBBB", "sub_14000CCCC", "sub_14000DDDD" })
		CHECK(count_of(html, std::string("<span class=\"name\">") + n + "</span>") == 1);
	CHECK(count_of(html, "<summary") == 4);
	CHECK(html.find("sub_14000DDDD") < html.find("new_14000BBBB"));
	CHECK(html.find("new_14000BBBB") < html.find("sub_14000AAAA"));
}

TEST(html_shows_decompile_error) {
	report::Data d{};
	auto e = entry(report::Kind::Changed, "sub_140001000");
	e.c_error_new = "call analysis failed at 140001234";
	d.entries.push_back(e);
	CHECK(write(d).find("call analysis failed at 140001234") != std::string::npos);
}

TEST(html_warns_when_too_different) {
	report::Data d{};
	CHECK(write(d).find("too different") == std::string::npos);
	d.too_different = true;
	CHECK(write(d).find("too different") != std::string::npos);
}

static func::Set two_funcs(uint32_t base, uint64_t h0, uint64_t h1, uint64_t h2) {
	func::Set s;
	uint64_t hs[3] = { h0, h1, h2 };
	for (uint32_t i = 0; i < 3; ++i) {
		func::Function f{};
		f.rva = base + i * 0x100; f.end = f.rva + 0x10; f.size = 0x10; f.hash = hs[i];
		s.spans.push_back({ f.rva, f.end, i });
		s.funcs.push_back(f);
	}
	return s;
}

TEST(map_csv_rows) {
	auto ia = test::image_from_code({ 0xC3 });
	auto ib = test::image_from_code({ 0xC3 });
	auto a = two_funcs(0x1000, 1, 2, 3);
	auto b = two_funcs(0x1000, 1, 2, 4);
	b.funcs[2].rva = 0x1300; b.funcs[2].end = 0x1310;
	func::Function extra{};
	extra.rva = 0x1400; extra.end = 0x1410; extra.size = 0x10; extra.hash = 9;
	b.funcs.push_back(extra);
	a.funcs.push_back(extra);
	a.funcs[3].rva = 0x1500; a.funcs[3].end = 0x1510; a.funcs[3].hash = 8;
	match::Result r;
	r.pairs = { { 0, 0, match::Status::Same, 1.0f }, { 1, 1, match::Status::Same, 1.0f }, { 2, 2, match::Status::Changed, 0.5f, match::Method::Similar } };
	r.removed = { 3 };
	r.added = { 3 };
	match::Names n;
	match::name(ia, a, ib, b, r, n);
	auto p = temp_file("map.csv");
	std::string err;
	CHECK(report::write_map_csv(p.c_str(), ia, a, ib, b, r, n, err));
	auto csv = slurp(p);
	std::vector<std::string> rows;
	std::stringstream ss(csv);
	for (std::string line; std::getline(ss, line);) rows.push_back(line);
	CHECK(rows.size() == 6);
	CHECK(rows.size() == 6 && rows[0] == "status,name,old_va,new_va,old_size,new_size,method,similarity");
	CHECK(count_of(csv, "\nsame,") == 2);
	CHECK(count_of(csv, ",exact-unique,100\n") == 2);
	CHECK(csv.find("\nchanged,sub_140001200,0x140001200,0x140001300,16,16,similar,50\n") != std::string::npos);
	CHECK(csv.find("\nadded,new_140001400,,0x140001400,,16,,\n") != std::string::npos);
	CHECK(csv.find("\nremoved,sub_140001500,0x140001500,,16,,,\n") != std::string::npos);
}

TEST(html_write_fails_cleanly) {
	report::Data d{};
	std::string err;
	CHECK(!report::write_html(L"Z:\\no\\such\\dir\\report.html", d, err));
	CHECK(!err.empty());
}

TEST(html_shows_signatures) {
	report::Data d{};
	auto e = entry(report::Kind::Changed, "sub_140001000");
	e.sig_old = "48 89 5C 24 ? 57";
	e.sig_new = "48 89 5C 24 ? 55";
	e.sig_note = "the old signature finds nothing in the new exe";
	d.entries.push_back(e);
	auto same = entry(report::Kind::Changed, "sub_140005000");
	same.sig_old = same.sig_new = "40 53 48 83 EC ?";
	d.entries.push_back(same);
	auto failed = entry(report::Kind::Added, "new_140009000");
	failed.sig_error_new = "Signature not unique after 1000 bytes";
	d.entries.push_back(failed);
	auto html = write(d);
	CHECK(html.find("- 48 89 5C 24 ? 57") != std::string::npos);
	CHECK(html.find("+ 48 89 5C 24 ? 55") != std::string::npos);
	CHECK(html.find("the old signature finds nothing in the new exe") != std::string::npos);
	CHECK(html.find("  40 53 48 83 EC ?") != std::string::npos);
	CHECK(html.find("<h3>Signature (unchanged)") != std::string::npos);
	CHECK(html.find("Signature not unique after 1000 bytes") != std::string::npos);
	CHECK(count_of(html, "<h3>Signature") == 3);
}

TEST(html_search_key_has_signatures) {
	report::Data d{};
	auto e = entry(report::Kind::Changed, "sub_140001000");
	e.sig_old = "48 89 5C 24 ? 57";
	e.sig_new = "E8 ? ? ? ? 90";
	d.entries.push_back(e);
	auto html = write(d);
	auto at = html.find("data-k=\"");
	CHECK(at != std::string::npos);
	auto key = html.substr(at, html.find('"', at + 8) - at);
	CHECK(key.find("48 89 5c 24 ? 57") != std::string::npos);
	CHECK(key.find("e8 ? ? ? ? 90") != std::string::npos);
}

TEST(md5_known_vectors) {
	const uint8_t abc[] = { 'a', 'b', 'c' };
	CHECK(util::md5_hex(abc, 3) == "900150983cd24fb0d6963f7d28e17f72");
	CHECK(util::md5_hex(nullptr, 0) == "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(pair_txt_content) {
	report::PairSide a{ L"C:\\exes\\old.exe", 1234, "900150983cd24fb0d6963f7d28e17f72", L"C:\\work\\00000000000000AA" };
	report::PairSide b{ L"C:\\exes\\new.exe", 5678, "d41d8cd98f00b204e9800998ecf8427e", L"C:\\work\\00000000000000BB" };
	auto p = temp_file("pair.txt");
	std::string err;
	CHECK(report::write_pair_txt(p.c_str(), a, b, err));
	CHECK(slurp(p) ==
		"old_exe=C:\\exes\\old.exe\nold_size=1234\nold_md5=900150983cd24fb0d6963f7d28e17f72\nold_work=C:\\work\\00000000000000AA\n"
		"new_exe=C:\\exes\\new.exe\nnew_size=5678\nnew_md5=d41d8cd98f00b204e9800998ecf8427e\nnew_work=C:\\work\\00000000000000BB\n");
	err.clear();
	CHECK(!report::write_pair_txt(L"Z:\\no\\such\\dir\\pair.txt", a, b, err));
	CHECK(!err.empty());
}
