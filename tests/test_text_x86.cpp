#include "tests/test.hpp"
#include "src/text/render.hpp"
#include "src/func/discover.hpp"
#include "src/match/match.hpp"
#include <cctype>

// x86 rendering: absolute operands and relocated immediates print as names, not addresses

using B = std::vector<uint8_t>;

static void emit_rel32(B& code, uint32_t base, std::initializer_list<uint8_t> opcode, uint32_t target) {
	code.insert(code.end(), opcode);
	uint32_t next = base + static_cast<uint32_t>(code.size()) + 4;
	uint32_t rel = target - next;
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

static void abs32(B& code, uint32_t rva) {
	uint32_t va = rva + 0x400000;
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(va >> (8 * i)));
}

static std::vector<std::string> render_first(pe::Image& img) {
	func::Set set;
	func::discover(img, set);
	CHECK(!set.funcs.empty());
	if (set.funcs.empty()) return {};
	return text::render(img, set, 0, { "sub_401000", "sub_401020" });
}

TEST(render_x86_import_call) {
	B code = { 0xFF, 0x15 };
	abs32(code, 0x20800);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { 0x1002 };
	img.imports.push_back({ 0x20800, "KERNEL32.dll!Sleep" });
	auto lines = render_first(img);
	CHECK(lines == std::vector<std::string>({ "call [KERNEL32.dll!Sleep]", "ret" }));
}

TEST(render_x86_string_push) {
	B code = { 0x68 };
	abs32(code, 0x20040);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { 0x1001 };
	const char* text = "Invalid session";
	test::put(img, 0x20040, text, std::strlen(text) + 1);
	auto lines = render_first(img);
	CHECK(lines == std::vector<std::string>({ "push \"Invalid session\"", "ret" }));
}

TEST(render_x86_data_variable_has_no_address) {
	B code = { 0xA1 };	// mov eax, [moffs32]
	abs32(code, 0x20100);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { 0x1001 };
	auto lines = render_first(img);
	CHECK(lines.size() == 2 && lines[0].find("<.data>") != std::string::npos && lines[0].find("0x4") == std::string::npos);
}

TEST(render_x86_indexed_table_has_no_address) {
	B code = { 0x8B, 0x04, 0x85 };	// mov eax, [eax*4 + table]
	abs32(code, 0x20100);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { 0x1003 };
	auto lines = render_first(img);
	CHECK(lines.size() == 2 && lines[0] == "mov eax, [eax*4+<.data>]");
}

TEST(render_x86_call_uses_matched_name) {
	// the callee's rva is above the image base value: a relative target must not be taken for an absolute address
	B code;
	emit_rel32(code, 0x410000, { 0xE8 }, 0x410020);
	code.push_back(0xC3);
	code.resize(0x20, 0xCC);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	auto img = test::image_from_code_x86(code, 0x410000);
	img.entry_rva = 0x410000;
	auto lines = render_first(img);
	CHECK(lines == std::vector<std::string>({ "call sub_401020", "ret" }));
}

TEST(render_x86_unrelocated_imm_stays_numeric) {
	B code = { 0x68 };
	abs32(code, 0x20040);	// same bytes as a string push, but nothing marks them as an address
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	const char* text = "Invalid session";
	test::put(img, 0x20040, text, std::strlen(text) + 1);
	auto lines = render_first(img);
	CHECK(lines.size() == 2 && lines[0].find("420040") != std::string::npos && lines[0].find('"') == std::string::npos);
}

TEST(render_x86_without_relocations_names_addresses_in_the_image) {
	B code = { 0x68 };
	abs32(code, 0x20040);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs_stripped = true;
	const char* text = "Invalid session";
	test::put(img, 0x20040, text, std::strlen(text) + 1);
	auto lines = render_first(img);
	CHECK(lines == std::vector<std::string>({ "push \"Invalid session\"", "ret" }));
}

// equal-hash functions are interchangeable to the matcher, so a pair may call differently named twins
static std::string without_names(std::string s) {
	for (const char* prefix : { "sub_", "new_" })
		for (size_t at = s.find(prefix); at != std::string::npos; at = s.find(prefix, at + 4)) {
			size_t end = at + 4;
			while (end < s.size() && std::isxdigit(static_cast<unsigned char>(s[end]))) ++end;
			s.replace(at, end - at, "fn");
		}
	return s;
}

TEST(render_x86_sample_same_pairs_identical) {
	auto po = test::sample_x86_old(), pn = test::sample_x86_new(); if (!po || !pn) { SKIP(); return; }
	pe::Image ia, ib; func::Set a, b; std::string err;
	CHECK(pe::load(po, ia, err) && pe::load(pn, ib, err));
	func::discover(ia, a); func::discover(ib, b);
	match::Result r; match::run(a, b, r);
	match::Names n; match::name(ia, a, ib, b, r, n);
	double t0 = test::now_seconds();
	// tiny getters pair by order and may reference another global: only longer functions count
	size_t same = 0, differ = 0, tiny = 0, renamed = 0, shown = 0;
	for (auto& p : r.pairs) {
		if (p.status != match::Status::Same) continue;
		++same;
		auto la = text::render(ia, a, p.old_idx, n.old_names), lb = text::render(ib, b, p.new_idx, n.new_names);
		if (la == lb) continue;
		bool equal = la.size() == lb.size();
		for (size_t i = 0; equal && i < la.size(); ++i) equal = without_names(la[i]) == without_names(lb[i]);
		if (equal) { ++renamed; continue; }
		if (la.size() <= 4) { ++tiny; continue; }
		++differ;
		for (size_t i = 0; shown < 8 && i < std::min(la.size(), lb.size()); ++i)
			if (without_names(la[i]) != without_names(lb[i])) { ++shown; std::printf("    %s: '%s' vs '%s'\n", n.old_names[p.old_idx].c_str(), la[i].c_str(), lb[i].c_str()); break; }
	}
	std::printf("  render_x86_sample: %zu funcs old, %zu new, %zu same pairs: %zu differ only in a callee's name, %zu tiny functions reference another global, %zu longer ones render differently (%.2fs)\n",
		a.funcs.size(), b.funcs.size(), same, renamed, tiny, differ, test::now_seconds() - t0);
	CHECK(same > 10000);
	CHECK(differ * 2000 <= same);
}
