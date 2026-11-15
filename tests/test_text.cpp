#include "tests/test.hpp"
#include "src/text/render.hpp"
#include "src/func/discover.hpp"
#include "src/match/match.hpp"

using B = std::vector<uint8_t>;

static void emit_rel32(B& code, uint32_t base, std::initializer_list<uint8_t> opcode, uint32_t target) {
	code.insert(code.end(), opcode);
	uint32_t next = base + static_cast<uint32_t>(code.size()) + 4;
	uint32_t rel = target - next;
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

static std::vector<std::string> render_sample(uint32_t code_rva, uint32_t callee_off, uint32_t str_rva) {
	B code;
	emit_rel32(code, code_rva, { 0xE8 }, code_rva + callee_off);
	emit_rel32(code, code_rva, { 0x48, 0x8D, 0x0D }, str_rva);
	emit_rel32(code, code_rva, { 0xFF, 0x15 }, 0x20800);
	code.insert(code.end(), { 0xEB, 0x00, 0xC3 });
	uint32_t f_end = code_rva + static_cast<uint32_t>(code.size());
	code.resize(callee_off, 0xCC);
	code.push_back(0xC3);
	auto img = test::image_from_code(code, code_rva);
	const char* text = "Invalid session";
	test::put(img, str_rva, text, std::strlen(text) + 1);
	img.imports.push_back({ 0x20800, "KERNEL32.dll!Sleep" });
	img.pdata = { { code_rva, f_end, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	if (set.funcs.size() != 2) return {};
	return text::render(img, set, 0, { "sub_140001000", "sub_140001020" });
}

TEST(render_names_and_strings) {
	auto lines = render_sample(0x1000, 0x20, 0x20040);
	std::vector<std::string> want = { "call sub_140001020", "lea rcx, \"Invalid session\"", "call KERNEL32.dll!Sleep", "jmp loc_14", "ret" };
	CHECK(lines == want);
}

TEST(render_same_text_after_move) {
	auto a = render_sample(0x1000, 0x20, 0x20040);
	auto b = render_sample(0x3000, 0x200, 0x20400);
	CHECK(!a.empty() && a == b);
}

TEST(render_data_has_no_address) {
	B code;
	emit_rel32(code, 0x1000, { 0x8B, 0x05 }, 0x20100);
	code.push_back(0xC3);
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x1007, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines.size() == 2 && lines[0] == "mov eax, [<.data>]");
}

TEST(render_image_base_register) {
	B code = { 0x4C, 0x8D, 0x2D, 0xF9, 0xEF, 0xFF, 0xFF, 0x49, 0x8D, 0x95, 0x10, 0x00, 0x02, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x100F, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines.size() == 3 && lines[1] == "lea rdx, [r13+<.data>]");
}

TEST(render_use_before_image_base_load) {
	B code = { 0x49, 0x8D, 0x95, 0x10, 0x00, 0x02, 0x00, 0x4C, 0x8D, 0x2D, 0xF2, 0xEF, 0xFF, 0xFF, 0xC3 };
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x100F, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines.size() == 3 && lines[0] == "lea rdx, [r13+<.data>]");
}

TEST(render_image_base_register_in_chunk) {
	B code = { 0x4C, 0x8D, 0x2D, 0xF9, 0xEF, 0xFF, 0xFF, 0x49, 0x8D, 0x95, 0x10, 0x00, 0x02, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	uint8_t chained_unwind[16] = { 0x21, 0, 0, 0, 0x00, 0x10, 0, 0, 0x07, 0x10, 0, 0, 0x00, 0x00, 0x02, 0x00 };
	test::put(img, 0x20100, chained_unwind, sizeof(chained_unwind));
	img.pdata = { { 0x1000, 0x1007, 0x20000 }, { 0x1007, 0x100F, 0x20100 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines.size() == 4 && lines[2] == "lea rdx, [r13+<.data>]");
}

TEST(render_chunk_marker) {
	B code(0x40, 0xCC);
	code[0x00] = 0x90; code[0x01] = 0xC3;
	code[0x30] = 0x90; code[0x31] = 0xC3;
	auto img = test::image_from_code(code);
	uint8_t chained_unwind[16] = { 0x21, 0, 0, 0, 0x00, 0x10, 0, 0, 0x02, 0x10, 0, 0, 0x00, 0x00, 0x02, 0x00 };
	test::put(img, 0x20100, chained_unwind, sizeof(chained_unwind));
	img.pdata = { { 0x1000, 0x1002, 0x20000 }, { 0x1030, 0x1032, 0x20100 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines == std::vector<std::string>({ "nop", "ret", "; chunk", "nop", "ret" }));
}

TEST(render_trailing_data) {
	auto img = test::image_from_code({ 0xC3, 0xC4 });
	img.pdata = { { 0x1000, 0x1002, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	auto lines = text::render(img, set, 0, { "sub_140001000" });
	CHECK(lines == std::vector<std::string>({ "ret", "; data, 1 bytes" }));
}

TEST(render_sample_same_pairs_identical) {
	auto po = test::sample_old(), pn = test::sample_new(); if (!po || !pn) { SKIP(); return; }
	pe::Image ia, ib; func::Set a, b; std::string err;
	CHECK(pe::load(po, ia, err) && pe::load(pn, ib, err));
	func::discover(ia, a); func::discover(ib, b);
	match::Result r; match::run(a, b, r);
	match::Names n; match::name(ia, a, ib, b, r, n);
	double t0 = test::now_seconds();
	size_t same = 0, differ = 0, shown = 0;
	for (auto& p : r.pairs) {
		if (p.status != match::Status::Same) continue;
		++same;
		auto la = text::render(ia, a, p.old_idx, n.old_names), lb = text::render(ib, b, p.new_idx, n.new_names);
		if (la == lb) continue;
		++differ;
		for (size_t i = 0; shown < 5 && i < std::min(la.size(), lb.size()); ++i)
			if (la[i] != lb[i]) { ++shown; std::printf("    %s: '%s' vs '%s'\n", n.old_names[p.old_idx].c_str(), la[i].c_str(), lb[i].c_str()); break; }
	}
	std::printf("  render_sample: %zu same pairs, %zu render differently (%.2fs)\n", same, differ, test::now_seconds() - t0);
	CHECK(differ * 2000 <= same);
}
