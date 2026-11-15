#include "tests/test.hpp"
#include "src/func/discover.hpp"
#include <algorithm>

// x86 discovery: no .pdata, so functions come from seeds, call targets and padding

using B = std::vector<uint8_t>;

static void emit_rel32(B& code, uint32_t base, std::initializer_list<uint8_t> opcode, uint32_t target) {
	code.insert(code.end(), opcode);
	uint32_t next = base + static_cast<uint32_t>(code.size()) + 4;
	uint32_t rel = target - next;
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

static void fill_to(B& code, size_t off, uint8_t byte) {
	if (code.size() < off) code.resize(off, byte);
}

static bool sorted_and_disjoint(const func::Set& set) {
	for (size_t i = 1; i < set.funcs.size(); ++i)
		if (set.funcs[i - 1].rva >= set.funcs[i].rva || set.funcs[i - 1].end > set.funcs[i].rva) return false;
	return true;
}

TEST(discover_x86_entry_and_call_target) {
	B code = { 0x55, 0x8B, 0xEC };
	emit_rel32(code, 0x1000, { 0xE8 }, 0x1020);
	code.insert(code.end(), { 0x5D, 0xC3 });
	fill_to(code, 0x20, 0xCC);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	if (set.funcs.size() == 2) {
		CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x100A);
		CHECK(set.funcs[1].rva == 0x1020 && set.funcs[1].end == 0x1023);
		CHECK(!set.funcs[0].from_pdata && !set.funcs[1].from_pdata);
		CHECK(set.funcs[0].chunk_count == 0 && set.funcs[1].chunk_count == 0);
	}
	CHECK(set.skipped.empty());
}

TEST(discover_x86_export_seed) {
	B code = { 0xC3 };
	fill_to(code, 0x40, 0xF4);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.exports = { { 0x1040, "Foo" } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	CHECK(set.at(0x1040) >= 0);
}

TEST(discover_x86_reloc_pointer_seed) {
	B code = { 0xC3 };
	fill_to(code, 0x60, 0xF4);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { test::kDataRva };
	uint32_t ptr = 0x401060;
	test::put(img, test::kDataRva, &ptr, 4);
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	CHECK(set.at(0x1060) >= 0);
}

TEST(discover_x86_padding_ends_function) {
	B code = { 0x31, 0xC0, 0xC3, 0xCC, 0xCC, 0xCC, 0x33, 0xC0, 0xC3 };
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	if (set.funcs.size() == 2) {
		CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x1003);
		CHECK(set.funcs[1].rva == 0x1006 && set.funcs[1].end == 0x1009);
	}
}

TEST(discover_x86_int3_after_noreturn_call_ends_function) {
	B code = { 0x90 };
	emit_rel32(code, 0x1000, { 0xE8 }, 0x1040);	// call that never returns, no ret after it
	code.insert(code.end(), { 0xCC, 0xCC, 0x31, 0xC0, 0xC3 });
	fill_to(code, 0x40, 0xCC);
	code.insert(code.end(), { 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 3);
	if (set.funcs.size() == 3) {
		CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x1006);
		CHECK(set.funcs[1].rva == 0x1008 && set.funcs[1].end == 0x100B);
	}
}

TEST(discover_x86_jump_table_not_a_function) {
	B code = { 0xFF, 0x24, 0x85, 0x10, 0x10, 0x40, 0x00 };	// jmp dword ptr [eax*4 + 0x401010]
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });	// case 0 at 0x1007
	code.insert(code.end(), { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 });	// case 1 at 0x100A
	code.insert(code.end(), { 0x07, 0x10, 0x40, 0x00, 0x0A, 0x10, 0x40, 0x00 });	// table at 0x1010
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.relocs = { 0x1003, 0x1010, 0x1014 };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1);
	if (!set.funcs.empty()) CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x1010);
	CHECK(set.find(0x1010) < 0);
	CHECK(set.find(0x1014) < 0);
	CHECK(set.skipped.empty());
}

TEST(discover_x86_seed_that_does_not_decode_is_skipped) {
	B code = { 0xC3 };
	fill_to(code, 0x40, 0xF4);
	code.insert(code.end(), { 0xFF, 0xFF });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.exports = { { 0x1040, "Bad" } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1);
	CHECK(set.find(0x1040) < 0);
	CHECK(set.skipped.size() == 1);
	if (set.skipped.size() == 1) {
		CHECK(set.skipped[0].rva == 0x1040);
		CHECK(!set.skipped[0].reason.empty());
	}
}

TEST(discover_x86_seed_with_no_end_is_skipped) {
	B code = { 0xC3 };
	fill_to(code, 0xFFC, 0xF4);
	code.insert(code.end(), { 0x90, 0x90, 0x90, 0x90 });	// runs into the end of .text without ret or jmp
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.exports = { { 0x1FFC, "Runaway" } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1);
	CHECK(set.skipped.size() == 1);
	if (set.skipped.size() == 1) CHECK(set.skipped[0].reason.find("end") != std::string::npos);
}

TEST(discover_x86_no_seeds) {
	B code = { 0x55, 0x8B, 0xEC, 0xC3 };
	auto img = test::image_from_code_x86(code);
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.empty());
	CHECK(set.skipped.empty());
	CHECK(set.covered_bytes == 0);
	CHECK(set.exec_bytes > 0);
}

TEST(discover_x86_sorted_and_disjoint) {
	B code;
	emit_rel32(code, 0x1000, { 0xE8 }, 0x1030);
	emit_rel32(code, 0x1000, { 0xE8 }, 0x1020);
	code.push_back(0xC3);
	fill_to(code, 0x20, 0xCC);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	fill_to(code, 0x30, 0xCC);
	code.insert(code.end(), { 0x33, 0xC0, 0xC3 });
	fill_to(code, 0x40, 0xCC);
	code.push_back(0xC3);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.exports = { { 0x1040, "Last" } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 4);
	CHECK(sorted_and_disjoint(set));
}

TEST(discover_x86_coverage_counts) {
	B code = { 0x31, 0xC0, 0xC3 };
	fill_to(code, 0x10, 0xCC);
	code.push_back(0xC3);
	fill_to(code, 0x1000, 0xCC);
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	img.exports = { { 0x1010, "Second" } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	uint64_t sum = 0;
	for (auto& f : set.funcs) sum += f.size;
	CHECK(sum == 4);
	CHECK(set.covered_bytes == sum);
	CHECK(set.exec_bytes == 4);
}

TEST(discover_x64_coverage_counts) {
	B code = { 0x31, 0xC0, 0xC3 };
	fill_to(code, 0x10, 0xCC);
	code.push_back(0xC3);
	fill_to(code, 0x1000, 0xCC);
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x1003, 0x20000 }, { 0x1010, 0x1011, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 2);
	CHECK(set.covered_bytes == 4);
	CHECK(set.exec_bytes == 4);
	CHECK(set.skipped.empty());
}

static void x86_sample_stats(const wchar_t* path, const char* label, func::Set& set) {
	pe::Image img; std::string err;
	CHECK(pe::load(path, img, err));
	double t0 = test::now_seconds();
	func::discover(img, set);
	double dt = test::now_seconds() - t0;
	unsigned long long covered = set.covered_bytes, total = set.exec_bytes;
	std::printf("  %s: %zu funcs, %zu skipped seeds, %llu of %llu code bytes covered (%llu outside), %.2fs\n",
		label, set.funcs.size(), set.skipped.size(), covered, total, total - std::min(total, covered), dt);
	CHECK(sorted_and_disjoint(set));
	CHECK(dt < 10.0);
}

TEST(discover_x86_sample) {
	auto a = test::sample_x86_old(), b = test::sample_x86_new();
	if (!a || !b) { SKIP(); return; }
	func::Set sa, sb;
	x86_sample_stats(a, "x86 old", sa);
	x86_sample_stats(b, "x86 new", sb);
	CHECK(sa.funcs.size() >= 10000);
	CHECK(sb.funcs.size() >= 10000);
}

TEST(discover_x86_is_deterministic) {
	auto p = test::sample_x86_old(); if (!p) { SKIP(); return; }
	pe::Image img; std::string err;
	CHECK(pe::load(p, img, err));
	func::Set a, b;
	func::discover(img, a);
	func::discover(img, b);
	CHECK(a.funcs.size() == b.funcs.size());
	bool same = a.funcs.size() == b.funcs.size() && a.skipped.size() == b.skipped.size();
	for (size_t i = 0; same && i < a.funcs.size(); ++i)
		same = a.funcs[i].hash == b.funcs[i].hash && a.funcs[i].rva == b.funcs[i].rva && a.funcs[i].end == b.funcs[i].end;
	CHECK(same);
}

TEST(discover_x86_tail_jump_over_padding_ends_function) {
	// `jmp` to a later function must not stretch the function over the padding and the functions in between
	B code;
	emit_rel32(code, 0x1000, { 0xE9 }, 0x1030);
	fill_to(code, 0x10, 0xCC);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	fill_to(code, 0x30, 0xCC);
	code.insert(code.end(), { 0x31, 0xC9, 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 3);
	if (set.funcs.size() == 3) {
		CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x1005);
		CHECK(set.funcs[1].rva == 0x1010 && set.funcs[1].end == 0x1013);
		CHECK(set.funcs[2].rva == 0x1030 && set.funcs[2].end == 0x1033);
	}
}

TEST(discover_x86_conditional_branch_over_int3_keeps_function) {
	// an int3 after noreturn code inside a function is not its end while a branch still reaches beyond it
	B code = { 0x85, 0xC0, 0x74 };	// test eax,eax / jz +N
	code.push_back(0x06);
	code.insert(code.end(), { 0xE8 });
	emit_rel32(code, 0x1000, { }, 0x1100);	// call noreturn
	code.push_back(0xCC);	// int3 after the noreturn call
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });	// jz target: xor eax,eax / ret
	fill_to(code, 0x100, 0xCC);
	code.insert(code.end(), { 0xC3 });
	auto img = test::image_from_code_x86(code);
	img.entry_rva = 0x1000;
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() >= 1);
	if (!set.funcs.empty()) CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x100D);
}
