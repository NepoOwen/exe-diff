#include "tests/test.hpp"
#include "src/func/discover.hpp"

using B = std::vector<uint8_t>;

static void emit_rel32(B& code, uint32_t base, std::initializer_list<uint8_t> opcode, uint32_t target) {
	code.insert(code.end(), opcode);
	uint32_t next = base + static_cast<uint32_t>(code.size()) + 4;
	uint32_t rel = target - next;
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

static void at_offset(B& code, size_t off) {
	if (code.size() < off) code.resize(off, 0xCC);
}

TEST(discover_pdata_and_leaf) {
	B code;
	emit_rel32(code, 0x1000, { 0xE8 }, 0x1020);
	code.push_back(0xC3);
	at_offset(code, 0x10);
	code.push_back(0xC3);
	at_offset(code, 0x20);
	code.insert(code.end(), { 0x31, 0xC0, 0xC3 });
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x1006, 0x20000 }, { 0x1010, 0x1011, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 3);
	if (set.funcs.size() == 3) {
		CHECK(set.funcs[0].rva == 0x1000 && set.funcs[0].end == 0x1006 && set.funcs[0].from_pdata);
		CHECK(set.funcs[2].rva == 0x1020);
		CHECK(!set.funcs[2].from_pdata);
		CHECK(set.funcs[2].end == 0x1023);
		CHECK(set.funcs[2].size == 3);
	}
	CHECK(set.find(0x1021) == 2);
	CHECK(set.at(0x1021) == -1);
	CHECK(set.at(0x1010) == 1);
	CHECK(set.find(0x1008) == -1);
}

TEST(discover_chained_chunk) {
	B code(0x40, 0xCC);
	code[0x00] = 0x90; code[0x01] = 0xC3;
	code[0x30] = 0x90; code[0x31] = 0xC3;
	auto img = test::image_from_code(code);
	uint8_t chained_unwind[16] = { 0x21, 0, 0, 0, 0x00, 0x10, 0, 0, 0x02, 0x10, 0, 0, 0x00, 0x00, 0x02, 0x00 };
	test::put(img, 0x20100, chained_unwind, sizeof(chained_unwind));
	img.pdata = { { 0x1000, 0x1002, 0x20000 }, { 0x1030, 0x1032, 0x20100 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1);
	if (set.funcs.size() == 1) {
		CHECK(set.funcs[0].chunk_count == 1);
		CHECK(set.funcs[0].size == 4);
	}
	CHECK(set.find(0x1031) == 0);
}

static uint64_t base_in_chunk_hash(uint32_t data_rva) {
	B code = { 0x4C, 0x8D, 0x2D, 0xF9, 0xEF, 0xFF, 0xFF, 0x49, 0x8D, 0x95 };	// lea r13, image base | lea rdx, [r13+data_rva]
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(data_rva >> (8 * i)));
	code.push_back(0xC3);
	auto img = test::image_from_code(code);
	uint8_t chained_unwind[16] = { 0x21, 0, 0, 0, 0x00, 0x10, 0, 0, 0x07, 0x10, 0, 0, 0x00, 0x00, 0x02, 0x00 };
	test::put(img, 0x20100, chained_unwind, sizeof(chained_unwind));
	img.pdata = { { 0x1000, 0x1007, 0x20000 }, { 0x1007, 0x100F, 0x20100 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1 && set.funcs[0].chunk_count == 1);
	return set.funcs.empty() ? 0 : set.funcs[0].hash;
}

TEST(hash_masks_image_base_register_across_chunks) {
	CHECK(base_in_chunk_hash(0x20010) == base_in_chunk_hash(0x20020));
}

static uint64_t use_before_base_load_hash(uint32_t data_rva) {
	B code = { 0x49, 0x8D, 0x95 };	// lea rdx, [r13+data_rva] | lea r13, image base | ret
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(data_rva >> (8 * i)));
	code.insert(code.end(), { 0x4C, 0x8D, 0x2D, 0xF2, 0xEF, 0xFF, 0xFF, 0xC3 });
	auto img = test::image_from_code(code);
	img.pdata = { { 0x1000, 0x100F, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 1);
	return set.funcs.empty() ? 0 : set.funcs[0].hash;
}

TEST(hash_masks_use_before_image_base_load) {
	CHECK(use_before_base_load_hash(0x20010) == use_before_base_load_hash(0x20020));
}

static void indexed_load(B& code, size_t off, uint32_t disp) {
	at_offset(code, off);
	code.insert(code.end(), { 0x8B, 0x84, 0x81 });	// mov eax, [rcx+rax*4+disp32]
	for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(disp >> (8 * i)));
}

TEST(table_starts_ignores_table_bytes) {
	B code;
	indexed_load(code, 0x00, 0x1020);
	code.push_back(0xC3);
	at_offset(code, 0x10);
	code.push_back(0xC3);
	indexed_load(code, 0x20, 0x1010);
	at_offset(code, 0x30);
	auto img = test::image_from_code(code);
	auto t = func::table_starts(img, { { 0x1000, 0x1010 }, { 0x1010, 0x1018 }, { 0x1020, 0x1028 } });
	CHECK(t == std::vector<uint32_t>({ 0x1020 }));
}

TEST(table_starts_table_before_code) {
	B code;
	indexed_load(code, 0x00, 0x1010);
	at_offset(code, 0x10);
	code.push_back(0xC3);
	indexed_load(code, 0x20, 0x1000);
	code.push_back(0xC3);
	at_offset(code, 0x30);
	auto img = test::image_from_code(code);
	auto t = func::table_starts(img, { { 0x1020, 0x1030 }, { 0x1000, 0x1008 }, { 0x1010, 0x1018 } });
	CHECK(t == std::vector<uint32_t>({ 0x1000 }));
}

struct Layout { uint32_t code_rva, f_off, x_off, str_rva; const char* text; const char* import; };

static uint64_t hash_of(const Layout& l) {
	B code;
	emit_rel32(code, l.code_rva, { 0xE8 }, l.code_rva + l.x_off);
	emit_rel32(code, l.code_rva, { 0x48, 0x8D, 0x0D }, l.str_rva);
	emit_rel32(code, l.code_rva, { 0xFF, 0x15 }, 0x20800);
	code.push_back(0xC3);
	uint32_t f_end = l.code_rva + static_cast<uint32_t>(code.size());
	at_offset(code, l.x_off);
	code.push_back(0xC3);
	auto img = test::image_from_code(code, l.code_rva);
	test::put(img, l.str_rva, l.text, std::strlen(l.text) + 1);
	img.imports.push_back({ 0x20800, l.import });
	img.pdata = { { l.code_rva, f_end, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	int i = set.at(l.code_rva);
	CHECK(i >= 0);
	return i >= 0 ? set.funcs[i].hash : 0;
}

TEST(hash_ignores_position) {
	auto a = hash_of({ 0x1000, 0, 0x100, 0x20040, "Hello world", "KERNEL32.dll!Sleep" });
	auto b = hash_of({ 0x3000, 0, 0x200, 0x20400, "Hello world", "KERNEL32.dll!Sleep" });
	CHECK(a == b);
}

TEST(hash_sees_string_change) {
	auto a = hash_of({ 0x1000, 0, 0x100, 0x20040, "Hello world", "KERNEL32.dll!Sleep" });
	auto b = hash_of({ 0x1000, 0, 0x100, 0x20040, "Hello there", "KERNEL32.dll!Sleep" });
	CHECK(a != b);
}

TEST(hash_sees_import_change) {
	auto a = hash_of({ 0x1000, 0, 0x100, 0x20040, "Hello world", "KERNEL32.dll!CreateFileW" });
	auto b = hash_of({ 0x1000, 0, 0x100, 0x20040, "Hello world", "KERNEL32.dll!CreateFileA" });
	CHECK(a != b);
}

TEST(discover_sample) {
	auto p = test::sample_old(); if (!p) { SKIP(); return; }
	pe::Image img; std::string err;
	CHECK(pe::load(p, img, err));
	double t0 = test::now_seconds();
	func::Set set;
	func::discover(img, set);
	double dt = test::now_seconds() - t0;
	size_t clean = 0, leaves = 0;
	bool sorted = true, overlap = false;
	for (size_t i = 0; i < set.funcs.size(); ++i) {
		clean += set.funcs[i].clean;
		leaves += !set.funcs[i].from_pdata;
		if (i) {
			sorted &= set.funcs[i - 1].rva < set.funcs[i].rva;
			overlap |= set.funcs[i - 1].end > set.funcs[i].rva;
		}
	}
	std::printf("  discover_sample: %zu funcs (%zu leaf), %zu clean, %.2fs\n", set.funcs.size(), leaves, clean, dt);
	CHECK(set.funcs.size() >= 50000);
	CHECK(sorted);
	CHECK(!overlap);
	CHECK(clean * 100 >= set.funcs.size() * 99);
	CHECK(dt < 10.0);
}

TEST(discover_is_deterministic) {
	auto p = test::sample_old(); if (!p) { SKIP(); return; }
	pe::Image img; std::string err;
	CHECK(pe::load(p, img, err));
	func::Set a, b;
	func::discover(img, a);
	func::discover(img, b);
	CHECK(a.funcs.size() == b.funcs.size());
	bool same = a.funcs.size() == b.funcs.size();
	for (size_t i = 0; same && i < a.funcs.size(); ++i)
		same = a.funcs[i].hash == b.funcs[i].hash && a.funcs[i].rva == b.funcs[i].rva;
	CHECK(same);
}
