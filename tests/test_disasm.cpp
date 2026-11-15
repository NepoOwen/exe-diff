#include "tests/test.hpp"
#include "src/disasm/decode.hpp"

using B = std::vector<uint8_t>;

static disasm::Decoded run(const pe::Image& img, uint32_t begin, uint32_t size) {
	disasm::Decoded d;
	disasm::decode(img, { begin, begin + size }, d);
	return d;
}

TEST(mask_call_rel32) {
	B code = { 0xE8, 0x3B, 0x12, 0x00, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 6);
	CHECK(d.masked == B({ 0xE8, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.clean);
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Code);
		CHECK(d.refs[0].is_call);
		CHECK(!d.refs[0].is_branch);
		CHECK(d.refs[0].insn_off == 0);
		CHECK(d.refs[0].target_rva == 0x1000 + 5 + 0x123B);
	}
	CHECK(d.insn_offs == std::vector<uint32_t>({ 0, 5 }));
}

TEST(mask_rip_relative) {
	B code = { 0x48, 0x8D, 0x0D, 0xF9, 0xEF, 0x01, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 8);
	CHECK(d.masked == B({ 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Data);
		CHECK(d.refs[0].target_rva == 0x20000);
	}
}

TEST(keep_local_branch) {
	B code = { 0xEB, 0x02, 0x90, 0x90, 0xC3 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 5);
	CHECK(d.masked == code);
	CHECK(d.refs.empty());
}

TEST(mask_two_identical_functions_at_different_addresses) {
	B a = { 0xE8, 0xFB, 0x6F, 0x00, 0x00, 0xC3 };
	B b = { 0xE8, 0xFB, 0x4F, 0x00, 0x00, 0xC3 };
	auto ia = test::image_from_code(a, 0x1000);
	auto ib = test::image_from_code(b, 0x3000);
	auto da = run(ia, 0x1000, 6);
	auto db = run(ib, 0x3000, 6);
	CHECK(a != b);
	CHECK(da.masked == db.masked);
	CHECK(da.refs.size() == 1 && db.refs.size() == 1);
	if (da.refs.size() == 1 && db.refs.size() == 1) {
		CHECK(da.refs[0].target_rva == 0x8000);
		CHECK(db.refs[0].target_rva == 0x8000);
	}
}

TEST(mask_image_relative_table) {
	B code = { 0x8B, 0x8C, 0x82, 0x00, 0x00, 0x02, 0x00, 0x8B, 0x8C, 0x82, 0x10, 0x00, 0x00, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 15);
	CHECK(d.masked == B({ 0x8B, 0x8C, 0x82, 0, 0, 0, 0, 0x8B, 0x8C, 0x82, 0x10, 0x00, 0x00, 0x00, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::ImageRel);
		CHECK(d.refs[0].target_rva == 0x20000);
	}
}

static const B kBaseInR13 = { 0x4C, 0x8D, 0x2D, 0xF9, 0xEF, 0xFF, 0xFF };	// lea r13, [rip-0x1007] = image base at rva 0x1000
static const B kLeaRdxR13Data = { 0x49, 0x8D, 0x95, 0x10, 0x00, 0x02, 0x00 };	// lea rdx, [r13+0x20010]

TEST(mask_image_base_register) {
	B code = kBaseInR13;
	code.insert(code.end(), kLeaRdxR13Data.begin(), kLeaRdxR13Data.end());
	code.push_back(0xC3);
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 15);
	CHECK(d.masked == B({ 0x4C, 0x8D, 0x2D, 0, 0, 0, 0, 0x49, 0x8D, 0x95, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 2);
	if (d.refs.size() == 2) {
		CHECK(d.refs[1].kind == disasm::RefKind::ImageRel);
		CHECK(d.refs[1].insn_off == 7);
		CHECK(d.refs[1].target_rva == 0x20010);
	}
}

TEST(plain_register_disp_not_masked) {
	B code = kLeaRdxR13Data;
	code.push_back(0xC3);
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 8);
	CHECK(d.masked == code);
	CHECK(d.refs.empty());
	CHECK(d.base_regs == 0);
}

TEST(image_base_register_carried_into_next_range) {
	B code = kBaseInR13;
	code.insert(code.end(), kLeaRdxR13Data.begin(), kLeaRdxR13Data.end());
	auto img = test::image_from_code(code);
	disasm::Decoded a, b;
	disasm::decode(img, { 0x1000, 0x1007 }, a);
	CHECK(a.base_regs == (1u << 13));
	disasm::decode(img, { 0x1007, 0x100E }, b, nullptr, a.base_regs);
	CHECK(b.refs.size() == 1 && b.refs[0].kind == disasm::RefKind::ImageRel);
}

TEST(mask_relocated_imm64) {
	B code = { 0x48, 0xB8, 0x00, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	img.relocs = { 0x1002 };
	auto d = run(img, 0x1000, 11);
	CHECK(d.masked == B({ 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Data);
		CHECK(d.refs[0].target_rva == 0x20000);
	}
}

TEST(undecodable_tail_is_kept) {
	B code = { 0xC3, 0x06, 0x06, 0x06 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 4);
	CHECK(!d.clean);
	CHECK(d.masked == code);
	CHECK(d.insn_offs == std::vector<uint32_t>({ 0 }));
}

TEST(range_past_section_end_is_safe) {
	B code = { 0x90, 0x90 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1ff0, 0x40);
	CHECK(!d.clean);
	CHECK(d.masked.size() == 0x40);
}

TEST(string_and_import_refs) {
	B code = { 0x48, 0x8D, 0x0D, 0xF9, 0xEF, 0x01, 0x00, 0xFF, 0x15, 0xF3, 0xF0, 0x01, 0x00, 0xC3 };
	auto img = test::image_from_code(code);
	const char s[] = "Hello world";
	test::put(img, 0x20000, s, sizeof(s));
	img.imports.push_back({ 0x20100, "KERNEL32.dll!Sleep" });
	auto d = run(img, 0x1000, 14);
	CHECK(d.masked == B({ 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 2);
	if (d.refs.size() == 2) {
		CHECK(d.refs[0].kind == disasm::RefKind::String);
		CHECK(d.refs[0].target_rva == 0x20000);
		CHECK(d.refs[1].kind == disasm::RefKind::Import);
		CHECK(d.refs[1].is_call);
		CHECK(d.refs[1].target_rva == 0x20100);
		CHECK(d.refs[1].insn_off == 7);
	}
}

TEST(jump_table_in_range_is_masked) {
	B code = { 0x8B, 0x8C, 0x82, 0x10, 0x10, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x07, 0x10, 0x00, 0x00, 0x07, 0x10, 0x00, 0x00 };
	auto img = test::image_from_code(code);
	auto d = run(img, 0x1000, 24);
	CHECK(d.clean);
	B want = code;
	for (int i : { 3, 4, 5, 6 }) want[i] = 0;
	for (int i = 16; i < 24; ++i) want[i] = 0;
	CHECK(d.masked == want);
	CHECK(d.insn_offs.size() == 10);
}

TEST(jump_table_in_other_chunk_is_masked) {
	B code = { 0xC3, 0xCC, 0xCC, 0xCC, 0x07, 0x10, 0x00, 0x00 };
	auto img = test::image_from_code(code);
	disasm::Decoded d;
	std::vector<uint32_t> starts = { 0x1004 };
	disasm::decode(img, { 0x1000, 0x1008 }, d, &starts);
	CHECK(d.clean);
	CHECK(d.masked == B({ 0xC3, 0xCC, 0xCC, 0xCC, 0, 0, 0, 0 }));
}

static void put32(B& v, size_t off, uint32_t x) {
	if (v.size() < off + 4) v.resize(off + 4, 0xCC);
	std::memcpy(v.data() + off, &x, 4);
}

TEST(x86_mask_call_rel32) {
	B code = { 0xE8, 0x3B, 0x12, 0x00, 0x00, 0xC3 };
	auto img = test::image_from_code_x86(code);
	auto d = run(img, 0x1000, 6);
	CHECK(d.masked == B({ 0xE8, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.clean);
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Code);
		CHECK(d.refs[0].is_call);
		CHECK(d.refs[0].target_rva == 0x1000 + 5 + 0x123B);
	}
}

TEST(x86_keep_local_branch) {
	B code = { 0xEB, 0x02, 0x90, 0x90, 0xC3 };
	auto img = test::image_from_code_x86(code);
	auto d = run(img, 0x1000, 5);
	CHECK(d.masked == code);
	CHECK(d.refs.empty());
}

TEST(x86_mask_relocated_mov_imm32) {
	B code = { 0xB8, 0x00, 0x20, 0x42, 0x00, 0xC3 };	// mov eax, 0x422000
	auto img = test::image_from_code_x86(code);
	img.relocs = { 0x1001 };
	auto d = run(img, 0x1000, 6);
	CHECK(d.masked == B({ 0xB8, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Data);
		CHECK(d.refs[0].target_rva == 0x22000);
	}
	// the same code linked at another base and address masks to the same bytes
	B other = { 0xB8, 0x00, 0x00, 0x91, 0x00, 0xC3 };
	auto img2 = test::image_from_code_x86(other, 0x3000);
	img2.image_base = 0x800000;
	img2.relocs = { 0x3001 };
	auto d2 = run(img2, 0x3000, 6);
	CHECK(d2.masked == d.masked);
}

TEST(x86_mask_absolute_memory_operand) {
	B a = { 0xA1, 0x00, 0x20, 0x42, 0x00 };	// mov eax, [0x422000]
	auto ia = test::image_from_code_x86(a);
	ia.relocs = { 0x1001 };
	auto da = run(ia, 0x1000, 5);
	CHECK(da.masked == B({ 0xA1, 0, 0, 0, 0 }));
	B b = { 0x8B, 0x0D, 0x00, 0x20, 0x42, 0x00 };	// mov ecx, [0x422000]
	auto ib = test::image_from_code_x86(b);
	ib.relocs = { 0x1002 };
	auto db = run(ib, 0x1000, 6);
	CHECK(db.masked == B({ 0x8B, 0x0D, 0, 0, 0, 0 }));
	CHECK(db.refs.size() == 1);
}

TEST(x86_import_call_through_iat) {
	B code = { 0xFF, 0x15, 0x00, 0x01, 0x42, 0x00, 0xC3 };	// call [0x420100]
	auto img = test::image_from_code_x86(code);
	img.relocs = { 0x1002 };
	img.imports = { { 0x20100, "KERNEL32.dll!Sleep" } };
	auto d = run(img, 0x1000, 7);
	CHECK(d.masked == B({ 0xFF, 0x15, 0, 0, 0, 0, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) {
		CHECK(d.refs[0].kind == disasm::RefKind::Import);
		CHECK(d.refs[0].is_call);
		CHECK(d.refs[0].target_rva == 0x20100);
	}
}

TEST(x86_indexed_jump_table_entry_masked) {
	B code = { 0xFF, 0x24, 0x85 };	// jmp [eax*4 + 0x401010]
	put32(code, 3, 0x401010);
	code.resize(0x10, 0xCC);
	put32(code, 0x10, 0x401000);	// table of absolute addresses of code
	put32(code, 0x14, 0x401004);
	auto img = test::image_from_code_x86(code);
	img.relocs = { 0x1003, 0x1010, 0x1014 };
	auto d = run(img, 0x1000, 0x18);
	CHECK(d.clean);
	CHECK(std::equal(d.masked.begin() + 0x10, d.masked.begin() + 0x18, B(8, 0).begin()));
	CHECK(std::equal(d.masked.begin() + 3, d.masked.begin() + 7, B(4, 0).begin()));
	CHECK(!d.insn_offs.empty() && d.insn_offs.back() < 0x10);
}

TEST(x86_unrelocated_constant_not_masked) {
	B code = { 0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3 };
	auto img = test::image_from_code_x86(code);
	img.relocs = { 0x2000 };
	auto d = run(img, 0x1000, 6);
	CHECK(d.masked == code);
	CHECK(d.refs.empty());
}

TEST(x86_no_relocs_fallback_masks_by_range) {
	B code = { 0x68, 0x00, 0x01, 0x42, 0x00, 0x6A, 0x05, 0xC3 };	// push 0x420100 ; push 5
	auto img = test::image_from_code_x86(code);
	img.relocs_stripped = true;
	auto d = run(img, 0x1000, 8);
	CHECK(d.masked == B({ 0x68, 0, 0, 0, 0, 0x6A, 0x05, 0xC3 }));
	CHECK(d.refs.size() == 1);
	if (d.refs.size() == 1) CHECK(d.refs[0].target_rva == 0x20100);
	B small = { 0x68, 0x05, 0x00, 0x00, 0x00, 0xC3 };	// push 5 as an imm32 is below the image base
	auto img2 = test::image_from_code_x86(small);
	img2.relocs_stripped = true;
	auto d2 = run(img2, 0x1000, 6);
	CHECK(d2.masked == small);
}

TEST(x86_decoder_is_32_bit) {
	B code = { 0x40, 0xC3 };	// inc eax ; ret   (a REX prefix on ret in 64-bit mode)
	auto x86 = test::image_from_code_x86(code);
	auto x64 = test::image_from_code(code);
	CHECK(run(x86, 0x1000, 2).insn_offs == std::vector<uint32_t>({ 0, 1 }));
	CHECK(run(x64, 0x1000, 2).insn_offs == std::vector<uint32_t>({ 0 }));
	CHECK(disasm::machine_mode(pe::Arch::X86) == ZYDIS_MACHINE_MODE_LEGACY_32);
	CHECK(disasm::stack_width(pe::Arch::X86) == ZYDIS_STACK_WIDTH_32);
	CHECK(disasm::machine_mode(pe::Arch::X64) == ZYDIS_MACHINE_MODE_LONG_64);
	CHECK(disasm::stack_width(pe::Arch::X64) == ZYDIS_STACK_WIDTH_64);
}
