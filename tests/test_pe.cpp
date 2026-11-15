#include "tests/test.hpp"
#include "tests/pe_builder.hpp"
#include "src/pe/image.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

static std::wstring temp_file(const wchar_t* name, const std::vector<uint8_t>& bytes) {
	auto path = std::filesystem::temp_directory_path() / L"exediff_tests";
	std::filesystem::create_directories(path);
	path /= name;
	std::ofstream f(path, std::ios::binary);
	f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
	return path.wstring();
}

static std::vector<uint8_t> read_prefix(const wchar_t* path, size_t n) {
	std::ifstream f(path, std::ios::binary);
	std::vector<uint8_t> v(n);
	f.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(n));
	v.resize(static_cast<size_t>(f.gcount()));
	return v;
}

static void check_sample(const wchar_t* p, size_t pdata_count, uint32_t text_vsize) {
	pe::Image img; std::string err;
	CHECK(pe::load(p, img, err));
	CHECK(img.sections.size() == 9);
	CHECK(img.text() && std::string(img.text()->name) == ".text");
	CHECK(img.text() && img.text()->vsize == text_vsize);
	CHECK(img.pdata.size() == pdata_count);
	CHECK(std::is_sorted(img.pdata.begin(), img.pdata.end(), [](auto& a, auto& b) { return a.begin < b.begin; }));
	CHECK(!img.relocs.empty() && std::is_sorted(img.relocs.begin(), img.relocs.end()));
	CHECK(!img.imports.empty());
	CHECK(!img.imports.empty() && img.imports[0].name.find('!') != std::string::npos);
	CHECK(img.text() && img.at(img.text()->rva, 16) != nullptr);
	CHECK(img.at(img.size_of_image, 1) == nullptr);
	CHECK(img.image_base == 0x140000000ull);
	CHECK(img.content_hash != 0);
}

TEST(pe_loads_sample_old) {
	auto p = test::sample_old(); if (!p) { SKIP(); return; }
	check_sample(p, 88699, 0xfd8f7f);
}

TEST(pe_loads_sample_new) {
	auto p = test::sample_new(); if (!p) { SKIP(); return; }
	check_sample(p, 88700, 0xfd885f);
}

static void expect_reject(const wchar_t* name, const std::vector<uint8_t>& bytes) {
	pe::Image img; std::string err;
	CHECK(!pe::load(temp_file(name, bytes).c_str(), img, err));
	CHECK(!err.empty());
}

TEST(pe_rejects_bad_input) {
	expect_reject(L"empty.exe", {});
	expect_reject(L"zeros.exe", std::vector<uint8_t>(64, 0));
	std::vector<uint8_t> mz(64, 0);
	mz[0] = 'M'; mz[1] = 'Z';
	mz[0x3c] = 0x00; mz[0x3d] = 0x10;
	expect_reject(L"mz_far.exe", mz);
	pe::Image img; std::string err;
	CHECK(!pe::load(L"does_not_exist.exe", img, err));
	CHECK(!err.empty());
	auto p = test::sample_old(); if (!p) return;
	expect_reject(L"truncated.exe", read_prefix(p, 0x300));
	auto head = read_prefix(p, 0x400);
	uint32_t lfanew = head[0x3c] | (head[0x3d] << 8) | (head[0x3e] << 16) | (head[0x3f] << 24);
	head[lfanew + 4] = 0x4C; head[lfanew + 5] = 0x01;
	expect_reject(L"i386.exe", head);
}

TEST(pe_string_at) {
	pe::Image img;
	const char data[] = "Hello world\0ab\0";
	img.file.assign(data, data + sizeof(data));
	img.image_base = 0x140000000ull;
	img.size_of_image = 0x2000;
	pe::Section s{};
	std::memcpy(s.name, ".rdata", 7);
	s.rva = 0x1000; s.vsize = 0x1000; s.raw_off = 0; s.raw_size = static_cast<uint32_t>(img.file.size());
	s.flags = 0x40000040;
	img.sections.push_back(s);
	std::string out;
	CHECK(img.string_at(0x1000, out));
	CHECK(out == "Hello world");
	CHECK(!img.string_at(0x100c, out));
	CHECK(!img.string_at(0x3000, out));
}

TEST(x86_samples_present) {
	const wchar_t* names[] = { L"old.exe", L"new.exe", L"old_fixed.exe", L"new_fixed.exe", L"old.dll", L"new.dll" };
	for (auto n : names) {
		if (!test::x86_file(n)) { SKIP(); return; }
	}
	CHECK(true);
}

static bool load_spec(const test::PeSpec& spec, pe::Image& img, std::string& err, const wchar_t* name = L"spec.exe") {
	return pe::load(temp_file(name, test::make_pe(spec)).c_str(), img, err);
}

TEST(pe_loads_x86_basic) {
	test::PeSpec spec;
	spec.entry_rva = 0x1004;
	spec.text = { 0x90, 0x90, 0x90, 0x90, 0xC3 };
	pe::Image img; std::string err;
	CHECK(load_spec(spec, img, err));
	CHECK(img.arch == pe::Arch::X86);
	CHECK(img.image_base == 0x400000);
	CHECK(img.entry_rva == 0x1004);
	CHECK(img.pdata.empty());
	CHECK(img.ptr_size() == 4);
	CHECK(img.text() && img.at(0x1000, 5) != nullptr);
}

TEST(pe_x86_relocs_highlow_only) {
	test::PeSpec spec;
	spec.text.assign(0x20, 0x90);
	spec.relocs = { 0x1002, 0x1010 };
	spec.foreign_relocs = { 0x1008 };
	pe::Image img; std::string err;
	CHECK(load_spec(spec, img, err));
	CHECK((img.relocs == std::vector<uint32_t>{ 0x1002, 0x1010 }));
	CHECK(!img.relocs_stripped);
}

TEST(pe_x86_imports_four_byte_thunks) {
	test::PeSpec spec;
	spec.imports = { { "KERNEL32.dll", "Sleep" }, { "KERNEL32.dll", "GetTickCount" }, { "KERNEL32.dll", "#12" } };
	pe::Image img; std::string err;
	CHECK(load_spec(spec, img, err));
	CHECK(img.imports.size() == 3);
	if (img.imports.size() != 3) return;
	CHECK(img.imports[0].name == "KERNEL32.dll!Sleep");
	CHECK(img.imports[1].name == "KERNEL32.dll!GetTickCount");
	CHECK(img.imports[2].name == "KERNEL32.dll!#12");
	CHECK(img.imports[1].iat_rva - img.imports[0].iat_rva == 4);
	CHECK(img.imports[2].iat_rva - img.imports[1].iat_rva == 4);
}

TEST(pe_loads_exports_both_arches) {
	test::PeSpec spec;
	spec.dll = true;
	spec.text.assign(0x40, 0x90);
	spec.exports = { { "Bar", 0x1020 }, { "Foo", 0x1010 } };
	for (auto arch : { pe::Arch::X86, pe::Arch::X64 }) {
		spec.arch = arch;
		spec.image_base = arch == pe::Arch::X86 ? 0x10000000 : 0x180000000ull;
		pe::Image img; std::string err;
		CHECK(load_spec(spec, img, err, L"spec.dll"));
		CHECK(img.exports.size() == 2);
		if (img.exports.size() != 2) continue;
		CHECK(img.exports[0].rva == 0x1010 && img.exports[0].name == "Foo");
		CHECK(img.exports[1].rva == 0x1020 && img.exports[1].name == "Bar");
	}
}

TEST(pe_x86_relocs_stripped_flag) {
	test::PeSpec spec;
	pe::Image img; std::string err;
	CHECK(load_spec(spec, img, err));
	CHECK(img.relocs_stripped);
	CHECK(img.relocs.empty());
}

TEST(pe_x86_reloc_directory_without_usable_entries_counts_as_stripped) {
	test::PeSpec spec;
	spec.foreign_relocs = { 0x1002 };
	pe::Image img; std::string err;
	CHECK(load_spec(spec, img, err));
	CHECK(img.relocs.empty());
	CHECK(img.relocs_stripped);
	spec.foreign_relocs.clear();
	spec.relocs = { 0x1002 };
	CHECK(load_spec(spec, img, err));
	CHECK(!img.relocs.empty());
	CHECK(!img.relocs_stripped);
}

TEST(pe_x64_without_pdata_still_fails) {
	test::PeSpec spec;
	spec.arch = pe::Arch::X64;
	spec.image_base = 0x140000000ull;
	spec.pdata_for_x64 = false;
	pe::Image img; std::string err;
	CHECK(!load_spec(spec, img, err));
	CHECK(err.find("no usable .pdata") != std::string::npos);
	spec.pdata_for_x64 = true;
	CHECK(load_spec(spec, img, err));
	CHECK(img.arch == pe::Arch::X64);
	CHECK(img.ptr_size() == 8);
	CHECK(img.pdata.size() == 1);
}

TEST(pe_rejects_machine_magic_mismatch) {
	test::PeSpec spec;
	pe::Image img; std::string err;
	spec.machine_override = 0x8664;
	CHECK(!load_spec(spec, img, err));
	CHECK(!err.empty());
	test::PeSpec spec64;
	spec64.arch = pe::Arch::X64;
	spec64.machine_override = 0x014c;
	err.clear();
	CHECK(!load_spec(spec64, img, err));
	CHECK(!err.empty());
	test::PeSpec arm;
	arm.machine_override = 0x01c4;
	err.clear();
	CHECK(!load_spec(arm, img, err));
	CHECK(err.find("0x01C4") != std::string::npos);
}

TEST(pe_arch_names) {
	CHECK(std::string(pe::arch_name(pe::Arch::X86)) == "x86");
	CHECK(std::string(pe::arch_name(pe::Arch::X64)) == "x64");
}

TEST(pe_loads_x86_synthetic_samples) {
	const wchar_t* names[] = { L"old.exe", L"new.exe", L"old_fixed.exe", L"new_fixed.exe", L"old.dll", L"new.dll" };
	for (auto n : names) {
		auto p = test::x86_file(n);
		if (!p) { SKIP(); return; }
		pe::Image img; std::string err;
		CHECK(pe::load(p, img, err));
		CHECK(img.arch == pe::Arch::X86);
		CHECK(img.entry_rva != 0);
	}
	pe::Image fixed, normal, dll; std::string err;
	CHECK(pe::load(test::x86_file(L"old_fixed.exe"), fixed, err));
	CHECK(fixed.relocs_stripped);
	CHECK(pe::load(test::x86_file(L"old.exe"), normal, err));
	CHECK(!normal.relocs_stripped && !normal.relocs.empty());
	CHECK(pe::load(test::x86_file(L"old.dll"), dll, err));
	CHECK(!dll.exports.empty());
}

TEST(pe_loads_x86_real_sample) {
	auto p = test::sample_x86_old(); if (!p) { SKIP(); return; }
	pe::Image img; std::string err;
	CHECK(pe::load(p, img, err));
	CHECK(img.arch == pe::Arch::X86);
	CHECK(img.image_base == 0x400000);
	CHECK(img.entry_rva == 0xCC1CBC);
	CHECK(img.pdata.empty());
	CHECK(img.exports.size() == 276);
	CHECK(!img.relocs.empty() && std::is_sorted(img.relocs.begin(), img.relocs.end()));
	CHECK(!img.imports.empty());
}
