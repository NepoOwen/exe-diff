#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace test {
	struct Case { const char* name; void (*fn)(); };
	std::vector<Case>& registry();
	struct Reg {
		Reg(const char* name, void (*fn)()) { registry().push_back({ name, fn }); }
	};
	void fail(const char* file, int line, const char* expr);
	void skip();
	const wchar_t* sample_old();
	const wchar_t* sample_new();
	const wchar_t* sample_x86_old();
	const wchar_t* sample_x86_new();
	const wchar_t* x86_file(const wchar_t* name);
	double now_seconds();
}

#include "src/pe/image.hpp"
#include <algorithm>
#include <cstring>

namespace test {
	constexpr uint32_t kDataRva = 0x20000;

	// exec section at rva holding code, non-exec ".data" at kDataRva (0x1000 zero bytes)
	inline pe::Image image_from_code(const std::vector<uint8_t>& code, uint32_t rva = 0x1000) {
		pe::Image img;
		img.image_base = 0x140000000ull;
		img.size_of_image = 0x100000;
		uint32_t code_size = static_cast<uint32_t>(std::max<size_t>(code.size(), 0x1000));
		img.file.assign(code_size + 0x1000, 0);
		std::memcpy(img.file.data(), code.data(), code.size());
		pe::Section t{};
		std::memcpy(t.name, ".text", 6);
		t.rva = rva; t.vsize = code_size; t.raw_off = 0; t.raw_size = code_size; t.flags = 0x60000020;
		pe::Section d{};
		std::memcpy(d.name, ".data", 6);
		d.rva = kDataRva; d.vsize = 0x1000; d.raw_off = code_size; d.raw_size = 0x1000; d.flags = 0xC0000040;
		img.sections = { t, d };
		return img;
	}

	// like image_from_code, but a 32-bit image with base 0x400000
	inline pe::Image image_from_code_x86(const std::vector<uint8_t>& code, uint32_t rva = 0x1000) {
		pe::Image img = image_from_code(code, rva);
		img.arch = pe::Arch::X86;
		img.image_base = 0x400000;
		return img;
	}

	inline void put(pe::Image& img, uint32_t rva, const void* bytes, size_t n) {
		auto p = const_cast<uint8_t*>(img.at(rva, static_cast<uint32_t>(n)));
		if (p) std::memcpy(p, bytes, n);
	}
}

#define TEST(name) \
	static void test_##name(); \
	static test::Reg reg_##name(#name, test_##name); \
	static void test_##name()
#define CHECK(expr) do { if (!(expr)) test::fail(__FILE__, __LINE__, #expr); } while (0)
#define SKIP() test::skip()
