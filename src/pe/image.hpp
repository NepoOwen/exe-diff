#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace pe {
	constexpr uint32_t kScnExecute = 0x20000000;

	enum class Arch : uint8_t { X64, X86 };
	const char* arch_name(Arch a);

	struct Section { char name[9]; uint32_t rva, vsize, raw_off, raw_size, flags; };
	struct RuntimeFunction { uint32_t begin, end, unwind; };
	struct Import { uint32_t iat_rva; std::string name; };
	struct Export { uint32_t rva; std::string name; };

	struct Image {
		std::vector<uint8_t> file;
		Arch arch = Arch::X64;
		uint64_t image_base = 0;
		uint32_t entry_rva = 0;
		bool relocs_stripped = false;
		uint32_t size_of_image = 0;
		uint64_t content_hash = 0;
		std::vector<Section> sections;
		std::vector<RuntimeFunction> pdata;
		std::vector<uint32_t> relocs;
		std::vector<Import> imports;
		std::vector<Export> exports;

		uint32_t ptr_size() const { return arch == Arch::X86 ? 4 : 8; }
		const uint8_t* at(uint32_t rva, uint32_t size) const;
		const Section* section_of(uint32_t rva) const;
		const Section* text() const;
		bool is_exec(uint32_t rva) const;
		bool is_chained(const RuntimeFunction& f) const;
		uint32_t chain_parent(const RuntimeFunction& f) const;
		bool has_reloc(uint32_t rva, uint32_t size) const;
		const Import* import_at(uint32_t iat_rva) const;
		bool string_at(uint32_t rva, std::string& out) const;
	};

	bool load(const wchar_t* path, Image& out, std::string& err);
}
