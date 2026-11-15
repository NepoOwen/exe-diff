#pragma once
#include "src/disasm/decode.hpp"
#include "src/pe/image.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace func {
	struct Function {
		uint32_t rva, end;
		uint32_t first_chunk, chunk_count;
		uint32_t first_ref, ref_count;
		uint32_t first_token, token_count;
		uint32_t size;
		uint64_t hash;
		bool from_pdata;
		bool clean;
	};

	struct Skipped { uint32_t rva; std::string reason; };	// a function start that was found but could not be used
	struct Span { uint32_t begin, end, func; };
	struct Loc { int func; uint32_t part, off; };	// part 0 = main range, k = chunk k-1

	struct Set {
		std::vector<Function> funcs;
		std::vector<disasm::Range> chunks;
		std::vector<disasm::Ref> refs;
		std::vector<uint32_t> tokens;
		std::vector<Span> spans;
		std::vector<Skipped> skipped;	// x86 only
		uint64_t exec_bytes = 0;	// executable section bytes, minus runs of int3/nop padding
		uint64_t covered_bytes = 0;	// bytes inside functions

		int find(uint32_t rva) const;
		int at(uint32_t rva) const;
		Loc locate(uint32_t rva) const;
		std::vector<disasm::Range> parts(uint32_t idx) const;
	};

	std::vector<uint32_t> table_starts(const pe::Image& img, const std::vector<disasm::Range>& parts);
	void discover(const pe::Image& img, Set& out);
}
