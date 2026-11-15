#pragma once
#include "src/pe/image.hpp"
#include "external/zydis/Zydis.h"
#include <cstdint>
#include <vector>

namespace disasm {
	ZydisMachineMode machine_mode(pe::Arch arch);
	ZydisStackWidth stack_width(pe::Arch arch);
	const ZydisDecoder& decoder(pe::Arch arch);

	struct Range { uint32_t begin, end; };
	enum class RefKind : uint8_t { Code, Import, String, Data, ImageRel };
	struct Ref { uint32_t insn_off; uint32_t target_rva; RefKind kind; bool is_call; bool is_branch; };
	struct Decoded {
		std::vector<uint8_t> masked;
		std::vector<uint32_t> insn_offs;
		std::vector<Ref> refs;
		bool clean = true;
		uint32_t base_regs = 0;	// bit per gpr id: passed in, plus any loaded with the image base in the range
	};

	// data_starts: rvas where a jump table starts, from other ranges of the same function
	// base_regs: registers that hold the image base somewhere in the function; [reg+disp32] through them is image-relative
	void decode(const pe::Image& img, Range r, Decoded& out, const std::vector<uint32_t>* data_starts = nullptr, uint32_t base_regs = 0);
}
