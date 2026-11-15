#include "src/func/seeds.hpp"
#include "src/disasm/decode.hpp"
#include <algorithm>
#include <cstring>

namespace func {
	namespace {
		void sort_unique(std::vector<uint32_t>& v) {
			std::sort(v.begin(), v.end());
			v.erase(std::unique(v.begin(), v.end()), v.end());
		}
	}

	void seeds_x86(const pe::Image& img, std::vector<uint32_t>& out, std::vector<uint32_t>* data_ptrs) {
		const uint32_t base = static_cast<uint32_t>(img.image_base);
		if (img.entry_rva && img.is_exec(img.entry_rva)) out.push_back(img.entry_rva);
		for (auto& e : img.exports)
			if (img.is_exec(e.rva)) out.push_back(e.rva);
		auto& ptrs = data_ptrs ? *data_ptrs : out;
		for (uint32_t r : img.relocs) {
			if (img.is_exec(r)) continue;	// inside code: operands and jump table entries, not function pointers we can trust
			auto p = img.at(r, 4);
			if (!p) continue;
			uint32_t v;
			std::memcpy(&v, p, 4);
			if (v >= base && img.is_exec(v - base)) ptrs.push_back(v - base);
		}
		sort_unique(out);
		if (data_ptrs) sort_unique(*data_ptrs);
	}

	uint32_t padded_end(const pe::Image& img, uint32_t start, uint32_t limit, uint32_t* data_end) {
		if (data_end) *data_end = 0;
		auto sec = img.section_of(start);
		if (!sec) return start;
		const uint32_t sec_end = sec->rva + sec->vsize;
		limit = std::min(limit, sec_end);
		const uint32_t base = static_cast<uint32_t>(img.image_base);
		auto& dec = disasm::decoder(img.arch);
		uint32_t far = start, off = start, tail = 0;
		bool after_exit = false;	// the previous instruction was a ret or a jmp
		ZydisDecodedInstruction insn;
		ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
		while (off < limit) {
			uint32_t n = std::min<uint32_t>(15, limit - off);
			auto p = img.at(off, n);
			while (!p && n > 1) p = img.at(off, --n);
			if (!p || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, n, &insn, ops))) {
				if (data_end) *data_end = tail;
				return off;	// start itself when nothing decoded
			}
			// padding after a ret or jmp ends the function: an earlier branch past it is a tail jump
			if (insn.mnemonic == ZYDIS_MNEMONIC_INT3 && off > start && (off >= far || after_exit)) {
				if (data_end) *data_end = tail;
				return off;
			}
			uint32_t next = off + insn.length;
			auto cat = insn.meta.category;
			if ((cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR) && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				ZyanU64 abs;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], off, &abs)) && abs >= start && abs < limit)
					far = std::max(far, static_cast<uint32_t>(abs));
			} else if (cat == ZYDIS_CATEGORY_UNCOND_BR && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY
				&& ops[0].mem.base == ZYDIS_REGISTER_NONE && ops[0].mem.index != ZYDIS_REGISTER_NONE && insn.raw.disp.size == 32) {
				uint32_t table = static_cast<uint32_t>(insn.raw.disp.value) - base;	// switch: jmp [index*4 + table]
				uint32_t count = 0;
				for (; count < 0x4000; ++count) {
					auto e = img.at(table + count * 4, 4);
					if (!e) break;
					uint32_t v;
					std::memcpy(&v, e, 4);
					uint32_t t = v - base;
					if (v < base || t < start || t >= limit) break;
					far = std::max(far, t);
				}
				if (count) tail = std::max(tail, table + count * 4);
			}
			if ((cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR) && next > far) {
				if (data_end) *data_end = tail;
				return next;
			}
			after_exit = cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR;
			off = next;
		}
		if (limit >= sec_end) return start;	// ran off the end of the section: no end to be found
		if (data_end) *data_end = tail;
		return limit;
	}
}
