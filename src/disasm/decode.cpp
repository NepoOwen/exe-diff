#include "src/disasm/decode.hpp"
#include <cstring>
#include <string>

namespace disasm {
	ZydisMachineMode machine_mode(pe::Arch arch) {
		return arch == pe::Arch::X86 ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;
	}

	ZydisStackWidth stack_width(pe::Arch arch) {
		return arch == pe::Arch::X86 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64;
	}

	const ZydisDecoder& decoder(pe::Arch arch) {
		struct Decoders {
			ZydisDecoder d[2];
			Decoders() {
				for (auto a : { pe::Arch::X64, pe::Arch::X86 })
					ZydisDecoderInit(&d[static_cast<int>(a)], machine_mode(a), stack_width(a));
			}
		};
		static Decoders all;
		return all.d[static_cast<int>(arch)];
	}

	namespace {
		void zero(std::vector<uint8_t>& v, uint32_t off, uint32_t n) {
			if (off < v.size())
				std::memset(v.data() + off, 0, std::min<size_t>(n, v.size() - off));
		}

		RefKind classify(const pe::Image& img, uint32_t target) {
			if (img.import_at(target)) return RefKind::Import;
			std::string s;
			if (img.string_at(target, s)) return RefKind::String;
			if (img.is_exec(target)) return RefKind::Code;
			return RefKind::Data;
		}

		bool in_any_section(const pe::Image& img, uint32_t rva) {
			return img.section_of(rva) != nullptr;
		}

		bool in_image(const pe::Image& img, uint32_t value) {	// a 32-bit absolute address of something in the image
			return value >= img.image_base && value - img.image_base < img.size_of_image && img.section_of(static_cast<uint32_t>(value - img.image_base));
		}

		uint32_t gpr_bit(ZydisRegister reg) {
			auto full = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
			if (ZydisRegisterGetClass(full) != ZYDIS_REGCLASS_GPR64) return 0;
			return 1u << ZydisRegisterGetId(full);
		}
	}

	void decode(const pe::Image& img, Range r, Decoded& out, const std::vector<uint32_t>* data_starts, uint32_t base_regs) {
		out.masked.clear();
		out.insn_offs.clear();
		out.refs.clear();
		out.clean = true;
		out.base_regs = base_regs;
		if (r.end <= r.begin) return;
		uint32_t size = r.end - r.begin;
		out.masked.assign(size, 0);
		uint32_t avail = size;
		const uint8_t* src = img.at(r.begin, size);
		if (!src) {
			avail = 0;
			while (avail < size && img.at(r.begin + avail, 1)) ++avail;
			src = avail ? img.at(r.begin, avail) : nullptr;
			out.clean = false;
		}
		if (src) std::memcpy(out.masked.data(), src, avail);

		uint32_t stop = UINT32_MAX;
		if (data_starts)
			for (uint32_t s : *data_starts)
				if (s >= r.begin && s < r.end) stop = std::min(stop, s);
		const bool x86 = img.arch == pe::Arch::X86;
		const uint32_t base32 = static_cast<uint32_t>(img.image_base);
		auto table = [&](uint32_t from) {
			for (uint32_t k = from; k + 4 <= avail; k += 4) {
				uint32_t v;
				std::memcpy(&v, src + k, 4);
				if (x86 ? v >= base32 && img.is_exec(v - base32) : v && img.is_exec(v)) zero(out.masked, k, 4);
			}
		};

		auto& dec = decoder(img.arch);
		ZydisDecodedInstruction insn;
		ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
		uint32_t off = 0;
		while (off < avail) {
			if (r.begin + off >= stop) {
				table(stop - r.begin);
				return;
			}
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, src + off, avail - off, &insn, ops))) {
				out.clean = false;
				return;
			}
			out.insn_offs.push_back(off);
			uint32_t rva = r.begin + off;
			bool is_call = insn.meta.category == ZYDIS_CATEGORY_CALL;
			bool is_branch = insn.meta.category == ZYDIS_CATEGORY_COND_BR || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
			bool masked_disp = false, loads_base = false;
			for (uint8_t i = 0; i < insn.operand_count_visible; ++i) {
				auto& op = ops[i];
				if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
					ZyanU64 abs;
					if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, rva, &abs))) continue;
					uint32_t target = static_cast<uint32_t>(abs);
					if (target >= r.begin && target < r.end) continue;
					for (auto& imm : insn.raw.imm)
						if (imm.is_relative)
							zero(out.masked, off + imm.offset, imm.size / 8);
					out.refs.push_back({ off, target, RefKind::Code, is_call, is_branch });
				} else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
					ZyanU64 abs;
					if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, rva, &abs))) continue;
					uint32_t target = static_cast<uint32_t>(abs);
					if (target >= r.begin && target < r.end) continue;
					zero(out.masked, off + insn.raw.disp.offset, insn.raw.disp.size / 8);
					masked_disp = true;
					loads_base |= target == 0 && insn.mnemonic == ZYDIS_MNEMONIC_LEA;
					out.refs.push_back({ off, target, classify(img, target), is_call, is_branch });
				} else if (!x86 && op.type == ZYDIS_OPERAND_TYPE_MEMORY && !masked_disp && op.mem.base != ZYDIS_REGISTER_RIP && insn.raw.disp.size == 32
					&& (op.mem.index != ZYDIS_REGISTER_NONE || (base_regs & gpr_bit(op.mem.base)))) {
					uint32_t disp = static_cast<uint32_t>(insn.raw.disp.value);
					if (!in_any_section(img, disp)) continue;
					zero(out.masked, off + insn.raw.disp.offset, 4);
					masked_disp = true;
					if (disp > rva && disp < r.end) stop = std::min(stop, disp);
					out.refs.push_back({ off, disp, RefKind::ImageRel, is_call, is_branch });
				}
			}
			if (x86) {
				bool relocated = img.has_reloc(rva, insn.length);
				auto fix = [&](uint32_t field_off, uint32_t value, bool is_disp) {
					uint32_t target = value - base32;
					zero(out.masked, off + field_off, 4);
					if (is_disp && target > rva && target < r.end) stop = std::min(stop, target);	// jump table inside the function's range
					out.refs.push_back({ off, target, classify(img, target), is_call, is_branch });
				};
				if (relocated) {
					for (uint32_t k = 0; k + 4 <= insn.length; ++k) {
						if (!img.has_reloc(rva + k, 1)) continue;
						uint32_t value = 0;
						if (auto p = img.at(rva + k, 4)) std::memcpy(&value, p, 4);
						fix(k, value, k == insn.raw.disp.offset && insn.raw.disp.size == 32);
						k += 3;
					}
				} else if (img.relocs_stripped) {
					if (insn.raw.disp.size == 32 && in_image(img, static_cast<uint32_t>(insn.raw.disp.value)))
						fix(insn.raw.disp.offset, static_cast<uint32_t>(insn.raw.disp.value), true);
					for (auto& imm : insn.raw.imm)
						if (imm.size == 32 && !imm.is_relative && in_image(img, static_cast<uint32_t>(imm.value.u)))
							fix(imm.offset, static_cast<uint32_t>(imm.value.u), false);
				}
			} else if (img.has_reloc(rva, insn.length)) {
				for (uint32_t k = 0; k < insn.length; ++k) {
					if (!img.has_reloc(rva + k, 1)) continue;
					uint64_t value = 0;
					if (auto p = img.at(rva + k, 8)) std::memcpy(&value, p, 8);
					zero(out.masked, off + k, 8);
					uint32_t target = static_cast<uint32_t>(value - img.image_base);
					loads_base |= value == img.image_base && insn.mnemonic == ZYDIS_MNEMONIC_MOV;
					out.refs.push_back({ off, target, img.is_exec(target) ? RefKind::Code : RefKind::Data, is_call, is_branch });
				}
			}
			if (loads_base && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				base_regs |= gpr_bit(ops[0].reg.value);
				out.base_regs = base_regs;
			}
			off += insn.length;
		}
	}
}
