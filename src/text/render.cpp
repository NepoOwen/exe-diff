#include "src/text/render.hpp"
#include "src/disasm/decode.hpp"
#include "external/zydis/Zydis.h"
#include <cstdio>
#include <cstring>

namespace text {
	namespace {
		constexpr size_t kMaxString = 60;

		struct Ctx {
			const pe::Image& img;
			const func::Set& set;
			uint32_t self;
			const std::vector<std::string>& names;
			bool image_rel = false;
		};

		std::string hex(const char* f, uint64_t v) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), f, static_cast<unsigned long long>(v));
			return buf;
		}

		std::string quoted(const std::string& s) {
			std::string out = "\"";
			for (size_t i = 0; i < s.size() && i < kMaxString; ++i) {
				if (s[i] == '"' || s[i] == '\\') out += '\\';
				out += s[i];
			}
			if (s.size() > kMaxString) out += "...";
			return out + "\"";
		}

		std::string section_text(const pe::Image& img, uint32_t rva) {
			auto sec = img.section_of(rva);
			return sec ? std::string("<") + sec->name + ">" : std::string();
		}

		std::string func_text(const Ctx& c, uint32_t rva) {
			auto l = c.set.locate(rva);
			if (l.func < 0) return {};
			if (static_cast<uint32_t>(l.func) == c.self)
				return l.part ? "loc_c" + std::to_string(l.part) + hex("_%llX", l.off) : hex("loc_%llX", l.off);
			std::string name = static_cast<size_t>(l.func) < c.names.size() ? c.names[l.func] : hex("sub_%llX", c.img.image_base + c.set.funcs[l.func].rva);
			if (l.part) return name + ".c" + std::to_string(l.part) + hex("+0x%llX", l.off);
			return l.off ? name + hex("+0x%llX", l.off) : name;
		}

		std::string target_text(const Ctx& c, uint32_t rva) {
			if (auto imp = c.img.import_at(rva)) return imp->name;
			std::string s;
			if (c.img.string_at(rva, s)) return quoted(s);
			if (auto f = func_text(c, rva); !f.empty()) return f;
			return section_text(c.img, rva);
		}

		ZyanStatus append(ZydisFormatterBuffer* buffer, const std::string& s) {
			ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
			ZyanString* str;
			ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &str));
			auto& v = str->vector;	// size counts the terminator, like the amalgamation's internal ZydisStringAppend
			if (v.size + s.size() > v.capacity) return ZYAN_STATUS_INSUFFICIENT_BUFFER_SIZE;
			auto p = static_cast<char*>(v.data);
			std::memcpy(p + v.size - 1, s.data(), s.size());
			v.size += s.size();
			p[v.size - 1] = 0;
			return ZYAN_STATUS_SUCCESS;
		}

		ZydisFormatterFunc orig_mem, orig_abs, orig_disp, orig_imm;

		const Ctx& ctx_of(ZydisFormatterContext* context) { return *static_cast<const Ctx*>(context->user_data); }

		// x86: relocated field, or any field pointing into the image when the file has no relocations
		bool x86_address(const Ctx& c, uint32_t at, uint32_t value, uint32_t& rva) {
			uint32_t base = static_cast<uint32_t>(c.img.image_base);
			if (value < base) return false;
			rva = value - base;
			if (c.img.has_reloc(at, 1)) return true;
			return c.img.relocs_stripped && rva < c.img.size_of_image && c.img.section_of(rva);
		}

		bool is_riprel(const ZydisDecodedOperand& op) {
			return op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP && op.mem.index == ZYDIS_REGISTER_NONE;
		}

		ZyanStatus hook_mem(const ZydisFormatter* f, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) {
			auto& c = ctx_of(context);
			if (is_riprel(*context->operand)) {
				ZyanU64 abs;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(context->instruction, context->operand, context->runtime_address, &abs))) {
					uint32_t rva = static_cast<uint32_t>(abs);
					std::string s;
					if (auto imp = c.img.import_at(rva)) return append(buffer, imp->name);
					if (c.img.string_at(rva, s)) return append(buffer, quoted(s));
					if (c.img.is_exec(rva)) {
						auto t = func_text(c, rva);
						return append(buffer, t.empty() ? section_text(c.img, rva) : t);
					}
				}
			}
			return orig_mem(f, buffer, context);
		}

		ZyanStatus hook_abs(const ZydisFormatter* f, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) {
			auto& c = ctx_of(context);
			ZyanU64 abs;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(context->instruction, context->operand, context->runtime_address, &abs))) {
				if (c.img.arch == pe::Arch::X86) {
					uint32_t rva = static_cast<uint32_t>(abs);	// a relative branch target is already an rva
					bool ok = context->operand->type != ZYDIS_OPERAND_TYPE_MEMORY
						|| x86_address(c, static_cast<uint32_t>(context->runtime_address) + context->instruction->raw.disp.offset, static_cast<uint32_t>(abs), rva);
					if (ok) {
						auto t = target_text(c, rva);
						if (!t.empty()) return append(buffer, t);
					}
					return orig_abs(f, buffer, context);
				}
				if (abs >= c.img.image_base) abs -= c.img.image_base;
				if (abs <= UINT32_MAX) {
					auto t = target_text(c, static_cast<uint32_t>(abs));
					if (!t.empty()) return append(buffer, t);
				}
			}
			return orig_abs(f, buffer, context);
		}

		ZyanStatus hook_disp(const ZydisFormatter* f, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) {
			auto& c = ctx_of(context);
			auto& op = *context->operand;
			auto& insn = *context->instruction;
			uint32_t rva;
			if (c.img.arch == pe::Arch::X86 && insn.raw.disp.size == 32
				&& x86_address(c, static_cast<uint32_t>(context->runtime_address) + insn.raw.disp.offset, static_cast<uint32_t>(insn.raw.disp.value), rva)) {
				auto t = target_text(c, rva);
				if (!t.empty()) return append(buffer, (op.mem.base != ZYDIS_REGISTER_NONE || op.mem.index != ZYDIS_REGISTER_NONE ? "+" : "") + t);
			}
			if (c.image_rel && op.mem.base != ZYDIS_REGISTER_RIP && context->instruction->raw.disp.size == 32) {
				uint32_t disp = static_cast<uint32_t>(context->instruction->raw.disp.value);
				if (c.img.section_of(disp)) {
					auto t = target_text(c, disp);
					return append(buffer, "+" + t);
				}
			}
			return orig_disp(f, buffer, context);
		}

		ZyanStatus hook_imm(const ZydisFormatter* f, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) {
			auto& c = ctx_of(context);
			auto& insn = *context->instruction;
			auto& op = *context->operand;
			if (c.img.arch == pe::Arch::X86 && !op.imm.is_relative && op.size == 32) {
				for (auto& raw : insn.raw.imm) {
					if (raw.size != 32) continue;
					uint32_t rva;
					if (!x86_address(c, static_cast<uint32_t>(context->runtime_address) + raw.offset, static_cast<uint32_t>(op.imm.value.u), rva)) continue;
					auto t = target_text(c, rva);
					if (!t.empty()) return append(buffer, t);
				}
			}
			if (c.img.arch == pe::Arch::X64 && !op.imm.is_relative && op.size == 64) {
				for (auto& raw : insn.raw.imm) {
					if (raw.size != 64) continue;
					uint32_t at = static_cast<uint32_t>(context->runtime_address) + raw.offset;
					if (!c.img.has_reloc(at, 1)) continue;
					uint64_t va = op.imm.value.u;
					if (va >= c.img.image_base && va - c.img.image_base <= UINT32_MAX) {
						auto t = target_text(c, static_cast<uint32_t>(va - c.img.image_base));
						if (!t.empty()) return append(buffer, t);
					}
				}
			}
			return orig_imm(f, buffer, context);
		}

		struct Formatter {
			ZydisFormatter f;
			ZydisDecoder d;
			explicit Formatter(pe::Arch arch) {
				ZydisDecoderInit(&d, disasm::machine_mode(arch), disasm::stack_width(arch));
				ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL);
				auto set = [&](ZydisFormatterFunction type, ZydisFormatterFunc hook, ZydisFormatterFunc& orig) {
					const void* p = reinterpret_cast<const void*>(hook);
					ZydisFormatterSetHook(&f, type, &p);
					orig = reinterpret_cast<ZydisFormatterFunc>(const_cast<void*>(p));
				};
				set(ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_MEM, hook_mem, orig_mem);
				set(ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, hook_abs, orig_abs);
				set(ZYDIS_FORMATTER_FUNC_PRINT_DISP, hook_disp, orig_disp);
				set(ZYDIS_FORMATTER_FUNC_PRINT_IMM, hook_imm, orig_imm);
			}
		};

		const Formatter& formatter(pe::Arch arch) {
			static Formatter x64(pe::Arch::X64), x86(pe::Arch::X86);
			return arch == pe::Arch::X86 ? x86 : x64;
		}
	}

	std::vector<std::string> render(const pe::Image& img, const func::Set& set, uint32_t func_idx, const std::vector<std::string>& names) {
		std::vector<std::string> out;
		auto& fm = formatter(img.arch);
		Ctx ctx{ img, set, func_idx, names };
		auto parts = set.parts(func_idx);
		auto tables = func::table_starts(img, parts);
		disasm::Decoded d;
		ZydisDecodedInstruction insn;
		ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
		char buf[512];
		uint32_t regs = 0;
		for (auto& r : parts) {
			disasm::decode(img, r, d, tables.empty() ? nullptr : &tables);
			regs |= d.base_regs;
		}
		for (size_t k = 0; k < parts.size(); ++k) {
			auto r = parts[k];
			if (k) out.push_back("; chunk");
			disasm::decode(img, r, d, tables.empty() ? nullptr : &tables, regs);
			uint32_t size = r.end - r.begin, done = 0;
			size_t ri = 0;
			for (uint32_t off : d.insn_offs) {
				ctx.image_rel = false;
				for (; ri < d.refs.size() && d.refs[ri].insn_off <= off; ++ri)
					ctx.image_rel |= d.refs[ri].insn_off == off && d.refs[ri].kind == disasm::RefKind::ImageRel;
				uint32_t n = std::min<uint32_t>(15, size - off);
				auto p = img.at(r.begin + off, n);
				while (!p && n > 1) p = img.at(r.begin + off, --n);
				if (!p || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&fm.d, p, n, &insn, ops))) break;
				if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fm.f, &insn, ops, insn.operand_count_visible, buf, sizeof(buf), r.begin + off, &ctx)))
					std::snprintf(buf, sizeof(buf), "; ?");
				out.push_back(buf);
				done = off + insn.length;
			}
			if (done < size) out.push_back("; data, " + std::to_string(size - done) + " bytes");
		}
		return out;
	}
}
