#include "src/func/discover.hpp"
#include "src/func/seeds.hpp"
#include "src/util/hash.hpp"
#include "external/zydis/Zydis.h"
#include <algorithm>
#include <functional>
#include <queue>
#include <set>
#include <string>

namespace func {
	namespace {
		struct Proto {
			uint32_t rva, end;
			bool pdata;
			std::vector<disasm::Range> chunks;
			std::vector<disasm::Ref> refs;
			std::vector<uint32_t> tokens;
			uint32_t size = 0;
			uint64_t hash = 0;
			bool clean = true;
			uint32_t tail = 0;	// x86: end of the jump table bytes that follow the code
		};

		const pe::RuntimeFunction* pdata_at(const pe::Image& img, uint32_t begin) {
			auto it = std::lower_bound(img.pdata.begin(), img.pdata.end(), begin, [](const pe::RuntimeFunction& a, uint32_t v) { return a.begin < v; });
			return it != img.pdata.end() && it->begin == begin ? &*it : nullptr;
		}

		uint32_t root_of(const pe::Image& img, const pe::RuntimeFunction& f) {
			const pe::RuntimeFunction* cur = &f;
			for (int depth = 0; depth < 32 && img.is_chained(*cur); ++depth) {
				auto parent = pdata_at(img, img.chain_parent(*cur));
				if (!parent || parent == cur) return img.chain_parent(*cur);
				cur = parent;
			}
			return cur->begin;
		}

		uint64_t ref_content(const pe::Image& img, const disasm::Ref& r, uint64_t seed) {
			if (r.kind == disasm::RefKind::String) {
				std::string s;
				if (img.string_at(r.target_rva, s)) return util::hash_str(s, seed);
			} else if (r.kind == disasm::RefKind::Import) {
				if (auto imp = img.import_at(r.target_rva)) return util::hash_str(imp->name, seed);
			}
			return 0;
		}

		void analyse(const pe::Image& img, Proto& p) {
			disasm::Decoded d;
			std::vector<uint32_t> tables;
			if (!p.chunks.empty()) {
				std::vector<disasm::Range> parts{ { p.rva, p.end } };
				parts.insert(parts.end(), p.chunks.begin(), p.chunks.end());
				tables = table_starts(img, parts);
			}
			uint64_t h;
			uint32_t regs = 0, seen = 0;
			auto one = [&](disasm::Range r) {
				disasm::decode(img, r, d, tables.empty() ? nullptr : &tables, regs);
				seen |= d.base_regs;
				p.clean &= d.clean;
				p.size += r.end - r.begin;
				h = util::hash_bytes(d.masked.data(), d.masked.size(), h);
				size_t ri = 0;
				for (size_t i = 0; i < d.insn_offs.size(); ++i) {
					uint32_t a = d.insn_offs[i];
					uint32_t b = i + 1 < d.insn_offs.size() ? d.insn_offs[i + 1] : static_cast<uint32_t>(d.masked.size());
					uint64_t t = util::hash_bytes(d.masked.data() + a, b - a, 0x9e37);
					for (; ri < d.refs.size() && d.refs[ri].insn_off == a; ++ri) {
						uint64_t c = ref_content(img, d.refs[ri], 0x51ed);
						if (c) {
							t = util::mix(t, c);
							h = util::mix(h, c);
						}
					}
					p.tokens.push_back(static_cast<uint32_t>(t ^ (t >> 32)));
				}
				p.refs.insert(p.refs.end(), d.refs.begin(), d.refs.end());
			};
			for (;;) {
				h = 0x84222325cbf29ce4ull;
				p.clean = true; p.size = 0; p.tokens.clear(); p.refs.clear();
				one({ p.rva, p.end });
				for (auto& c : p.chunks) one(c);
				if (seen == regs) break;
				regs = seen;
			}
			p.hash = h;
		}

		uint32_t leaf_end(const pe::Image& img, uint32_t start, uint32_t limit) {
			auto& dec = disasm::decoder(img.arch);
			uint32_t far = start, off = start;
			ZydisDecodedInstruction insn;
			ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
			while (off < limit) {
				uint32_t n = std::min<uint32_t>(15, limit - off);
				auto p = img.at(off, n);
				while (!p && n > 1) p = img.at(off, --n);
				if (!p || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, n, &insn, ops))) return off;
				uint32_t next = off + insn.length;
				auto cat = insn.meta.category;
				if ((cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR) && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					ZyanU64 abs;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], off, &abs)) && abs >= start && abs < limit)
						far = std::max(far, static_cast<uint32_t>(abs));
				}
				if ((cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR) && next > far)
					return next;
				off = next;
			}
			return limit;
		}

		struct Known {
			std::vector<disasm::Range> ranges;
			void add(disasm::Range r) { ranges.push_back(r); }
			void sort() { std::sort(ranges.begin(), ranges.end(), [](auto& a, auto& b) { return a.begin < b.begin; }); }
			bool contains(uint32_t rva) const {
				auto it = std::upper_bound(ranges.begin(), ranges.end(), rva, [](uint32_t v, const disasm::Range& r) { return v < r.begin; });
				return it != ranges.begin() && rva < std::prev(it)->end;
			}
			uint32_t next_start(uint32_t rva) const {
				auto it = std::upper_bound(ranges.begin(), ranges.end(), rva, [](uint32_t v, const disasm::Range& r) { return v < r.begin; });
				return it == ranges.end() ? UINT32_MAX : it->begin;
			}
		};
	}

	int Set::find(uint32_t rva) const {
		auto it = std::upper_bound(spans.begin(), spans.end(), rva, [](uint32_t v, const Span& s) { return v < s.begin; });
		if (it == spans.begin()) return -1;
		--it;
		return rva < it->end ? static_cast<int>(it->func) : -1;
	}

	int Set::at(uint32_t rva) const {
		auto it = std::lower_bound(funcs.begin(), funcs.end(), rva, [](const Function& f, uint32_t v) { return f.rva < v; });
		return it != funcs.end() && it->rva == rva ? static_cast<int>(it - funcs.begin()) : -1;
	}

	Loc Set::locate(uint32_t rva) const {
		int f = find(rva);
		if (f < 0) return { -1, 0, 0 };
		auto& fn = funcs[f];
		if (rva >= fn.rva && rva < fn.end) return { f, 0, rva - fn.rva };
		for (uint32_t k = 0; k < fn.chunk_count; ++k) {
			auto& c = chunks[fn.first_chunk + k];
			if (rva >= c.begin && rva < c.end) return { f, k + 1, rva - c.begin };
		}
		return { f, 0, 0 };
	}

	std::vector<disasm::Range> Set::parts(uint32_t idx) const {
		auto& f = funcs[idx];
		std::vector<disasm::Range> v{ { f.rva, f.end } };
		v.insert(v.end(), chunks.begin() + f.first_chunk, chunks.begin() + f.first_chunk + f.chunk_count);
		return v;
	}

	std::vector<uint32_t> table_starts(const pe::Image& img, const std::vector<disasm::Range>& parts) {
		if (parts.size() < 2) return {};
		auto order = parts;
		std::sort(order.begin(), order.end(), [](auto& a, auto& b) { return a.begin < b.begin; });
		disasm::Decoded d;
		auto collect = [&](const std::vector<uint32_t>* stops) {
			std::vector<uint32_t> found;
			for (auto& r : order) {
				auto use = stops ? stops : &found;
				disasm::decode(img, r, d, use->empty() ? nullptr : use);
				for (auto& ref : d.refs) {
					if (ref.kind != disasm::RefKind::ImageRel) continue;
					for (auto& p : order)
						if (ref.target_rva >= p.begin && ref.target_rva < p.end) { found.push_back(ref.target_rva); break; }
				}
			}
			std::sort(found.begin(), found.end());
			found.erase(std::unique(found.begin(), found.end()), found.end());
			return found;
		};
		auto tables = collect(nullptr);
		for (int round = 0; round < 4; ++round) {	// drop starts that only table bytes decoded as code pointed at
			auto next = collect(&tables);
			if (next == tables) break;
			tables = std::move(next);
		}
		return tables;
	}

	namespace {
	std::vector<Proto> pdata_protos(const pe::Image& img) {
		std::vector<Proto> protos;
		protos.reserve(img.pdata.size());
		std::vector<std::pair<uint32_t, disasm::Range>> chained;
		for (auto& rf : img.pdata) {
			if (img.is_chained(rf))
				chained.push_back({ root_of(img, rf), { rf.begin, rf.end } });
			else
				protos.push_back({ rf.begin, rf.end, true });
		}
		auto proto_at = [&](uint32_t rva) -> Proto* {
			auto it = std::lower_bound(protos.begin(), protos.end(), rva, [](const Proto& p, uint32_t v) { return p.rva < v; });
			return it != protos.end() && it->rva == rva ? &*it : nullptr;
		};
		std::vector<Proto> orphans;
		for (auto& [root, range] : chained) {
			if (auto p = proto_at(root))
				p->chunks.push_back(range);
			else
				orphans.push_back({ range.begin, range.end, true });
		}
		protos.insert(protos.end(), orphans.begin(), orphans.end());
		std::sort(protos.begin(), protos.end(), [](auto& a, auto& b) { return a.rva < b.rva; });

		Known known;
		for (auto& p : protos) {
			known.add({ p.rva, p.end });
			for (auto& c : p.chunks) known.add(c);
		}
		known.sort();

		size_t analysed = 0;
		for (;;) {
			for (; analysed < protos.size(); ++analysed)
				analyse(img, protos[analysed]);
			std::vector<uint32_t> cands;
			for (auto& p : protos)
				for (auto& r : p.refs)
					if (r.kind == disasm::RefKind::Code && r.is_call && img.is_exec(r.target_rva) && !known.contains(r.target_rva))
						cands.push_back(r.target_rva);
			std::sort(cands.begin(), cands.end());
			cands.erase(std::unique(cands.begin(), cands.end()), cands.end());
			if (cands.empty()) break;
			size_t before = protos.size();
			for (size_t i = 0; i < cands.size(); ++i) {
				uint32_t c = cands[i];
				auto sec = img.section_of(c);
				uint32_t limit = std::min(known.next_start(c), sec->rva + sec->vsize);
				if (i + 1 < cands.size()) limit = std::min(limit, cands[i + 1]);
				uint32_t end = leaf_end(img, c, limit);
				if (end > c)
					protos.push_back({ c, end, false });
			}
			if (protos.size() == before) break;
			for (size_t i = before; i < protos.size(); ++i)
				known.add({ protos[i].rva, protos[i].end });
			known.sort();
		}
		std::sort(protos.begin(), protos.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
		return protos;
	}
	}

	namespace {
	// x86 has no .pdata: starts come from entry and exports, call targets, code after padding, last data pointers
	std::vector<Proto> x86_protos(const pe::Image& img, std::vector<Skipped>& skipped) {
		std::vector<uint32_t> hard, soft;
		seeds_x86(img, hard, &soft);
		std::vector<Proto> protos;
		Known known;
		std::set<uint32_t> tried;
		auto& dec = disasm::decoder(img.arch);
		auto sec_end = [&](uint32_t rva) {
			auto s = img.section_of(rva);
			return s ? s->rva + s->vsize : 0u;
		};
		auto decodes = [&](uint32_t rva) {
			uint32_t n = 15;
			auto p = img.at(rva, n);
			while (!p && n > 1) p = img.at(rva, --n);
			ZydisDecodedInstruction insn;
			ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
			return p && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, n, &insn, ops));
		};
		// first byte after the int3/nop padding that follows `from`, or 0 when there is none
		auto after_padding = [&](uint32_t from) -> uint32_t {
			uint32_t q = from, end = sec_end(from - 1);
			ZydisDecodedInstruction insn;
			ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
			while (q < end) {
				uint32_t n = std::min<uint32_t>(15, end - q);
				auto p = img.at(q, n);
				while (!p && n > 1) p = img.at(q, --n);
				if (!p || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, n, &insn, ops))) break;
				if (insn.mnemonic != ZYDIS_MNEMONIC_INT3 && insn.mnemonic != ZYDIS_MNEMONIC_NOP) break;
				q += insn.length;
			}
			return q > from && q < end ? q : 0;
		};
		auto usable = [&](std::vector<uint32_t>& v) {
			std::sort(v.begin(), v.end());
			v.erase(std::unique(v.begin(), v.end()), v.end());
			v.erase(std::remove_if(v.begin(), v.end(), [&](uint32_t c) { return !img.is_exec(c) || known.contains(c) || tried.count(c); }), v.end());
		};

		std::vector<uint32_t> work = hard;
		usable(work);
		size_t analysed = 0, scanned = 0;
		bool soft_done = false;
		for (;;) {
			if (!work.empty()) {	// ascending, so the function just added is the only one a later start can fall inside
				std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>> heap(work.begin(), work.end());
				work.clear();
				const size_t before = protos.size();
				uint32_t round_end = 0;
				while (!heap.empty()) {
					uint32_t c = heap.top();
					heap.pop();
					if (c < round_end || !img.is_exec(c) || known.contains(c) || tried.count(c)) continue;
					tried.insert(c);
					uint32_t limit = std::min(known.next_start(c), sec_end(c));
					while (!heap.empty() && heap.top() <= c) heap.pop();
					if (!heap.empty()) limit = std::min(limit, heap.top());
					uint32_t tail = 0;
					uint32_t end = padded_end(img, c, limit, &tail);
					if (end > c) {
						Proto p{ c, end, false };
						p.tail = tail;
						protos.push_back(std::move(p));
						round_end = end;
						if (uint32_t q = after_padding(std::max(end, tail))) heap.push(q);
					} else {
						skipped.push_back({ c, decodes(c) ? "no end inside the section" : "start does not decode" });
					}
				}
				const size_t first = known.ranges.size();
				for (size_t i = before; i < protos.size(); ++i)
					known.add({ protos[i].rva, protos[i].end });
				std::inplace_merge(known.ranges.begin(), known.ranges.begin() + first, known.ranges.end(), [](auto& a, auto& b) { return a.begin < b.begin; });
			}
			for (; analysed < protos.size(); ++analysed)
				analyse(img, protos[analysed]);
			for (; scanned < protos.size(); ++scanned)
				for (auto& r : protos[scanned].refs)
					if (r.kind == disasm::RefKind::Code && r.is_call)
						work.push_back(r.target_rva);
			usable(work);
			if (work.empty() && !soft_done) {
				soft_done = true;
				work = soft;
				usable(work);
			}
			if (work.empty()) break;
		}
		std::sort(protos.begin(), protos.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
		std::sort(skipped.begin(), skipped.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
		return protos;
	}

	void count_bytes(const pe::Image& img, const std::vector<Proto>& protos, Set& out) {
		for (auto& p : protos) {
			out.covered_bytes += p.end - p.rva;
			for (auto& c : p.chunks) out.covered_bytes += c.end - c.begin;
		}
		for (auto& s : img.sections) {
			if (!(s.flags & pe::kScnExecute)) continue;
			uint32_t n = s.vsize ? std::min(s.vsize, s.raw_size) : s.raw_size;
			auto p = img.at(s.rva, n);
			if (!p) continue;
			out.exec_bytes += n;
			for (uint32_t i = 0; i < n;) {	// a run of two or more int3 or nop bytes is padding, not code
				uint32_t j = i;
				while (j < n && p[j] == p[i] && (p[i] == 0xCC || p[i] == 0x90)) ++j;
				if (j - i >= 2) { out.exec_bytes -= j - i; i = j; } else ++i;
			}
		}
	}
	}

	void discover(const pe::Image& img, Set& out) {
		out = Set{};
		std::vector<Proto> protos = img.arch == pe::Arch::X86 ? x86_protos(img, out.skipped) : pdata_protos(img);

		out.funcs.reserve(protos.size());
		for (auto& p : protos) {
			Function f{};
			f.rva = p.rva; f.end = p.end;
			f.first_chunk = static_cast<uint32_t>(out.chunks.size());
			f.chunk_count = static_cast<uint32_t>(p.chunks.size());
			f.first_ref = static_cast<uint32_t>(out.refs.size());
			f.ref_count = static_cast<uint32_t>(p.refs.size());
			f.first_token = static_cast<uint32_t>(out.tokens.size());
			f.token_count = static_cast<uint32_t>(p.tokens.size());
			f.size = p.size; f.hash = p.hash; f.from_pdata = p.pdata; f.clean = p.clean;
			uint32_t idx = static_cast<uint32_t>(out.funcs.size());
			out.spans.push_back({ p.rva, p.end, idx });
			for (auto& c : p.chunks) out.spans.push_back({ c.begin, c.end, idx });
			out.chunks.insert(out.chunks.end(), p.chunks.begin(), p.chunks.end());
			out.refs.insert(out.refs.end(), p.refs.begin(), p.refs.end());
			out.tokens.insert(out.tokens.end(), p.tokens.begin(), p.tokens.end());
			out.funcs.push_back(f);
		}
		std::sort(out.spans.begin(), out.spans.end(), [](auto& a, auto& b) { return a.begin < b.begin; });
		count_bytes(img, protos, out);
	}
}
