#pragma once
#include "src/pe/image.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace test {
	// fixed RVAs: .text 0x1000, .rdata 0x2000, .reloc 0x3000, .pdata 0x4000
	struct PeSpec {
		pe::Arch arch = pe::Arch::X86;
		uint64_t image_base = 0x400000;
		bool dll = false;
		uint32_t entry_rva = 0x1000;
		std::vector<uint8_t> text = { 0xC3 };
		std::vector<uint32_t> relocs;			// fixups of the file's own pointer type (HIGHLOW for x86, DIR64 for x64)
		std::vector<uint32_t> foreign_relocs;	// fixups of the other architecture's type, which a loader must ignore
		std::vector<std::pair<std::string, uint32_t>> exports;	// name, rva
		std::vector<std::pair<std::string, std::string>> imports;	// dll, function ("#12" is an ordinal)
		bool pdata_for_x64 = true;
		uint16_t machine_override = 0;
		uint16_t magic_override = 0;
	};

	namespace pe_detail {
		inline void put16(std::vector<uint8_t>& v, size_t off, uint16_t x) { std::memcpy(v.data() + off, &x, 2); }
		inline void put32(std::vector<uint8_t>& v, size_t off, uint32_t x) { std::memcpy(v.data() + off, &x, 4); }
		inline void put64(std::vector<uint8_t>& v, size_t off, uint64_t x) { std::memcpy(v.data() + off, &x, 8); }
		inline uint32_t align(uint32_t x, uint32_t a) { return (x + a - 1) & ~(a - 1); }
	}

	inline std::vector<uint8_t> make_pe(const PeSpec& s) {
		using namespace pe_detail;
		const bool x86 = s.arch == pe::Arch::X86;
		const uint32_t ptr = x86 ? 4 : 8;

		// .rdata: import descriptors, per-dll INT+IAT arrays and hint/name entries, then the export directory
		std::vector<std::string> dlls;
		for (auto& i : s.imports)
			if (std::find(dlls.begin(), dlls.end(), i.first) == dlls.end()) dlls.push_back(i.first);
		std::vector<uint8_t> rd;
		auto grow = [&](size_t n) { if (rd.size() < n) rd.resize(n, 0); };
		uint32_t imp_rva = 0, imp_size = 0, exp_rva = 0, exp_size = 0;
		const uint32_t rd_rva = 0x2000;
		if (!dlls.empty()) {
			imp_rva = rd_rva; imp_size = static_cast<uint32_t>((dlls.size() + 1) * 20);
			grow(imp_size);
			for (size_t d = 0; d < dlls.size(); ++d) {
				std::vector<std::string> fns;
				for (auto& i : s.imports) if (i.first == dlls[d]) fns.push_back(i.second);
				uint32_t int_off = align(static_cast<uint32_t>(rd.size()), 8);
				grow(int_off + (fns.size() + 1) * ptr);
				uint32_t iat_off = static_cast<uint32_t>(rd.size());
				grow(iat_off + (fns.size() + 1) * ptr);
				for (size_t f = 0; f < fns.size(); ++f) {
					uint64_t thunk;
					if (fns[f][0] == '#') {
						thunk = std::stoul(fns[f].substr(1)) | (1ull << (x86 ? 31 : 63));
					} else {
						uint32_t hn = static_cast<uint32_t>(rd.size());
						grow(hn + 2 + fns[f].size() + 1);
						std::memcpy(rd.data() + hn + 2, fns[f].c_str(), fns[f].size() + 1);
						thunk = rd_rva + hn;
					}
					if (x86) { put32(rd, int_off + f * 4, static_cast<uint32_t>(thunk)); put32(rd, iat_off + f * 4, static_cast<uint32_t>(thunk)); }
					else { put64(rd, int_off + f * 8, thunk); put64(rd, iat_off + f * 8, thunk); }
				}
				uint32_t name_off = static_cast<uint32_t>(rd.size());
				grow(name_off + dlls[d].size() + 1);
				std::memcpy(rd.data() + name_off, dlls[d].c_str(), dlls[d].size() + 1);
				size_t desc = d * 20;
				put32(rd, desc, rd_rva + int_off);
				put32(rd, desc + 12, rd_rva + name_off);
				put32(rd, desc + 16, rd_rva + iat_off);
			}
		}
		if (!s.exports.empty()) {
			uint32_t base = align(static_cast<uint32_t>(rd.size()), 4);
			uint32_t n = static_cast<uint32_t>(s.exports.size());
			uint32_t funcs = base + 40, names = funcs + n * 4, ords = names + n * 4, strs = ords + n * 2;
			grow(strs);
			std::string dll_name = "sample.dll";
			uint32_t cur = strs;
			grow(cur + dll_name.size() + 1);
			std::memcpy(rd.data() + cur, dll_name.c_str(), dll_name.size() + 1);
			uint32_t dll_name_off = cur;
			cur += static_cast<uint32_t>(dll_name.size()) + 1;
			for (uint32_t i = 0; i < n; ++i) {
				grow(cur + s.exports[i].first.size() + 1);
				std::memcpy(rd.data() + cur, s.exports[i].first.c_str(), s.exports[i].first.size() + 1);
				put32(rd, funcs + i * 4, s.exports[i].second);
				put32(rd, names + i * 4, rd_rva + cur);
				put16(rd, ords + i * 2, static_cast<uint16_t>(i));
				cur += static_cast<uint32_t>(s.exports[i].first.size()) + 1;
			}
			exp_rva = rd_rva + base; exp_size = cur - base;
			put32(rd, base + 12, rd_rva + dll_name_off);
			put32(rd, base + 16, 1);
			put32(rd, base + 20, n);
			put32(rd, base + 24, n);
			put32(rd, base + 28, rd_rva + funcs);
			put32(rd, base + 32, rd_rva + names);
			put32(rd, base + 36, rd_rva + ords);
		}
		if (rd.empty()) rd.resize(0x10, 0);

		// .reloc: one block per 4 KB page
		std::vector<uint8_t> rl;
		auto add_relocs = [&](std::vector<uint32_t> rvas, uint16_t type) {
			std::sort(rvas.begin(), rvas.end());
			size_t i = 0;
			while (i < rvas.size()) {
				uint32_t page = rvas[i] & ~0xfffu;
				size_t start = rl.size();
				rl.resize(start + 8);
				while (i < rvas.size() && (rvas[i] & ~0xfffu) == page) {
					rl.resize(rl.size() + 2);
					put16(rl, rl.size() - 2, static_cast<uint16_t>((type << 12) | (rvas[i] & 0xfff)));
					++i;
				}
				if (rl.size() % 4) rl.resize(rl.size() + 2);
				put32(rl, start, page);
				put32(rl, start + 4, static_cast<uint32_t>(rl.size() - start));
			}
		};
		add_relocs(s.relocs, x86 ? 3 : 10);
		add_relocs(s.foreign_relocs, x86 ? 10 : 3);

		const bool has_pdata = !x86 && s.pdata_for_x64;
		std::vector<uint8_t> pd;
		if (has_pdata) {
			pd.assign(12, 0);
			put32(pd, 0, 0x1000);
			put32(pd, 4, 0x1000 + static_cast<uint32_t>(s.text.size()));
			put32(pd, 8, 0x2000);
		}

		struct Sec { const char* name; uint32_t rva; const std::vector<uint8_t>* data; uint32_t flags; };
		std::vector<Sec> secs = { { ".text", 0x1000, &s.text, 0x60000020 }, { ".rdata", 0x2000, &rd, 0x40000040 } };
		if (!rl.empty()) secs.push_back({ ".reloc", 0x3000, &rl, 0x42000040 });
		if (has_pdata) secs.push_back({ ".pdata", 0x4000, &pd, 0x40000040 });

		const uint32_t opt_size = x86 ? 224 : 240;
		const uint32_t pe_off = 0x80, hdr_end = pe_off + 24 + opt_size + static_cast<uint32_t>(secs.size()) * 40;
		const uint32_t first_raw = align(hdr_end, 0x200);
		std::vector<uint8_t> out(first_raw, 0);
		out[0] = 'M'; out[1] = 'Z';
		put32(out, 0x3c, pe_off);
		put32(out, pe_off, 0x00004550);
		uint16_t machine = s.machine_override ? s.machine_override : (x86 ? 0x014c : 0x8664);
		put16(out, pe_off + 4, machine);
		put16(out, pe_off + 6, static_cast<uint16_t>(secs.size()));
		put16(out, pe_off + 20, static_cast<uint16_t>(opt_size));
		uint16_t chars = x86 ? 0x0102 : 0x0022;
		if (s.dll) chars |= 0x2000;
		if (rl.empty()) chars |= 0x0001;
		put16(out, pe_off + 22, chars);
		const size_t opt = pe_off + 24;
		put16(out, opt, s.magic_override ? s.magic_override : (x86 ? 0x10b : 0x20b));
		put32(out, opt + 16, s.entry_rva);
		put32(out, opt + 20, 0x1000);
		uint32_t last_end = 0x1000;
		for (auto& c : secs) last_end = std::max(last_end, c.rva + align(static_cast<uint32_t>(std::max<size_t>(c.data->size(), 1)), 0x1000));
		size_t dirs;
		if (x86) {
			put32(out, opt + 28, static_cast<uint32_t>(s.image_base));
			put32(out, opt + 92, 16);
			dirs = opt + 96;
		} else {
			put64(out, opt + 24, s.image_base);
			put32(out, opt + 108, 16);
			dirs = opt + 112;
		}
		put32(out, opt + 32, 0x1000);
		put32(out, opt + 36, 0x200);
		put32(out, opt + 56, last_end);
		put32(out, opt + 60, first_raw);
		put16(out, opt + 68, 3);
		put32(out, dirs + 0 * 8, exp_rva); put32(out, dirs + 0 * 8 + 4, exp_size);
		put32(out, dirs + 1 * 8, imp_rva); put32(out, dirs + 1 * 8 + 4, imp_size);
		if (has_pdata) { put32(out, dirs + 3 * 8, 0x4000); put32(out, dirs + 3 * 8 + 4, 12); }
		if (!rl.empty()) { put32(out, dirs + 5 * 8, 0x3000); put32(out, dirs + 5 * 8 + 4, static_cast<uint32_t>(rl.size())); }

		size_t sec_hdr = opt + opt_size;
		uint32_t raw = first_raw;
		for (size_t i = 0; i < secs.size(); ++i) {
			auto& c = secs[i];
			uint32_t size = static_cast<uint32_t>(c.data->size());
			uint32_t raw_size = align(std::max<uint32_t>(size, 1), 0x200);
			size_t o = sec_hdr + i * 40;
			std::memcpy(out.data() + o, c.name, std::strlen(c.name));
			put32(out, o + 8, size);
			put32(out, o + 12, c.rva);
			put32(out, o + 16, raw_size);
			put32(out, o + 20, raw);
			put32(out, o + 36, c.flags);
			out.resize(raw + raw_size, 0);
			std::memcpy(out.data() + raw, c.data->data(), size);
			raw += raw_size;
		}
		return out;
	}
}
