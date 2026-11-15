#include "src/pe/image.hpp"
#include "src/util/hash.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace pe {
	namespace {
		struct Reader {
			const std::vector<uint8_t>& f;
			bool ok(uint64_t off, uint64_t n) const { return off <= f.size() && n <= f.size() - off; }
			uint16_t u16(uint64_t off) const { uint16_t v; std::memcpy(&v, f.data() + off, 2); return v; }
			uint32_t u32(uint64_t off) const { uint32_t v; std::memcpy(&v, f.data() + off, 4); return v; }
			uint64_t u64(uint64_t off) const { uint64_t v; std::memcpy(&v, f.data() + off, 8); return v; }
		};

		bool read_file(const wchar_t* path, std::vector<uint8_t>& out, std::string& err) {
			std::ifstream f(path, std::ios::binary | std::ios::ate);
			if (!f) { err = "cannot open file"; return false; }
			auto size = static_cast<size_t>(f.tellg());
			f.seekg(0);
			out.resize(size);
			if (size && !f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size))) {
				err = "cannot read file";
				return false;
			}
			return true;
		}

		uint32_t file_limit(const Section& s) {
			return s.vsize ? std::min(s.vsize, s.raw_size) : s.raw_size;
		}

		bool rva_off(const Image& img, uint32_t rva, uint32_t size, uint64_t& off) {
			auto p = img.at(rva, size);
			if (!p) return false;
			off = static_cast<uint64_t>(p - img.file.data());
			return true;
		}

		bool read_cstr(const Image& img, uint32_t rva, size_t max, std::string& out) {
			out.clear();
			for (size_t i = 0; i < max; ++i) {
				auto p = img.at(rva + static_cast<uint32_t>(i), 1);
				if (!p) return false;
				if (!*p) return true;
				out.push_back(static_cast<char>(*p));
			}
			return false;
		}

		bool parse_pdata(Image& img, uint32_t rva, uint32_t size, std::string& err) {
			uint64_t off;
			if (!size || !rva_off(img, rva, size, off)) {
				err = "no usable .pdata (exception directory)";
				return false;
			}
			Reader r{ img.file };
			uint32_t n = size / 12;
			img.pdata.reserve(n);
			for (uint32_t i = 0; i < n; ++i) {
				RuntimeFunction rf{ r.u32(off + i * 12), r.u32(off + i * 12 + 4), r.u32(off + i * 12 + 8) };
				if (rf.begin && rf.end > rf.begin)
					img.pdata.push_back(rf);
			}
			std::sort(img.pdata.begin(), img.pdata.end(), [](auto& a, auto& b) { return a.begin < b.begin; });
			return true;
		}

		void parse_relocs(Image& img, uint32_t rva, uint32_t size) {
			const uint16_t type = img.arch == Arch::X86 ? 3 : 10;	// HIGHLOW / DIR64
			uint64_t off;
			if (!size || !rva_off(img, rva, size, off)) return;
			Reader r{ img.file };
			uint64_t end = off + size;
			while (off + 8 <= end) {
				uint32_t page = r.u32(off), block = r.u32(off + 4);
				if (block < 8 || off + block > end) break;
				for (uint64_t e = off + 8; e + 2 <= off + block; e += 2) {
					uint16_t v = r.u16(e);
					if ((v >> 12) == type)
						img.relocs.push_back(page + (v & 0xfff));
				}
				off += block;
			}
			std::sort(img.relocs.begin(), img.relocs.end());
		}

		void parse_imports(Image& img, uint32_t rva, uint32_t size) {
			uint64_t off;
			if (!size || !rva_off(img, rva, 20, off)) return;
			Reader r{ img.file };
			const uint32_t ptr = img.ptr_size();
			for (uint32_t d = rva;; d += 20) {
				if (!rva_off(img, d, 20, off)) break;
				uint32_t oft = r.u32(off), name_rva = r.u32(off + 12), ft = r.u32(off + 16);
				if (!oft && !name_rva && !ft) break;
				std::string dll;
				if (!read_cstr(img, name_rva, 256, dll)) continue;
				uint32_t thunks = oft ? oft : ft;
				for (uint32_t i = 0;; ++i) {
					uint64_t toff;
					if (!rva_off(img, thunks + i * ptr, ptr, toff)) break;
					uint64_t t = ptr == 4 ? r.u32(toff) : r.u64(toff);
					if (!t) break;
					std::string name;
					if (t >> (ptr * 8 - 1))
						name = dll + "!#" + std::to_string(t & 0xffff);
					else if (read_cstr(img, static_cast<uint32_t>(t) + 2, 512, name))
						name = dll + "!" + name;
					else
						name = dll + "!?";
					img.imports.push_back({ ft + i * ptr, std::move(name) });
				}
			}
			std::sort(img.imports.begin(), img.imports.end(), [](auto& a, auto& b) { return a.iat_rva < b.iat_rva; });
		}

		void parse_exports(Image& img, uint32_t rva, uint32_t size) {
			uint64_t off;
			if (!size || !rva_off(img, rva, 40, off)) return;
			Reader r{ img.file };
			uint32_t count = r.u32(off + 24), funcs = r.u32(off + 28), names = r.u32(off + 32), ords = r.u32(off + 36);
			for (uint32_t i = 0; i < count; ++i) {
				uint64_t noff, ooff, foff;
				if (!rva_off(img, names + i * 4, 4, noff) || !rva_off(img, ords + i * 2, 2, ooff)) break;
				std::string name;
				if (!read_cstr(img, r.u32(noff), 512, name)) continue;
				uint32_t ord = r.u16(ooff);
				if (!rva_off(img, funcs + ord * 4, 4, foff)) continue;
				uint32_t target = r.u32(foff);
				if (target >= rva && target - rva < size) continue;	// forwarder: the "address" is a string inside the export directory
				img.exports.push_back({ target, std::move(name) });
			}
			std::sort(img.exports.begin(), img.exports.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
		}
	}

	const char* arch_name(Arch a) {
		return a == Arch::X86 ? "x86" : "x64";
	}

	const uint8_t* Image::at(uint32_t rva, uint32_t size) const {
		for (auto& s : sections) {
			if (rva < s.rva) continue;
			uint64_t rel = rva - s.rva;
			if (rel + size > file_limit(s)) continue;
			uint64_t off = s.raw_off + rel;
			if (off + size > file.size()) return nullptr;
			return file.data() + off;
		}
		return nullptr;
	}

	const Section* Image::section_of(uint32_t rva) const {
		for (auto& s : sections)
			if (rva >= s.rva && rva - s.rva < std::max(s.vsize, s.raw_size))
				return &s;
		return nullptr;
	}

	const Section* Image::text() const {
		for (auto& s : sections)
			if (s.flags & kScnExecute)
				return &s;
		return nullptr;
	}

	bool Image::is_exec(uint32_t rva) const {
		auto s = section_of(rva);
		return s && (s->flags & kScnExecute);
	}

	bool Image::is_chained(const RuntimeFunction& f) const {
		auto p = at(f.unwind, 4);
		return p && ((p[0] >> 3) & 4);
	}

	uint32_t Image::chain_parent(const RuntimeFunction& f) const {
		auto p = at(f.unwind, 4);
		if (!p) return 0;
		uint32_t codes = (p[2] + 1u) & ~1u;
		auto parent = at(f.unwind + 4 + codes * 2, 12);
		if (!parent) return 0;
		uint32_t begin;
		std::memcpy(&begin, parent, 4);
		return begin;
	}

	bool Image::has_reloc(uint32_t rva, uint32_t size) const {
		auto it = std::lower_bound(relocs.begin(), relocs.end(), rva);
		return it != relocs.end() && *it - rva < size;
	}

	const Import* Image::import_at(uint32_t iat_rva) const {
		auto it = std::lower_bound(imports.begin(), imports.end(), iat_rva, [](const Import& a, uint32_t v) { return a.iat_rva < v; });
		return it != imports.end() && it->iat_rva == iat_rva ? &*it : nullptr;
	}

	bool Image::string_at(uint32_t rva, std::string& out) const {
		auto s = section_of(rva);
		if (!s || (s->flags & kScnExecute)) return false;
		out.clear();
		for (uint32_t i = 0; i <= 256; ++i) {
			auto p = at(rva + i, 1);
			if (!p) return false;
			if (!*p) return out.size() >= 4;
			if (*p < 0x20 || *p > 0x7e) {
				if (*p != '\t' && *p != '\n' && *p != '\r') return false;
			}
			out.push_back(static_cast<char>(*p));
		}
		return false;
	}

	bool load(const wchar_t* path, Image& img, std::string& err) {
		img = Image{};
		if (!read_file(path, img.file, err)) return false;
		Reader r{ img.file };
		if (!r.ok(0, 0x40) || img.file[0] != 'M' || img.file[1] != 'Z') { err = "not a PE file (no MZ header)"; return false; }
		uint32_t pe_off = r.u32(0x3c);
		if (!r.ok(pe_off, 24) || r.u32(pe_off) != 0x00004550) { err = "not a PE file (PE header out of range or missing)"; return false; }
		uint16_t machine = r.u16(pe_off + 4);
		if (machine != 0x8664 && machine != 0x014c) {
			char msg[64];
			std::snprintf(msg, sizeof msg, "not an x86 or x64 PE (machine 0x%04X)", machine);
			err = msg;
			return false;
		}
		const bool x86 = machine == 0x014c;
		img.arch = x86 ? Arch::X86 : Arch::X64;
		uint16_t nsec = r.u16(pe_off + 6), opt_size = r.u16(pe_off + 20), characteristics = r.u16(pe_off + 22);
		uint64_t opt = pe_off + 24;
		const uint32_t fixed_size = x86 ? 96 : 112;	// optional header up to the data directories
		if (opt_size < fixed_size || !r.ok(opt, opt_size)) { err = "optional header is truncated"; return false; }
		if (r.u16(opt) != (x86 ? 0x10b : 0x20b)) { err = "PE header is inconsistent: machine and optional-header magic disagree"; return false; }
		img.image_base = x86 ? r.u32(opt + 28) : r.u64(opt + 24);
		img.size_of_image = r.u32(opt + 56);
		img.entry_rva = r.u32(opt + 16);
		uint32_t ndirs = std::min<uint32_t>(r.u32(opt + fixed_size - 4), (opt_size - fixed_size) / 8);
		auto dir = [&](uint32_t i, uint32_t& rva, uint32_t& size) {
			rva = size = 0;
			if (i < ndirs) { rva = r.u32(opt + fixed_size + i * 8); size = r.u32(opt + fixed_size + 4 + i * 8); }
		};
		uint64_t sec = opt + opt_size;
		if (!r.ok(sec, static_cast<uint64_t>(nsec) * 40)) { err = "section table out of range"; return false; }
		for (uint16_t i = 0; i < nsec; ++i) {
			uint64_t o = sec + i * 40ull;
			Section s{};
			std::memcpy(s.name, img.file.data() + o, 8);
			s.vsize = r.u32(o + 8); s.rva = r.u32(o + 12); s.raw_size = r.u32(o + 16); s.raw_off = r.u32(o + 20); s.flags = r.u32(o + 36);
			if (s.raw_size && !r.ok(s.raw_off, 0)) { err = std::string("section ") + s.name + " starts past the end of the file"; return false; }
			if (s.raw_size && !r.ok(s.raw_off, s.raw_size)) s.raw_size = static_cast<uint32_t>(img.file.size() - s.raw_off);
			img.sections.push_back(s);
		}
		if (!img.text()) { err = "no executable section"; return false; }
		uint32_t rva, size;
		if (!x86) {
			dir(3, rva, size);
			if (!parse_pdata(img, rva, size, err)) return false;
		}
		dir(5, rva, size);
		parse_relocs(img, rva, size);
		img.relocs_stripped = (characteristics & 1) || img.relocs.empty();
		dir(1, rva, size);
		parse_imports(img, rva, size);
		dir(0, rva, size);
		parse_exports(img, rva, size);
		img.content_hash = util::hash_bytes(img.file.data(), img.file.size());
		return true;
	}
}
