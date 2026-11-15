#include "src/sig/scan.hpp"
#include <algorithm>
#include <cstring>

namespace sig {
	namespace {
		int nibble(char c) {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			return -1;
		}
	}

	bool parse(std::string_view text, Pattern& out) {
		out = {};
		bool literal = false;
		size_t i = 0;
		while (i < text.size()) {
			if (text[i] == ' ') { ++i; continue; }
			size_t j = text.find(' ', i);
			auto tok = text.substr(i, j == std::string_view::npos ? std::string_view::npos : j - i);
			i += tok.size();
			if (tok == "?" || tok == "??") {
				out.bytes.push_back(0);
				out.wild.push_back(true);
				continue;
			}
			if (tok.size() != 2) return false;
			int hi = nibble(tok[0]), lo = nibble(tok[1]);
			if (hi < 0 || lo < 0) return false;
			out.bytes.push_back(static_cast<uint8_t>(hi << 4 | lo));
			out.wild.push_back(false);
			literal = true;
		}
		return literal;
	}

	std::vector<uint32_t> find(const pe::Image& img, const Pattern& p, size_t limit) {
		std::vector<uint32_t> hits;
		size_t best = 0, best_len = 0;
		for (size_t i = 0, run = 0; i < p.bytes.size(); ++i) {
			run = p.wild[i] ? 0 : run + 1;
			if (run > best_len) { best_len = run; best = i + 1 - run; }
		}
		if (!best_len) return hits;
		const uint8_t* anchor = p.bytes.data() + best;
		for (auto& s : img.sections) {
			uint32_t size = std::min(s.vsize ? s.vsize : s.raw_size, s.raw_size);
			const uint8_t* data = img.at(s.rva, size);
			if (!data || size < p.bytes.size()) continue;
			const uint8_t* first = data + best;
			const uint8_t* last = data + size - (p.bytes.size() - best);
			for (auto at = first; at < last + 1;) {
				at = std::search(at, last + best_len, anchor, anchor + best_len);
				if (at > last) break;
				const uint8_t* start = at - best;
				bool ok = true;
				for (size_t k = 0; ok && k < p.bytes.size(); ++k) ok = p.wild[k] || start[k] == p.bytes[k];
				if (ok) {
					hits.push_back(s.rva + static_cast<uint32_t>(start - data));
					if (hits.size() >= limit) return hits;
				}
				++at;
			}
		}
		return hits;
	}
}
