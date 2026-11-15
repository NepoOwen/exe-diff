#include "src/report/notes.hpp"
#include <cstdio>

namespace report {
	namespace {
		std::string fmt(const char* f, unsigned long long a = 0, unsigned long long b = 0, unsigned long long c = 0) {
			char buf[256];
			std::snprintf(buf, sizeof(buf), f, a, b, c);
			return buf;
		}
	}

	std::vector<std::string> notes_for(const std::string& side, const std::string& file, const pe::Image& img, const func::Set& set) {
		std::vector<std::string> out;
		if (img.arch != pe::Arch::X86) return out;
		const std::string who = side + " (" + file + "): ";
		uint64_t outside = set.exec_bytes > set.covered_bytes ? set.exec_bytes - set.covered_bytes : 0;
		out.push_back(who + fmt("%llu functions found, ", set.funcs.size()) + fmt("%llu of %llu code bytes outside any function", outside, set.exec_bytes));

		std::vector<std::string> reasons;	// first-seen order
		for (auto& s : set.skipped) {
			bool seen = false;
			for (auto& r : reasons) seen |= r == s.reason;
			if (!seen) reasons.push_back(s.reason);
		}
		for (auto& reason : reasons) {
			size_t count = 0;
			std::string first;
			for (auto& s : set.skipped) {
				if (s.reason != reason) continue;
				if (count++ < 3) first += (first.empty() ? "" : ", ") + fmt("0x%llX", img.image_base + s.rva);
			}
			out.push_back(who + fmt("%llu function starts skipped: ", count) + reason + " (" + (count > 3 ? "first " : "") + first + ")");
		}
		if (img.relocs_stripped) out.push_back("no relocations in " + file + ": absolute addresses masked by range");
		return out;
	}
}
