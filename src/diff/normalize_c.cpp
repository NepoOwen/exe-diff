#include "src/diff/normalize_c.hpp"
#include <map>
#include <regex>

namespace diff {
	std::vector<std::string> normalize_c(std::string_view pseudocode, const std::unordered_set<std::string>& keep) {
		static const std::regex auto_name(
			R"(\b(?:(sub|loc|off|unk|byte|word|dword|qword|xmmword|flt|dbl|asc|stru|algn)_[0-9A-F]{6,}|(a[A-Z][A-Za-z0-9_]*?)_[0-9]+)\b)");
		static const std::regex stack_slot(R"( \[(?:rsp|rbp)[+-][0-9A-F]+h\])");	// frame offsets on declarations shift whenever the frame grows
		std::vector<std::string> out;
		std::map<std::string, std::map<std::string, int>> seen;
		bool header = true;
		size_t at = 0;
		while (at <= pseudocode.size()) {
			size_t nl = pseudocode.find('\n', at);
			if (nl == std::string_view::npos) nl = pseudocode.size();
			std::string line(pseudocode.substr(at, nl - at));
			at = nl + 1;
			while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) line.pop_back();
			if (header && line.starts_with("//")) continue;
			header = false;
			if (line.find(" // [") != std::string::npos) {
				line = std::regex_replace(line, stack_slot, "");
				if (line.ends_with(" //")) line.resize(line.size() - 3);
			}
			std::string text;
			auto last = line.cbegin();
			for (std::sregex_iterator it(line.begin(), line.end(), auto_name), end; it != end; ++it) {
				auto& m = *it;
				text.append(last, m[0].first);
				last = m[0].second;
				if (keep.contains(m.str())) { text += m.str(); continue; }
				std::string prefix = m[1].matched ? m[1].str() : m[2].str();
				auto& ids = seen[prefix];
				auto [slot, added] = ids.try_emplace(m.str(), static_cast<int>(ids.size()) + 1);
				text += prefix + "_" + std::to_string(slot->second);
			}
			text.append(last, line.cend());
			out.push_back(std::move(text));
		}
		while (!out.empty() && out.back().empty()) out.pop_back();
		return out;
	}
}
