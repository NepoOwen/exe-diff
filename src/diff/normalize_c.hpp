#pragma once
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace diff {
	// keep: names to leave as they are (the matched names the request gave IDA)
	std::vector<std::string> normalize_c(std::string_view pseudocode, const std::unordered_set<std::string>& keep = {});
}
