#pragma once
#include "src/func/discover.hpp"
#include "src/pe/image.hpp"
#include <string>
#include <vector>

namespace report {
	// report lines for what an x86 comparison could not see (empty for x64)
	std::vector<std::string> notes_for(const std::string& side, const std::string& file, const pe::Image& img, const func::Set& set);
}
