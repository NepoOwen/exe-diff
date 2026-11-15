#pragma once
#include "src/func/discover.hpp"
#include "src/pe/image.hpp"
#include <string>
#include <vector>

namespace text {
	std::vector<std::string> render(const pe::Image& img, const func::Set& set, uint32_t func_idx, const std::vector<std::string>& names);
}
