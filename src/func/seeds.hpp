#pragma once
#include "src/pe/image.hpp"
#include <cstdint>
#include <vector>

namespace func {
	// entry point and exports go to out, relocated code pointers stored in data to data_ptrs (to out when null); sorted, unique, executable
	void seeds_x86(const pe::Image& img, std::vector<uint32_t>& out, std::vector<uint32_t>* data_ptrs = nullptr);

	// end of the function at start, or start when there is none; data_end gets the end of the jump table bytes it owns (0 if none)
	uint32_t padded_end(const pe::Image& img, uint32_t start, uint32_t limit, uint32_t* data_end = nullptr);
}
