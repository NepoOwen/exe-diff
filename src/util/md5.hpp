#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace util {
	std::string md5_hex(const uint8_t* data, size_t size);
}
