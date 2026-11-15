#pragma once
#include <cstdint>
#include <cstring>
#include <string_view>

namespace util {
	inline uint64_t mix(uint64_t h, uint64_t v) {
		h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
		h *= 0xff51afd7ed558ccdull;
		return h ^ (h >> 32);
	}

	inline uint64_t hash_bytes(const uint8_t* p, size_t n, uint64_t seed = 0x243f6a8885a308d3ull) {
		uint64_t h = seed ^ (n * 0x100000001b3ull);
		size_t i = 0;
		for (; i + 8 <= n; i += 8) {
			uint64_t v;
			std::memcpy(&v, p + i, 8);
			h = mix(h, v);
		}
		uint64_t tail = 0;
		for (size_t k = 0; i < n; ++i, ++k)
			tail |= static_cast<uint64_t>(p[i]) << (8 * k);
		return mix(h, tail ^ 0xa5);
	}

	inline uint64_t hash_str(std::string_view s, uint64_t seed) {
		return hash_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size(), seed);
	}
}
