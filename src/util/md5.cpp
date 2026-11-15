#include "src/util/md5.hpp"
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace util {
	std::string md5_hex(const uint8_t* data, size_t size) {
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) return {};
		uint8_t digest[16];
		static const uint8_t kEmpty = 0;
		NTSTATUS st = BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(data ? data : &kEmpty), static_cast<ULONG>(size), digest, sizeof(digest));
		BCryptCloseAlgorithmProvider(alg, 0);
		if (st != 0) return {};
		static const char kHex[] = "0123456789abcdef";
		std::string s;
		for (uint8_t b : digest) {
			s += kHex[b >> 4];
			s += kHex[b & 15];
		}
		return s;
	}
}
