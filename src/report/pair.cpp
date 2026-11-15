#include "src/report/pair.hpp"
#include "src/util/wide.hpp"
#include <cstdio>

namespace report {
	namespace {
		void side(std::string& o, const char* prefix, const PairSide& s) {
			o += std::string(prefix) + "_exe=" + util::narrow(s.exe_path) + '\n';
			o += std::string(prefix) + "_size=" + std::to_string(s.size) + '\n';
			o += std::string(prefix) + "_md5=" + s.md5 + '\n';
			o += std::string(prefix) + "_work=" + util::narrow(s.work_dir) + '\n';
		}
	}

	bool write_pair_txt(const wchar_t* path, const PairSide& old_side, const PairSide& new_side, std::string& err) {
		std::string o;
		side(o, "old", old_side);
		side(o, "new", new_side);
		FILE* f = _wfopen(path, L"wb");
		if (!f) { err = "cannot write " + util::narrow(path); return false; }
		bool ok = std::fwrite(o.data(), 1, o.size(), f) == o.size();
		ok &= std::fclose(f) == 0;
		if (!ok) err = "cannot write " + util::narrow(path);
		return ok;
	}
}
