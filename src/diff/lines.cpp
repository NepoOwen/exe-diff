#include "src/diff/lines.hpp"
#include <algorithm>
#include <string_view>
#include <unordered_map>

namespace diff {
	namespace {
		constexpr int kMaxEdits = 2048;	// trace memory grows with edits squared

		void myers(const uint32_t* x, int n, const uint32_t* y, int m, uint32_t ax, uint32_t by, std::vector<Line>& out) {
			int max_d = std::min(n + m, kMaxEdits);
			int off = max_d + 1;
			std::vector<int> v(2 * max_d + 3, 0);
			std::vector<int> trace;
			int found = -1;
			for (int d = 0; d <= max_d && found < 0; ++d) {
				for (int k = -d; k <= d; k += 2) {
					int xk = (k == -d || (k != d && v[off + k - 1] < v[off + k + 1])) ? v[off + k + 1] : v[off + k - 1] + 1;
					int yk = xk - k;
					while (xk < n && yk < m && x[xk] == y[yk]) { ++xk; ++yk; }
					v[off + k] = xk;
					if (xk >= n && yk >= m) found = d;
				}
				for (int k = -d; k <= d; ++k) trace.push_back(v[off + k]);	// round d at trace[d*d + d + k]
			}
			if (found < 0) {
				for (int i = 0; i < n; ++i) out.push_back({ Op::Del, ax + i, 0 });
				for (int j = 0; j < m; ++j) out.push_back({ Op::Add, 0, by + j });
				return;
			}
			std::vector<Line> rev;
			int cx = n, cy = m;
			for (int d = found; d > 0; --d) {
				auto prev = [&](int k) { return trace[(d - 1) * (d - 1) + (d - 1) + k]; };
				int k = cx - cy;
				int pk = (k == -d || (k != d && prev(k - 1) < prev(k + 1))) ? k + 1 : k - 1;
				int px = prev(pk), py = px - pk;
				int sx = pk == k + 1 ? px : px + 1, sy = sx - k;
				while (cx > sx && cy > sy) { --cx; --cy; rev.push_back({ Op::Keep, ax + cx, by + cy }); }
				if (pk == k + 1) rev.push_back({ Op::Add, 0, by + py });
				else rev.push_back({ Op::Del, ax + px, 0 });
				cx = px; cy = py;
			}
			while (cx > 0 && cy > 0) { --cx; --cy; rev.push_back({ Op::Keep, ax + cx, by + cy }); }
			out.insert(out.end(), rev.rbegin(), rev.rend());
		}
	}

	std::vector<Line> lines(const std::vector<std::string>& a, const std::vector<std::string>& b) {
		std::unordered_map<std::string_view, uint32_t> ids;
		ids.reserve(a.size() + b.size());
		auto intern = [&](const std::vector<std::string>& s) {
			std::vector<uint32_t> v(s.size());
			for (size_t i = 0; i < s.size(); ++i)
				v[i] = ids.try_emplace(s[i], static_cast<uint32_t>(ids.size())).first->second;
			return v;
		};
		auto x = intern(a), y = intern(b);
		size_t n = x.size(), m = y.size(), pre = 0, suf = 0;
		while (pre < n && pre < m && x[pre] == y[pre]) ++pre;
		while (suf < n - pre && suf < m - pre && x[n - 1 - suf] == y[m - 1 - suf]) ++suf;
		std::vector<Line> out;
		out.reserve(std::max(n, m));
		for (uint32_t i = 0; i < pre; ++i) out.push_back({ Op::Keep, i, i });
		myers(x.data() + pre, static_cast<int>(n - pre - suf), y.data() + pre, static_cast<int>(m - pre - suf), static_cast<uint32_t>(pre), static_cast<uint32_t>(pre), out);
		for (size_t i = 0; i < suf; ++i)
			out.push_back({ Op::Keep, static_cast<uint32_t>(n - suf + i), static_cast<uint32_t>(m - suf + i) });
		return out;
	}

	std::vector<Hunk> hunks(const std::vector<Line>& lines, uint32_t context) {
		std::vector<Hunk> out;
		int64_t begin = -1, end = -1;
		int64_t last = static_cast<int64_t>(lines.size()) - 1;
		for (int64_t i = 0; i <= last; ++i) {
			if (lines[i].op == Op::Keep) continue;
			int64_t b = std::max<int64_t>(0, i - context), e = std::min<int64_t>(last, i + context);
			if (begin >= 0 && b <= end + 1) {
				end = std::max(end, e);
			} else {
				if (begin >= 0) out.push_back({ static_cast<uint32_t>(begin), static_cast<uint32_t>(end - begin + 1) });
				begin = b; end = e;
			}
		}
		if (begin >= 0) out.push_back({ static_cast<uint32_t>(begin), static_cast<uint32_t>(end - begin + 1) });
		return out;
	}
}
