#include "src/match/match.hpp"
#include "src/util/hash.hpp"
#include <algorithm>
#include <cstdio>
#include <unordered_map>

namespace match {
	namespace {
		constexpr uint32_t kNone = UINT32_MAX;
		constexpr size_t kGlobalLimit = 5000;
		constexpr size_t kGapPairLimit = 250000;
		constexpr float kGapOne = 0.2f;
		constexpr float kGapMany = 0.5f;
		constexpr float kGlobal = 0.6f;

		std::vector<uint32_t> sorted_tokens(const func::Set& s, const func::Function& f) {
			std::vector<uint32_t> t(s.tokens.begin() + f.first_token, s.tokens.begin() + f.first_token + f.token_count);
			std::sort(t.begin(), t.end());
			return t;
		}

		float sim_sorted(const std::vector<uint32_t>& x, const std::vector<uint32_t>& y) {
			if (x.empty() && y.empty()) return 1.0f;
			size_t i = 0, j = 0, common = 0;
			while (i < x.size() && j < y.size()) {
				if (x[i] < y[j]) ++i;
				else if (y[j] < x[i]) ++j;
				else { ++common; ++i; ++j; }
			}
			return static_cast<float>(2.0 * common / static_cast<double>(x.size() + y.size()));
		}

		struct State {
			const func::Set& a;
			const func::Set& b;
			std::vector<uint32_t> a2b, b2a;
			std::vector<Status> status;
			std::vector<float> sim;
			std::vector<uint8_t> weak;
			std::vector<Method> method;

			State(const func::Set& a_, const func::Set& b_) : a(a_), b(b_),
				a2b(a_.funcs.size(), kNone), b2a(b_.funcs.size(), kNone), status(a_.funcs.size(), Status::Same), sim(a_.funcs.size(), 1.0f), weak(a_.funcs.size(), 0), method(a_.funcs.size(), Method::Unique) {}

			void link(uint32_t i, uint32_t j, Status s, float v, Method m, bool by_order = false) {
				a2b[i] = j; b2a[j] = i; status[i] = s; sim[i] = v; method[i] = m; weak[i] = by_order;
			}

			void repair() {
				for (uint32_t i = 0; i < a.funcs.size(); ++i) {
					uint32_t j = a2b[i];
					if (j == kNone || a.funcs[i].ref_count != b.funcs[j].ref_count) continue;
					auto& fa = a.funcs[i];
					auto& fb = b.funcs[j];
					for (uint32_t k = 0; k < fa.ref_count; ++k) {
						auto& ra = a.refs[fa.first_ref + k];
						auto& rb = b.refs[fb.first_ref + k];
						if (ra.kind != disasm::RefKind::Code || rb.kind != disasm::RefKind::Code) continue;
						auto la = a.locate(ra.target_rva), lb = b.locate(rb.target_rva);
						if (la.func < 0 || lb.func < 0 || la.part != lb.part || la.off != lb.off) continue;
						uint32_t ta = la.func, tb = lb.func, x = a2b[ta], y = b2a[tb];
						if (x == tb || !weak[ta] || a.funcs[ta].hash != b.funcs[tb].hash) continue;
						if (y != kNone && !weak[y]) continue;
						if (x != kNone) b2a[x] = kNone;
						if (y != kNone) a2b[y] = kNone;
						link(ta, tb, Status::Same, 1.0f, Method::Refined);
						if (y != kNone && x != kNone) link(y, x, Status::Same, 1.0f, Method::Group, true);
					}
				}
			}

			// pairs in old order whose new indices form the longest increasing run; moved functions don't cut gaps
			std::vector<std::pair<uint32_t, uint32_t>> anchors() const {
				std::vector<std::pair<uint32_t, uint32_t>> v;
				for (uint32_t i = 0; i < a2b.size(); ++i)
					if (a2b[i] != kNone) v.push_back({ i, a2b[i] });
				std::vector<uint32_t> tails, prev(v.size(), kNone);
				for (uint32_t k = 0; k < v.size(); ++k) {
					auto at = std::lower_bound(tails.begin(), tails.end(), v[k].second, [&](uint32_t t, uint32_t j) { return v[t].second < j; });
					if (at != tails.begin()) prev[k] = *(at - 1);
					if (at == tails.end()) tails.push_back(k);
					else *at = k;
				}
				std::vector<std::pair<uint32_t, uint32_t>> run;
				for (uint32_t k = tails.empty() ? kNone : tails.back(); k != kNone; k = prev[k]) run.push_back(v[k]);
				std::reverse(run.begin(), run.end());
				return run;
			}

			template <class F>
			void for_each_gap(F&& fn) const {
				uint32_t pa = 0, pb = 0;
				auto emit = [&](uint32_t ea, uint32_t eb) {
					std::vector<uint32_t> ga, gb;
					for (uint32_t i = pa; i < ea; ++i) if (a2b[i] == kNone) ga.push_back(i);
					for (uint32_t j = pb; j < eb; ++j) if (b2a[j] == kNone) gb.push_back(j);
					if (!ga.empty() && !gb.empty()) fn(ga, gb);
				};
				for (auto& [i, j] : anchors()) {
					emit(i, j);
					pa = i + 1;
					pb = j + 1;
				}
				emit(static_cast<uint32_t>(a.funcs.size()), static_cast<uint32_t>(b.funcs.size()));
			}

			void greedy(const std::vector<uint32_t>& ga, const std::vector<uint32_t>& gb, float min_sim) {
				std::vector<std::vector<uint32_t>> ta(ga.size()), tb(gb.size());
				for (size_t i = 0; i < ga.size(); ++i) ta[i] = sorted_tokens(a, a.funcs[ga[i]]);
				for (size_t j = 0; j < gb.size(); ++j) tb[j] = sorted_tokens(b, b.funcs[gb[j]]);
				struct Cand { float s; uint32_t i, j; };
				std::vector<Cand> cands;
				for (size_t i = 0; i < ga.size(); ++i) {
					for (size_t j = 0; j < gb.size(); ++j) {
						size_t x = ta[i].size(), y = tb[j].size();
						if (2.0 * std::min(x, y) < min_sim * (x + y)) continue;
						float s = sim_sorted(ta[i], tb[j]);
						if (s >= min_sim) cands.push_back({ s, ga[i], gb[j] });
					}
				}
				std::stable_sort(cands.begin(), cands.end(), [](auto& x, auto& y) { return x.s > y.s; });
				for (auto& c : cands)
					if (a2b[c.i] == kNone && b2a[c.j] == kNone)
						link(c.i, c.j, Status::Changed, c.s, Method::Similar);
			}

			bool refs_agree(uint32_t i, uint32_t j) const {
				auto& fa = a.funcs[i];
				auto& fb = b.funcs[j];
				if (fa.ref_count != fb.ref_count) return false;
				for (uint32_t k = 0; k < fa.ref_count; ++k) {
					auto& ra = a.refs[fa.first_ref + k];
					auto& rb = b.refs[fb.first_ref + k];
					if (ra.kind != rb.kind) return false;
					if (ra.kind != disasm::RefKind::Code) continue;
					auto la = a.locate(ra.target_rva), lb = b.locate(rb.target_rva);
					if (la.func < 0 && lb.func < 0) continue;
					if (la.func < 0 || lb.func < 0) return false;
					if (la.part != lb.part || la.off != lb.off) return false;
					if (a2b[la.func] != static_cast<uint32_t>(lb.func) && a.funcs[la.func].hash != b.funcs[lb.func].hash) return false;
				}
				return true;
			}

			uint64_t ref_key(const func::Set& s, uint32_t idx, const std::vector<uint32_t>& partner, bool old_side) const {
				auto& f = s.funcs[idx];
				uint64_t k = f.hash;
				for (uint32_t r = 0; r < f.ref_count; ++r) {
					auto& ref = s.refs[f.first_ref + r];
					if (ref.kind != disasm::RefKind::Code) continue;
					auto l = s.locate(ref.target_rva);
					uint64_t id = 0;
					if (l.func >= 0) {
						uint32_t p = partner[l.func];
						if (p != kNone) id = old_side ? p : static_cast<uint32_t>(l.func);
						else id = s.funcs[l.func].hash | 1ull << 63;
						id = util::mix(id, (static_cast<uint64_t>(l.part) << 32) | l.off);
					}
					k = util::mix(k, id);
				}
				return k;
			}

			bool pair_by_refs() {
				std::unordered_map<uint64_t, std::pair<uint32_t, uint32_t>> groups;
				auto add = [&](uint64_t key, bool old_side, uint32_t idx) {
					auto [it, fresh] = groups.try_emplace(key, kNone, kNone);
					auto& slot = old_side ? it->second.first : it->second.second;
					slot = slot == kNone ? idx : kNone - 1;
				};
				for (uint32_t i = 0; i < a.funcs.size(); ++i)
					if (a2b[i] == kNone) add(ref_key(a, i, a2b, true), true, i);
				for (uint32_t j = 0; j < b.funcs.size(); ++j)
					if (b2a[j] == kNone) add(ref_key(b, j, b2a, false), false, j);
				bool progress = false;
				for (auto& [k, g] : groups) {
					if (g.first < kNone - 1 && g.second < kNone - 1) {
						link(g.first, g.second, Status::Same, 1.0f, Method::Refined);
						progress = true;
					}
				}
				return progress;
			}

			bool pair_by_callers() {
				bool progress = false;
				for (uint32_t i = 0; i < a.funcs.size(); ++i) {
					uint32_t j = a2b[i];
					if (j == kNone) continue;
					auto& fa = a.funcs[i];
					auto& fb = b.funcs[j];
					if (fa.ref_count != fb.ref_count) continue;
					for (uint32_t k = 0; k < fa.ref_count; ++k) {
						auto& ra = a.refs[fa.first_ref + k];
						auto& rb = b.refs[fb.first_ref + k];
						if (ra.kind != disasm::RefKind::Code || rb.kind != disasm::RefKind::Code) continue;
						auto la = a.locate(ra.target_rva), lb = b.locate(rb.target_rva);
						if (la.func < 0 || lb.func < 0 || la.part != lb.part || la.off != lb.off) continue;
						if (a2b[la.func] != kNone || b2a[lb.func] != kNone) continue;
						if (a.funcs[la.func].hash != b.funcs[lb.func].hash) continue;
						link(la.func, lb.func, Status::Same, 1.0f, Method::Propagated);
						progress = true;
					}
				}
				return progress;
			}
		};

		void pair_by_hash(State& st, const std::vector<uint32_t>& ga, const std::vector<uint32_t>& gb, bool unique_only) {
			Method m = unique_only ? Method::Unique : Method::Group;
			std::unordered_map<uint64_t, std::pair<std::vector<uint32_t>, std::vector<uint32_t>>> groups;
			groups.reserve(ga.size() + gb.size());
			for (uint32_t i : ga) groups[st.a.funcs[i].hash].first.push_back(i);
			for (uint32_t j : gb) groups[st.b.funcs[j].hash].second.push_back(j);
			for (auto& [h, g] : groups) {
				auto& [xa, xb] = g;
				if (xa.empty() || xb.empty()) continue;
				if (unique_only && (xa.size() != 1 || xb.size() != 1)) continue;
				std::sort(xa.begin(), xa.end());
				std::sort(xb.begin(), xb.end());
				size_t n = std::min(xa.size(), xb.size());
				for (size_t k = 0; k < n; ++k)
					st.link(xa[k], xb[k], Status::Same, 1.0f, m, xa.size() > 1 || xb.size() > 1);
			}
		}
	}

	float similarity(const func::Set& a, const func::Function& fa, const func::Set& b, const func::Function& fb) {
		return sim_sorted(sorted_tokens(a, fa), sorted_tokens(b, fb));
	}

	void run(const func::Set& a, const func::Set& b, Result& out) {
		out = Result{};
		State st(a, b);
		std::vector<uint32_t> all_a(a.funcs.size()), all_b(b.funcs.size());
		for (uint32_t i = 0; i < all_a.size(); ++i) all_a[i] = i;
		for (uint32_t j = 0; j < all_b.size(); ++j) all_b[j] = j;

		pair_by_hash(st, all_a, all_b, true);
		for (int round = 0; round < 16; ++round) {
			bool up = st.pair_by_refs();
			bool down = st.pair_by_callers();
			if (!up && !down) break;
		}
		st.for_each_gap([&](const std::vector<uint32_t>& ga, const std::vector<uint32_t>& gb) {
			pair_by_hash(st, ga, gb, false);
		});
		{
			std::vector<uint32_t> ra, rb;
			for (uint32_t i = 0; i < all_a.size(); ++i) if (st.a2b[i] == kNone) ra.push_back(i);
			for (uint32_t j = 0; j < all_b.size(); ++j) if (st.b2a[j] == kNone) rb.push_back(j);
			pair_by_hash(st, ra, rb, false);
		}
		st.repair();
		st.repair();

		st.for_each_gap([&](const std::vector<uint32_t>& ga, const std::vector<uint32_t>& gb) {
			if (ga.size() == 1 && gb.size() == 1) {
				float s = similarity(a, a.funcs[ga[0]], b, b.funcs[gb[0]]);
				if (s >= kGapOne) st.link(ga[0], gb[0], Status::Changed, s, Method::Similar);
			} else if (ga.size() * gb.size() <= kGapPairLimit) {
				st.greedy(ga, gb, kGapMany);
			}
		});

		std::vector<uint32_t> ra, rb;
		for (uint32_t i = 0; i < all_a.size(); ++i) if (st.a2b[i] == kNone) ra.push_back(i);
		for (uint32_t j = 0; j < all_b.size(); ++j) if (st.b2a[j] == kNone) rb.push_back(j);
		if (!ra.empty() && !rb.empty()) {
			if (ra.size() <= kGlobalLimit && rb.size() <= kGlobalLimit)
				st.greedy(ra, rb, kGlobal);
			else
				out.too_different = true;
		}

		for (uint32_t i = 0; i < all_a.size(); ++i)
			if (st.a2b[i] != kNone && st.status[i] == Status::Same && !st.refs_agree(i, st.a2b[i]))
				st.status[i] = Status::RefChanged;

		for (uint32_t i = 0; i < all_a.size(); ++i) {
			if (st.a2b[i] != kNone) out.pairs.push_back({ i, st.a2b[i], st.status[i], st.sim[i], st.method[i] });
			else out.removed.push_back(i);
		}
		for (uint32_t j = 0; j < all_b.size(); ++j)
			if (st.b2a[j] == kNone) out.added.push_back(j);
	}

	void name(const pe::Image& ia, const func::Set& a, const pe::Image& ib, const func::Set& b, const Result& r, Names& out) {
		auto fmt = [](const char* prefix, uint64_t va) {
			char buf[40];
			std::snprintf(buf, sizeof(buf), "%s_%llX", prefix, static_cast<unsigned long long>(va));
			return std::string(buf);
		};
		out.old_names.assign(a.funcs.size(), {});
		out.new_names.assign(b.funcs.size(), {});
		for (size_t i = 0; i < a.funcs.size(); ++i)
			out.old_names[i] = fmt("sub", ia.image_base + a.funcs[i].rva);
		for (auto& p : r.pairs)
			out.new_names[p.new_idx] = out.old_names[p.old_idx];
		for (uint32_t j : r.added)
			out.new_names[j] = fmt("new", ib.image_base + b.funcs[j].rva);
	}
}
