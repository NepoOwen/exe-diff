#include "tests/test.hpp"
#include "src/match/match.hpp"
#include <algorithm>

struct FSpec {
	uint32_t rva;
	uint64_t hash;
	std::vector<uint32_t> tokens;
	std::vector<disasm::Ref> refs;
};

static func::Set set_of(const std::vector<FSpec>& specs) {
	func::Set s;
	for (auto& f : specs) {
		func::Function fn{};
		fn.rva = f.rva;
		fn.end = f.rva + 0x10;
		fn.size = 0x10;
		fn.hash = f.hash;
		fn.first_ref = static_cast<uint32_t>(s.refs.size());
		fn.ref_count = static_cast<uint32_t>(f.refs.size());
		fn.first_token = static_cast<uint32_t>(s.tokens.size());
		fn.token_count = static_cast<uint32_t>(f.tokens.size());
		fn.from_pdata = true;
		fn.clean = true;
		s.refs.insert(s.refs.end(), f.refs.begin(), f.refs.end());
		s.tokens.insert(s.tokens.end(), f.tokens.begin(), f.tokens.end());
		s.spans.push_back({ fn.rva, fn.end, static_cast<uint32_t>(s.funcs.size()) });
		s.funcs.push_back(fn);
	}
	return s;
}

static const match::Pair* pair_of(const match::Result& r, uint32_t old_idx) {
	for (auto& p : r.pairs)
		if (p.old_idx == old_idx) return &p;
	return nullptr;
}

static disasm::Ref call_to(uint32_t target) {
	return { 0, target, disasm::RefKind::Code, true, false };
}

TEST(match_unique_hashes) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 2, { 2 } }, { 0x1200, 3, { 3 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 2, { 2 } }, { 0x2200, 3, { 3 } } });
	match::Result r;
	match::run(a, b, r);
	CHECK(r.pairs.size() == 3);
	for (uint32_t i = 0; i < 3; ++i) {
		auto p = pair_of(r, i);
		CHECK(p && p->new_idx == i && p->status == match::Status::Same && p->similarity == 1.0f);
	}
	CHECK(r.added.empty() && r.removed.empty());
}

TEST(match_duplicate_hashes_in_order) {
	auto a = set_of({ { 0x1000, 7, { 7 } }, { 0x1100, 7, { 7 } }, { 0x1200, 7, { 7 } } });
	auto b = set_of({ { 0x2000, 7, { 7 } }, { 0x2100, 7, { 7 } }, { 0x2200, 7, { 7 } } });
	match::Result r;
	match::run(a, b, r);
	CHECK(r.pairs.size() == 3);
	for (uint32_t i = 0; i < 3; ++i) {
		auto p = pair_of(r, i);
		CHECK(p && p->new_idx == i);
	}
}

TEST(match_duplicates_paired_inside_anchor_gaps) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 7, { 7 } }, { 0x1200, 2, { 2 } }, { 0x1300, 7, { 7 } } });
	auto b = set_of({ { 0x2000, 7, { 7 } }, { 0x2100, 1, { 1 } }, { 0x2200, 7, { 7 } }, { 0x2300, 2, { 2 } }, { 0x2400, 7, { 7 } } });
	match::Result r;
	match::run(a, b, r);
	auto p1 = pair_of(r, 1), p3 = pair_of(r, 3);
	CHECK(p1 && p1->new_idx == 2);
	CHECK(p3 && p3->new_idx == 4);
	CHECK(r.added == std::vector<uint32_t>({ 0 }));
}

TEST(match_changed_in_gap) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 2, { 1, 2, 3, 4 } }, { 0x1200, 3, { 3 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 4, { 1, 2, 3, 5 } }, { 0x2200, 3, { 3 } } });
	match::Result r;
	match::run(a, b, r);
	auto p = pair_of(r, 1);
	CHECK(p && p->new_idx == 1 && p->status == match::Status::Changed);
	CHECK(p && p->similarity == 0.75f);
}

TEST(match_methods) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 7, { 7 } }, { 0x1200, 7, { 7 } }, { 0x1300, 2, { 1, 2, 3, 4 } }, { 0x1400, 3, { 3 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 7, { 7 } }, { 0x2200, 7, { 7 } }, { 0x2300, 4, { 1, 2, 3, 5 } }, { 0x2400, 3, { 3 } } });
	match::Result r;
	match::run(a, b, r);
	auto p0 = pair_of(r, 0), p1 = pair_of(r, 1), p2 = pair_of(r, 2), p3 = pair_of(r, 3), p4 = pair_of(r, 4);
	CHECK(p0 && p0->method == match::Method::Unique);
	CHECK(p1 && p1->method == match::Method::Group);
	CHECK(p2 && p2->method == match::Method::Group);
	CHECK(p3 && p3->method == match::Method::Similar);
	CHECK(p4 && p4->method == match::Method::Unique);
}

TEST(match_added_and_removed) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 5, { 10, 11 } }, { 0x1200, 3, { 3 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 3, { 3 } }, { 0x2200, 6, { 20, 21 } } });
	match::Result r;
	match::run(a, b, r);
	CHECK(r.removed == std::vector<uint32_t>({ 1 }));
	CHECK(r.added == std::vector<uint32_t>({ 2 }));
	CHECK(r.pairs.size() == 2);
}

TEST(match_gap_after_far_moved_anchor) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 9, { 9 } }, { 0x1200, 2, { 2 } }, { 0x1300, 4, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } }, { 0x1400, 3, { 3 } }, { 0x1500, 5, { 5 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 2, { 2 } }, { 0x2200, 6, { 1, 2, 3, 11, 12, 13, 14, 15, 16, 17 } }, { 0x2300, 3, { 3 } }, { 0x2400, 5, { 5 } }, { 0x2500, 9, { 9 } } });
	match::Result r;
	match::run(a, b, r);
	auto p = pair_of(r, 3);
	CHECK(p && p->new_idx == 2 && p->status == match::Status::Changed);
	CHECK(r.added.empty() && r.removed.empty());
}

TEST(match_one_each_in_gap_low_similarity) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 2, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } }, { 0x1200, 3, { 3 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 4, { 1, 11, 12, 13, 14, 15, 16, 17, 18, 19 } }, { 0x2200, 3, { 3 } } });
	match::Result r;
	match::run(a, b, r);
	CHECK(pair_of(r, 1) == nullptr);
	CHECK(r.removed == std::vector<uint32_t>({ 1 }));
	CHECK(r.added == std::vector<uint32_t>({ 1 }));
}

TEST(match_ref_changed) {
	auto a = set_of({ { 0x1000, 9, { 9 }, { call_to(0x1100) } }, { 0x1100, 1, { 1 } }, { 0x1200, 2, { 2 } } });
	auto b = set_of({ { 0x2000, 9, { 9 }, { call_to(0x2200) } }, { 0x2100, 1, { 1 } }, { 0x2200, 2, { 2 } } });
	match::Result r;
	match::run(a, b, r);
	auto p = pair_of(r, 0), pa = pair_of(r, 1), pb = pair_of(r, 2);
	CHECK(p && p->status == match::Status::RefChanged);
	CHECK(pa && pa->status == match::Status::Same);
	CHECK(pb && pb->status == match::Status::Same);
}

TEST(match_ref_same_target_stays_same) {
	auto a = set_of({ { 0x1000, 9, { 9 }, { call_to(0x1104) } }, { 0x1100, 1, { 1 } } });
	auto b = set_of({ { 0x2000, 9, { 9 }, { call_to(0x2304) } }, { 0x2300, 1, { 1 } } });
	match::Result r;
	match::run(a, b, r);
	auto p = pair_of(r, 0);
	CHECK(p && p->status == match::Status::Same);
}

TEST(match_duplicates_paired_by_callee) {
	auto a = set_of({ { 0x1000, 1, { 1 } }, { 0x1100, 2, { 2 } }, { 0x1200, 9, { 9 }, { call_to(0x1000) } }, { 0x1300, 9, { 9 }, { call_to(0x1100) } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x2100, 2, { 2 } }, { 0x2200, 9, { 9 }, { call_to(0x2100) } }, { 0x2300, 9, { 9 }, { call_to(0x2000) } } });
	match::Result r;
	match::run(a, b, r);
	auto p2 = pair_of(r, 2), p3 = pair_of(r, 3);
	CHECK(p2 && p2->new_idx == 3 && p2->status == match::Status::Same);
	CHECK(p3 && p3->new_idx == 2 && p3->status == match::Status::Same);
}

TEST(match_duplicate_callees_paired_by_caller) {
	auto a = set_of({ { 0x1000, 5, { 5 } }, { 0x1100, 5, { 5 } }, { 0x1200, 11, { 11 }, { call_to(0x1000) } }, { 0x1300, 12, { 12 }, { call_to(0x1100) } } });
	auto b = set_of({ { 0x2000, 5, { 5 } }, { 0x2100, 5, { 5 } }, { 0x2200, 5, { 5 } }, { 0x2300, 11, { 11 }, { call_to(0x2100) } }, { 0x2400, 12, { 12 }, { call_to(0x2200) } } });
	match::Result r;
	match::run(a, b, r);
	auto p0 = pair_of(r, 0), p1 = pair_of(r, 1);
	CHECK(p0 && p0->new_idx == 1);
	CHECK(p1 && p1->new_idx == 2);
	CHECK(r.added == std::vector<uint32_t>({ 0 }));
	CHECK(pair_of(r, 2) && pair_of(r, 2)->status == match::Status::Same);
	CHECK(pair_of(r, 3) && pair_of(r, 3)->status == match::Status::Same);
}

TEST(match_duplicate_chain_repaired) {
	auto a = set_of({ { 0x1000, 5, { 5 } }, { 0x1100, 5, { 5 } }, { 0x1200, 11, { 11 }, { call_to(0x1000) } }, { 0x1300, 11, { 11 }, { call_to(0x1100) } } });
	auto b = set_of({ { 0x2000, 5, { 5 } }, { 0x2100, 5, { 5 } }, { 0x2200, 5, { 5 } }, { 0x2300, 11, { 11 }, { call_to(0x2100) } }, { 0x2400, 11, { 11 }, { call_to(0x2200) } } });
	match::Result r;
	match::run(a, b, r);
	auto p0 = pair_of(r, 0), p1 = pair_of(r, 1);
	CHECK(p0 && p0->new_idx == 1);
	CHECK(p1 && p1->new_idx == 2);
	CHECK(r.added == std::vector<uint32_t>({ 0 }));
}

TEST(match_ref_to_identical_callee_stays_same) {
	auto a = set_of({ { 0x1000, 9, { 9 }, { call_to(0x1100) } }, { 0x1100, 5, { 5 } }, { 0x1200, 5, { 5 } } });
	auto b = set_of({ { 0x2000, 9, { 9 }, { call_to(0x2200) } }, { 0x2100, 5, { 5 } }, { 0x2200, 5, { 5 } } });
	match::Result r;
	match::run(a, b, r);
	auto p = pair_of(r, 0);
	CHECK(p && p->status == match::Status::Same);
}

TEST(match_too_different) {
	std::vector<FSpec> sa, sb;
	for (uint32_t i = 0; i < 5001; ++i) {
		sa.push_back({ 0x1000 + i * 0x10, 100000ull + i, { i * 2 + 1 } });
		sb.push_back({ 0x1000 + i * 0x10, 900000ull + i, { i * 2 + 2 } });
	}
	auto a = set_of(sa), b = set_of(sb);
	match::Result r;
	double t0 = test::now_seconds();
	match::run(a, b, r);
	double dt = test::now_seconds() - t0;
	CHECK(r.too_different);
	CHECK(r.pairs.empty());
	CHECK(r.removed.size() == 5001 && r.added.size() == 5001);
	CHECK(dt < 2.0);
}

TEST(match_names) {
	auto ia = test::image_from_code({ 0xC3 }, 0x1000);
	auto ib = test::image_from_code({ 0xC3 }, 0x1000);
	auto a = set_of({ { 0x1000, 1, { 1 } } });
	auto b = set_of({ { 0x2000, 1, { 1 } }, { 0x3000, 2, { 2 } } });
	match::Result r;
	match::run(a, b, r);
	match::Names n;
	match::name(ia, a, ib, b, r, n);
	CHECK(n.old_names.size() == 1 && n.new_names.size() == 2);
	CHECK(n.old_names.size() == 1 && n.old_names[0] == "sub_140001000");
	CHECK(n.new_names.size() == 2 && n.new_names[0] == "sub_140001000");
	CHECK(n.new_names.size() == 2 && n.new_names[1] == "new_140003000");
}

static bool load_and_discover(const wchar_t* p, pe::Image& img, func::Set& set) {
	std::string err;
	if (!pe::load(p, img, err)) return false;
	func::discover(img, set);
	return true;
}

TEST(match_same_file) {
	auto p = test::sample_old(); if (!p) { SKIP(); return; }
	pe::Image img; func::Set set;
	CHECK(load_and_discover(p, img, set));
	match::Result r;
	match::run(set, set, r);
	CHECK(r.removed.empty() && r.added.empty());
	CHECK(r.pairs.size() == set.funcs.size());
	CHECK(std::all_of(r.pairs.begin(), r.pairs.end(), [](auto& x) { return x.status == match::Status::Same; }));
}

TEST(match_sample_pair) {
	auto po = test::sample_old(), pn = test::sample_new(); if (!po || !pn) { SKIP(); return; }
	pe::Image ia, ib; func::Set a, b;
	CHECK(load_and_discover(po, ia, a));
	CHECK(load_and_discover(pn, ib, b));
	match::Result r;
	double t0 = test::now_seconds();
	match::run(a, b, r);
	double dt = test::now_seconds() - t0;
	size_t changed = 0, refchanged = 0;
	for (auto& x : r.pairs) {
		changed += x.status == match::Status::Changed;
		refchanged += x.status == match::Status::RefChanged;
	}
	size_t diff = changed + refchanged + r.added.size() + r.removed.size();
	std::printf("  match_sample_pair: old %zu new %zu same %zu changed %zu refchanged %zu added %zu removed %zu (%.2fs)\n",
		a.funcs.size(), b.funcs.size(), r.pairs.size() - changed - refchanged, changed, refchanged, r.added.size(), r.removed.size(), dt);
	CHECK(diff * 100 <= a.funcs.size() * 2);
	CHECK(dt < 10.0);
}
