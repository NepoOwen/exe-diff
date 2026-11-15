#include "tests/test.hpp"
#include "src/diff/lines.hpp"

using S = std::vector<std::string>;

static bool same(const diff::Line& l, diff::Op op, uint32_t a, uint32_t b) {
	return l.op == op && (op == diff::Op::Add || l.a == a) && (op == diff::Op::Del || l.b == b);
}

TEST(diff_lines_basic) {
	auto d = diff::lines({ "x", "y", "z" }, { "x", "q", "z" });
	CHECK(d.size() == 4);
	if (d.size() != 4) return;
	CHECK(same(d[0], diff::Op::Keep, 0, 0));
	CHECK(same(d[1], diff::Op::Del, 1, 0));
	CHECK(same(d[2], diff::Op::Add, 0, 1));
	CHECK(same(d[3], diff::Op::Keep, 2, 2));
}

TEST(diff_lines_empty_sides) {
	auto add = diff::lines({}, { "a", "b" });
	CHECK(add.size() == 2 && same(add[0], diff::Op::Add, 0, 0) && same(add[1], diff::Op::Add, 0, 1));
	auto del = diff::lines({ "a", "b" }, {});
	CHECK(del.size() == 2 && same(del[0], diff::Op::Del, 0, 0) && same(del[1], diff::Op::Del, 1, 0));
	CHECK(diff::lines({}, {}).empty());
}

TEST(diff_lines_identical) {
	S a;
	for (int i = 0; i < 1000; ++i) a.push_back("line " + std::to_string(i % 7));
	auto d = diff::lines(a, a);
	CHECK(d.size() == 1000);
	bool all_keep = true;
	for (uint32_t i = 0; i < d.size(); ++i) all_keep &= same(d[i], diff::Op::Keep, i, i);
	CHECK(all_keep);
}

static bool reconstructs(const S& a, const S& b, const std::vector<diff::Line>& d) {
	S ra, rb;
	for (auto& l : d) {
		if (l.op != diff::Op::Add) ra.push_back(a[l.a]);
		if (l.op != diff::Op::Del) rb.push_back(b[l.b]);
		if (l.op == diff::Op::Keep && a[l.a] != b[l.b]) return false;
	}
	return ra == a && rb == b;
}

TEST(diff_lines_reconstruct) {
	S a = { "a", "b", "c", "a", "b", "b", "a" }, b = { "c", "b", "a", "b", "a", "c" };
	auto d = diff::lines(a, b);
	CHECK(reconstructs(a, b, d));
	size_t edits = 0;
	for (auto& l : d) edits += l.op != diff::Op::Keep;
	CHECK(edits == 5);
}

TEST(diff_hunks_context_and_merge) {
	std::vector<diff::Line> l(20);
	for (uint32_t i = 0; i < 20; ++i) l[i] = { diff::Op::Keep, i, i };
	l[5].op = diff::Op::Del;
	l[9].op = diff::Op::Add;
	auto h = diff::hunks(l);
	CHECK(h.size() == 1 && h[0].first == 2 && h[0].count == 11);
	for (uint32_t i = 0; i < 20; ++i) l[i].op = diff::Op::Keep;
	l[2].op = diff::Op::Del;
	l[18].op = diff::Op::Add;
	h = diff::hunks(l);
	CHECK(h.size() == 2);
	CHECK(h.size() == 2 && h[0].first == 0 && h[0].count == 6);
	CHECK(h.size() == 2 && h[1].first == 15 && h[1].count == 5);
	for (uint32_t i = 0; i < 20; ++i) l[i].op = diff::Op::Keep;
	CHECK(diff::hunks(l).empty());
}

TEST(diff_lines_large) {
	S a, b;
	for (int i = 0; i < 20000; ++i) a.push_back("insn " + std::to_string(i));
	b = a;
	for (int i = 0; i < 10; ++i) b[i * 1999 + 7] = "changed " + std::to_string(i);
	double t0 = test::now_seconds();
	auto d = diff::lines(a, b);
	double dt = test::now_seconds() - t0;
	CHECK(reconstructs(a, b, d));
	size_t edits = 0;
	for (auto& l : d) edits += l.op != diff::Op::Keep;
	CHECK(edits == 20);
	CHECK(dt < 1.0);
}

TEST(diff_lines_rewrite_falls_back) {
	S a, b;
	for (int i = 0; i < 6000; ++i) { a.push_back("a" + std::to_string(i)); b.push_back("b" + std::to_string(i)); }
	double t0 = test::now_seconds();
	auto d = diff::lines(a, b);
	double dt = test::now_seconds() - t0;
	CHECK(reconstructs(a, b, d));
	CHECK(dt < 1.0);
}
