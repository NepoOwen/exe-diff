#include "tests/test.hpp"
#include "src/sig/scan.hpp"

using B = std::vector<uint8_t>;

TEST(sig_parse_ida_format) {
	sig::Pattern p;
	CHECK(sig::parse("48 8B ? 05 ?? E8", p));
	CHECK(p.bytes.size() == 6 && p.wild.size() == 6);
	if (p.bytes.size() != 6 || p.wild.size() != 6) return;
	CHECK(p.bytes[0] == 0x48 && p.bytes[1] == 0x8B && p.bytes[3] == 0x05 && p.bytes[5] == 0xE8);
	CHECK(!p.wild[0] && !p.wild[1] && p.wild[2] && !p.wild[3] && p.wild[4] && !p.wild[5]);
}

TEST(sig_parse_rejects_garbage) {
	sig::Pattern p;
	CHECK(!sig::parse("", p));
	CHECK(!sig::parse("? ?", p));
	CHECK(!sig::parse("48 8G", p));
	CHECK(!sig::parse("488B", p));
	CHECK(!sig::parse("error: Signature not unique", p));
}

TEST(sig_find_counts_matches_in_every_section) {
	B code(0x40, 0xCC);
	B a = { 0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44 };
	B b = { 0x48, 0x8B, 0x05, 0x55, 0x66, 0x77, 0x88 };
	std::copy(a.begin(), a.end(), code.begin() + 0x10);
	std::copy(b.begin(), b.end(), code.begin() + 0x30);
	auto img = test::image_from_code(code);
	test::put(img, test::kDataRva + 0x80, a.data(), a.size());
	sig::Pattern p;
	CHECK(sig::parse("48 8B 05 ? ? ? ?", p));
	auto hits = sig::find(img, p, 10);
	CHECK(hits.size() == 3);
	CHECK(hits.size() == 3 && hits[0] == 0x1010 && hits[1] == 0x1030 && hits[2] == test::kDataRva + 0x80);
	CHECK(sig::find(img, p, 2).size() == 2);
	CHECK(sig::parse("48 8B 05 ? ? 33", p));
	hits = sig::find(img, p, 10);
	CHECK(hits.size() == 2 && hits[0] == 0x1010 && hits[1] == test::kDataRva + 0x80);
	CHECK(sig::parse("48 8B 05 ? ? 99", p));
	CHECK(sig::find(img, p, 10).empty());
}

TEST(sig_find_leading_wildcards_and_section_end) {
	B code(0x1000, 0x00);
	code[0] = 0xAB;
	code[0xFFE] = 0x5A; code[0xFFF] = 0xA5;
	auto img = test::image_from_code(code);
	sig::Pattern p;
	CHECK(sig::parse("? AB", p));
	CHECK(sig::find(img, p, 10).empty());
	CHECK(sig::parse("5A A5", p));
	auto hits = sig::find(img, p, 10);
	CHECK(hits.size() == 1 && hits[0] == 0x1FFE);
	CHECK(sig::parse("5A A5 ?", p));
	CHECK(sig::find(img, p, 10).empty());
}
