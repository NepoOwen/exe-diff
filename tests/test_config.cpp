#include "tests/test.hpp"
#include "src/config/settings.hpp"
#include "src/console/console.hpp"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

TEST(settings_read_ida_dir) {
	auto s = config::parse("; comment\r\n[ida]\r\nida_dir = C:\\Program Files\\IDA Professional 9.2\r\n");
	CHECK(s.ida_dir == L"C:\\Program Files\\IDA Professional 9.2");
	CHECK(s.warnings.empty());
}

TEST(settings_strip_quotes_and_bom) {
	auto s = config::parse("\xEF\xBB\xBF" "IDA_DIR=\"D:\\tools\\ida\"\n");
	CHECK(s.ida_dir == L"D:\\tools\\ida");
	CHECK(s.warnings.empty());
}

TEST(settings_empty_value_means_detect) {
	auto s = config::parse("ida_dir =\n");
	CHECK(s.ida_dir.empty());
	CHECK(s.warnings.empty());
}

TEST(settings_warn_about_typos) {
	auto s = config::parse("ida_path = x\nnonsense\n# fine\n");
	CHECK(s.ida_dir.empty());
	CHECK(s.warnings.size() == 2);
}

TEST(settings_default_file_round_trips) {
	auto dir = fs::temp_directory_path() / "exediff_tests" / "settings";
	std::error_code ec;
	fs::remove_all(dir, ec);
	fs::create_directories(dir);
	config::Settings loaded;
	CHECK(config::load(dir / "exediff.ini", loaded) == config::Load::Missing);
	CHECK(config::write_default(dir / "exediff.ini", L"C:\\IDA 9.2"));
	CHECK(config::load(dir / "exediff.ini", loaded) == config::Load::Ok);
	CHECK(loaded.ida_dir == L"C:\\IDA 9.2");
	CHECK(loaded.warnings.empty());
}

TEST(elapsed_formats) {
	CHECK(console::elapsed(4.26) == "4.3 s");
	CHECK(console::elapsed(61) == "1m 01s");
	CHECK(console::elapsed(242.9) == "4m 02s");
}
