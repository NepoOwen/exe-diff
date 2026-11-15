#include "tests/test.hpp"
#include "src/ida/install.hpp"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

static fs::path fresh(const char* name) {
	auto dir = fs::temp_directory_path() / "exediff_tests" / name;
	std::error_code ec;
	fs::remove_all(dir, ec);
	fs::create_directories(dir);
	return dir;
}

static void touch(const fs::path& p) {
	fs::create_directories(p.parent_path());
	std::ofstream(p, std::ios::binary) << "x";
}

TEST(inspect_accepts_an_install_folder) {
	auto dir = fresh("ida_ok");
	touch(dir / "idat.exe");
	touch(dir / "plugins" / "hexx64.dll");
	ida::Install i;
	std::string problem;
	CHECK(ida::inspect(dir, i, problem));
	CHECK(i.idat == dir / "idat.exe");
	CHECK(i.hexrays);
}

TEST(inspect_accepts_the_idat_path_and_notes_missing_hexrays) {
	auto dir = fresh("ida_idat");
	touch(dir / "idat.exe");
	ida::Install i;
	std::string problem;
	CHECK(ida::inspect(dir / "idat.exe", i, problem));
	CHECK(i.dir == dir);
	CHECK(!i.hexrays);
}

TEST(inspect_explains_what_is_wrong) {
	auto dir = fresh("ida_bad");
	ida::Install i;
	std::string problem;
	CHECK(!ida::inspect(dir / "missing", i, problem));
	CHECK(problem.find("does not exist") != std::string::npos);
	CHECK(!ida::inspect(dir, i, problem));
	CHECK(problem.find("idat.exe is not in") != std::string::npos);
	CHECK(!ida::inspect({}, i, problem));
	CHECK(!problem.empty());
}

TEST(scripts_are_found_next_to_the_exe_or_one_level_up) {
	auto root = fresh("ida_scripts");
	fs::path scripts;
	std::string problem;
	CHECK(!ida::find_scripts(root / "build", scripts, problem));
	CHECK(problem.find("analyse.py") != std::string::npos);
	touch(root / "ida" / "analyse.py");
	CHECK(!ida::find_scripts(root / "build", scripts, problem));
	touch(root / "ida" / "decompile.py");
	CHECK(ida::find_scripts(root / "build", scripts, problem));
	CHECK(scripts == root / "ida");
	touch(root / "build" / "ida" / "analyse.py");
	touch(root / "build" / "ida" / "decompile.py");
	CHECK(ida::find_scripts(root / "build", scripts, problem));
	CHECK(scripts == root / "build" / "ida");
}
