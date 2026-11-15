#include "src/ida/process.hpp"
#include "src/util/wide.hpp"
#include <chrono>

namespace ida {
	namespace {
		struct Handle {
			HANDLE h = INVALID_HANDLE_VALUE;
			Handle() = default;
			explicit Handle(HANDLE v) : h(v) {}
			Handle(const Handle&) = delete;
			Handle& operator=(const Handle&) = delete;
			~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
			bool ok() const { return h && h != INVALID_HANDLE_VALUE; }
		};

		Handle open_inheritable(const wchar_t* path, DWORD access, DWORD disposition) {
			SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
			return Handle(CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, disposition, FILE_ATTRIBUTE_NORMAL, nullptr));
		}

		std::string last_error(DWORD code) {
			wchar_t* msg = nullptr;
			DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
				reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
			std::wstring text(msg ? msg : L"", msg ? n : 0);
			if (msg) LocalFree(msg);
			while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) text.pop_back();
			return util::narrow(text) + " (error " + std::to_string(code) + ")";
		}
	}

	ProcessResult run_idat(const std::filesystem::path& idat, const std::wstring& args, const std::filesystem::path& out_file,
		const std::filesystem::path& err_file, const std::function<void(double)>& tick) {
		ProcessResult r;
		auto t0 = std::chrono::steady_clock::now();
		auto since = [&] { return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(); };

		Handle out = open_inheritable(out_file.c_str(), GENERIC_WRITE, CREATE_ALWAYS);
		Handle err = open_inheritable(err_file.c_str(), GENERIC_WRITE, CREATE_ALWAYS);
		Handle in = open_inheritable(L"NUL", GENERIC_READ, OPEN_EXISTING);
		if (!out.ok() || !err.ok() || !in.ok()) {
			r.error = "cannot write " + util::narrow((out.ok() ? err_file : out_file).wstring()) + ": " + last_error(GetLastError());
			return r;
		}

		STARTUPINFOW si{};
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = in.h;
		si.hStdOutput = out.h;
		si.hStdError = err.h;
		PROCESS_INFORMATION pi{};
		std::wstring cmd = L"\"" + idat.wstring() + L"\" " + args;
		if (!CreateProcessW(idat.c_str(), cmd.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
			r.error = "cannot start " + util::narrow(idat.wstring()) + ": " + last_error(GetLastError());
			return r;
		}
		Handle process(pi.hProcess), thread(pi.hThread);

		Handle job(CreateJobObjectW(nullptr, nullptr));
		if (job.ok()) {
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
			limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
			AssignProcessToJobObject(job.h, process.h);
		}
		ResumeThread(thread.h);

		while (WaitForSingleObject(process.h, 500) == WAIT_TIMEOUT) tick(since());
		r.launched = true;
		GetExitCodeProcess(process.h, &r.code);
		r.seconds = since();
		return r;
	}
}
