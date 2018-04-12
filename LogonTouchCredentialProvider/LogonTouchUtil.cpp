

#include <Windows.h>
#include <Winreg.h>

#include "LogonTouchUtil.h"
#include "sinks/null_sink.h"
#include "sinks/stdout_sinks.h"

static LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
{
	strValue = strDefaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}



int logontouch::getLogonTouchRegParam(const std::string &param, std::string &path) {
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\LazyGravity\\LogonTouchUI", 0, KEY_READ, &hKey);
	if (lRes != ERROR_SUCCESS) return -1;

	std::wstring str_tmp;
	std::wstring param_tmp(param.begin(), param.end());
	GetStringRegKey(hKey, param_tmp, str_tmp, L"");
	path.assign(str_tmp.begin(), str_tmp.end());

	RegCloseKey(hKey);

	return 0;
}

std::shared_ptr<spdlog::logger> spdlog::combined_logger_st_safe(
	const std::string &logger_name, const spdlog::filename_t &filename, size_t max_file_size, size_t max_files) {
	std::vector<spdlog::sink_ptr> sinks;
	sinks.push_back(std::make_shared<spdlog::sinks::null_sink_st>());
	try {
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_sink_st>());
		sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_st>(filename, max_file_size, max_files));
	}
	catch (...) {

	}
	auto combined_logger = std::make_shared<spdlog::logger>(logger_name, begin(sinks), end(sinks));

	return combined_logger;
}
