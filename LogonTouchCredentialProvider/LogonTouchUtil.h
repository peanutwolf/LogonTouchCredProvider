#pragma once

#include <string>
#include <memory>

#include "spdlog.h"

namespace spdlog {
	std::shared_ptr<spdlog::logger> combined_logger_st_safe(
		const std::string &logger_name, const spdlog::filename_t &filename, size_t max_file_size, size_t max_files);
}

namespace logontouch{
	int getLogonTouchRegParam(const std::string &param, std::string &path);
}




