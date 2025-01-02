#ifndef __UTIL_HPP
#define __UTIL_HPP

#include <cassert>
#include <iostream>

#include "nlohmann/json.hpp"

namespace util {
	constexpr unsigned long long kb(uint64_t n) {
		return n * 1024;
	}

	constexpr unsigned long long mb(uint64_t n) {
		return n * 1024 * 1024;
	}

	bool is_power_of_two(uint64_t n) {
		assert(n > 0);
		return (n & (n - 1)) == 0;
	}

	uint64_t ilog2(uint64_t x) {
		if (x == 0) return 0;
		uint64_t log = 0;
		while (x >>= 1) ++log;
		return log;
	}

	uint64_t round_up(uint64_t n, uint64_t x) {
		uint64_t remainder = n % x;
		if (remainder == 0) {
			return n;
		} else {
			return n + x - remainder;
		}
	}

	uint64_t round_down(uint64_t n, uint64_t x) {
		uint64_t remainder = n % x;
		if (remainder == 0) {
			return n;
		} else {
			return n - remainder;
		}
	}

	// 使用 nlohmann::json 类型
	uint64_t json_str_as_u64(const nlohmann::json& json, const std::string& field) {
		try {
			// 尝试获取字段
			if (json.contains(field)) {
				std::string valueStr = json.at(field).get<std::string>();  // 首先，尝试获取字符串
				return std::stoull(valueStr); // 尝试将字符串转换为 uint64_t
			} else {
				throw std::runtime_error("JSON field '" + field + "' does not exist");
			}
		} catch (std::exception& e) {
			// 捕获所有异常，并以更具体的错误消息抛出异常
			throw std::runtime_error("Error processing JSON field '" + field + "': " + e.what());
		}
	}
}

#endif /* __UTIL_HPP */
