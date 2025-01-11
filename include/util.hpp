#ifndef __UTIL_HPP
#define __UTIL_HPP

#include <cassert>
#include <iostream>

#include "nlohmann/json.hpp"

namespace util {
	uint64_t msb(uint64_t x);

	uint64_t lsb(uint64_t x);

	constexpr unsigned long long kb(uint64_t n) {
		return n * 1024;
	}

	constexpr unsigned long long mb(uint64_t n) {
		return n * 1024 * 1024;
	}

	bool is_power_of_two(uint64_t n);

	uint64_t ilog2(uint64_t x);

	uint64_t round_up(uint64_t n, uint64_t x);

	uint64_t round_down(uint64_t n, uint64_t x);

	// 使用 nlohmann::json 类型
	uint64_t json_str_as_u64(const nlohmann::json& json, const std::string& field);
}

#endif /* __UTIL_HPP */
