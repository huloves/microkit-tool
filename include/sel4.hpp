#ifndef __SEL4_HPP
#define __SEL4_HPP

#include <iostream>
#include <optional>
#include <nlohmann/json.hpp>

enum class Arch {
	Aarch64,
	Riscv64,
};

// Placeholder for RiscvVirtualMemory type
enum class RiscvVirtualMemory {
    Sv39,
};

enum class PageSize {
    Small = 0x1000,
    Large = 0x200000,
};

enum class IrqTrigger {
	Level = 0,
	Edge = 1,
};

class Config {
public:
	Arch arch;
	uint64_t word_size;
	uint64_t minimum_page_size;
	uint64_t paddr_user_device_top;
	uint64_t kernel_frame_size;
	uint64_t init_cnode_bits;
	uint64_t cap_address_bits;
	uint64_t fan_out_limit;
	bool hypervisor;
	bool benchmark;
	bool fpu;
	std::optional<size_t> arm_pa_size_bits; // ARM-specific
	std::optional<bool> arm_smc;            // ARM-specific
	std::optional<RiscvVirtualMemory> riscv_pt_levels; // RISC-V specific
	nlohmann::json invocations_labels;

	uint64_t user_top() const {
		switch (arch) {
		case Arch::Aarch64:
			if (hypervisor) {
				if (!arm_pa_size_bits.has_value()) throw std::runtime_error("Unknown ARM physical address size bits");
					switch (*arm_pa_size_bits) {
					case 40: return 0x10000000000;
					case 44: return 0x100000000000;
					default: throw std::runtime_error("Unknown ARM physical address size bits");
				}
			} else {
				return 0x800000000000;
			}
			break;
		case Arch::Riscv64:
			return 0x0000003ffffff000;
		default:
			throw std::runtime_error("Unsupported architecture");
		}
	}

	std::array<uint64_t, 2> page_sizes() const {
		return {0x1000, 0x200000};  // Fixed page sizes for Aarch64 and Riscv64
	}

	uint64_t pd_stack_top() const {
		return user_top();
	}

	uint64_t pd_stack_bottom(uint64_t stack_size) const {
		return pd_stack_top() - stack_size;
	}

	uint64_t pd_map_max_vaddr(uint64_t stack_size) const {
		assert(pd_stack_top() == user_top());
		return pd_stack_bottom(stack_size);
	}

	uint64_t vm_map_max_vaddr() const {
		return user_top();
	}
};

#endif /* __SEL4_HPP */
