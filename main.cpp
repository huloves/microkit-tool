#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <optional>

#include "sel4.hpp"
#include "sdf.hpp"
#include "elf.hpp"
#include "util.hpp"

#include "nlohmann/json.hpp"
#include "tinyxml2.h"

constexpr uint64_t SLOT_BITS = 5;
constexpr uint64_t SLOT_SIZE = 1 << SLOT_BITS;

constexpr uint64_t INIT_NULL_CAP_ADDRESS       = 0;
constexpr uint64_t INIT_TCB_CAP_ADDRESS        = 1;
constexpr uint64_t INIT_CNODE_CAP_ADDRESS      = 2;
constexpr uint64_t INIT_VSPACE_CAP_ADDRESS     = 3;
constexpr uint64_t IRQ_CONTROL_CAP_ADDRESS     = 4; // Singleton
constexpr uint64_t INIT_ASID_POOL_CAP_ADDRESS  = 6;
constexpr uint64_t SMC_CAP_ADDRESS             = 15;

const uint64_t MAX_SYSTEM_INVOCATION_SIZE = util::mb(128);

struct KernelFrameRiscv64 {
public:
    uint64_t paddr;
    uint64_t pptr;
    int32_t user_accessible;
};

struct KernelFrameAarch64 {
public:
    uint64_t paddr;
    uint64_t pptr;
    int32_t execute_never;
    int32_t user_accessible;
} __attribute__((__packed__));

std::vector<uint64_t> kernel_device_addrs(const Config& config, const ElfFile& kernel_elf) {
	assert(config.word_size == 64); // Ensure 64-bit word size

	std::vector<uint64_t> kernel_devices;
	std::optional<std::pair<uint64_t, uint64_t>> symbol = kernel_elf.find_symbol("kernel_device_frames");
	if (!symbol) {
		throw std::runtime_error("Could not find 'kernel_device_frames' symbol");
	}

	const std::vector<uint8_t> kernel_frame_bytes = kernel_elf.get_data(symbol->first, symbol->second);
	if (kernel_frame_bytes.empty()) {
		throw std::runtime_error("Failed to retrieve kernel device frame data");
	}

	size_t kernel_frame_size = 0;
	if (config.arch == Arch::Aarch64) {
		kernel_frame_size = sizeof(KernelFrameAarch64);
	} else if (config.arch == Arch::Riscv64) {
		kernel_frame_size = sizeof(KernelFrameRiscv64);
	} else {
		throw std::runtime_error("Unsupported architecture");
	}

	for (size_t offset = 0; offset + kernel_frame_size <= symbol->second; offset += kernel_frame_size) {
		uint32_t user_accessible = 0;
		uint64_t paddr = 0;

		if (config.arch == Arch::Aarch64) {
			const KernelFrameAarch64* frame = reinterpret_cast<const KernelFrameAarch64*>(kernel_frame_bytes.data() + offset);
			user_accessible = frame->user_accessible;
			paddr = frame->paddr;
		} else if (config.arch == Arch::Riscv64) {
			const KernelFrameRiscv64* frame = reinterpret_cast<const KernelFrameRiscv64*>(kernel_frame_bytes.data() + offset);
			user_accessible = frame->user_accessible;
			paddr = frame->paddr;
		}

		if (user_accessible == 0) {
			kernel_devices.push_back(paddr);
		}
	}

	return kernel_devices;
}

struct KernelRegion64 {
	uint64_t start;
	uint64_t end;
};

std::vector<std::pair<uint64_t, uint64_t>> kernel_phys_mem(const Config& kernel_config, const ElfFile& kernel_elf) {
	assert(kernel_config.word_size == 64 && "Unsupported word-size");

	std::vector<std::pair<uint64_t, uint64_t>> phys_mem;
	std::optional<std::pair<uint64_t, uint64_t>> symbol_info = kernel_elf.find_symbol("avail_p_regs");
	if (!symbol_info) {
		throw std::runtime_error("Could not find 'avail_p_regs' symbol");
	}

	const std::vector<uint8_t> p_region_bytes = kernel_elf.get_data(symbol_info->first, symbol_info->second);
	if (p_region_bytes.empty()) {
		throw std::runtime_error("Could not retrieve data for 'avail_p_regs'");
	}

	size_t p_region_size = sizeof(KernelRegion64);
	size_t offset = 0;
	while (offset < symbol_info->second) {
		if (offset + p_region_size > p_region_bytes.size()) {
			throw std::out_of_range("KernelRegion64 data out of range");
		}

		const KernelRegion64* p_region = reinterpret_cast<const KernelRegion64*>(p_region_bytes.data() + offset);
		phys_mem.emplace_back(p_region->start, p_region->end);
		offset += p_region_size;
	}

	return phys_mem;
}

MemoryRegion kernel_self_mem(const ElfFile& kernel_elf) {
	auto segments = kernel_elf.loadable_segments();
	if (segments.empty()) {
		throw std::runtime_error("No loadable segments found.");
	}

	const uint64_t base = segments[0]->get_physical_address();
	auto ki_end_symbol = kernel_elf.find_symbol("ki_end");
	if (!ki_end_symbol) {
		throw std::runtime_error("Could not find 'ki_end' symbol");
	}

	uint64_t ki_end_v = ki_end_symbol->first;
	uint64_t ki_end_p = ki_end_v - segments[0]->get_virtual_address() + base;

	return MemoryRegion(base, ki_end_p);
}

MemoryRegion kernel_boot_mem(ElfFile& kernel_elf) {
	const auto& segments = kernel_elf.loadable_segments();
	if (segments.empty()) {
		throw std::runtime_error("No loadable segments found");
	}
	uintptr_t base = segments[0]->get_physical_address();

	auto ki_boot = kernel_elf.find_symbol("ki_boot_end");
	uintptr_t ki_boot_end_p = ki_boot->first- segments[0]->get_virtual_address() + base;

	return MemoryRegion(base, ki_boot_end_p);
}

class KernelPartialBootInfo {
public:
	DisjointMemoryRegion device_memory;
	DisjointMemoryRegion normal_memory;
	MemoryRegion boot_region;

	/// Emulate what happens during a kernel boot, up to the point
	/// where the reserved region is allocated.
	///
	/// This factors the common parts of 'emulate_kernel_boot' and
	/// 'emulate_kernel_boot_partial' to avoid code duplication.
	///
	///
	/// 模拟内核启动过程，直到分配保留区域为止。
	///
	/// 这部分提取了 'emulate_kernel_boot' 和 'emulate_kernel_boot_partial'
	/// 的公共部分，以避免代码重复。
	static KernelPartialBootInfo kernel_partial_boot(const Config &kernel_config, ElfFile kernel_elf) {
		DisjointMemoryRegion device_memory;
		DisjointMemoryRegion normal_memory;

		// 首先将整个物理地址空间分配为设备内存 paddr_user_device_top = 0x10000000000
		device_memory.insert_region(0, kernel_config.paddr_user_device_top);

		// Next, remove all the kernel devices.
		// NOTE: There is an assumption each kernel device is one frame
		// in size only. It's possible this assumption could break in the
		// future.
		// 获取kernel_elf中的每一个设备信息，获得起始地址后移除，目前假设设备大小为一页
		for (auto paddr : kernel_device_addrs(kernel_config, kernel_elf)) {
			device_memory.remove_region(paddr, paddr + kernel_config.kernel_frame_size);
		}

		// Remove all the actual physical memory from the device regions
		// but add it all to the actual normal memory regions
		// 获取物理内存区域，从设备内存区域中移除，加入到不同普通内存区域中
		for (auto p_region : kernel_phys_mem(kernel_config, kernel_elf)) {
			device_memory.remove_region(p_region.first, p_region.second);
			normal_memory.insert_region(p_region.first, p_region.second);
		}

		MemoryRegion self_mem = kernel_self_mem(kernel_elf);
		normal_memory.remove_region(self_mem.base, self_mem.end);

		MemoryRegion boot_region = kernel_boot_mem(kernel_elf);

		return KernelPartialBootInfo {
			.device_memory = device_memory,
			.normal_memory = normal_memory,
			.boot_region = boot_region,
		};
	}

	static std::pair<DisjointMemoryRegion, MemoryRegion> emulate_kernel_boot_partial(const Config &kernel_config, ElfFile kernel_elf) {
		auto partial_info = kernel_partial_boot(kernel_config, kernel_elf);
		return {partial_info.normal_memory, partial_info.boot_region};
	}
};

class MonitorConfig {
private:
	const std::string untyped_info_symbol_name;
	const std::string bootstrap_invocation_count_symbol_name;
	const std::string bootstrap_invocation_data_symbol_name;
	const std::string system_invocation_count_symbol_name;

public:
	MonitorConfig(const std::string new_untyped_info_symbol_name,
		      const std::string new_bootstrap_invocation_count_symbol_name,
		      const std::string new_bootstrap_invocation_data_symbol_name,
		      const std::string new_system_invocation_count_symbol_name) :
			untyped_info_symbol_name(new_untyped_info_symbol_name),
			bootstrap_invocation_count_symbol_name(new_bootstrap_invocation_count_symbol_name),
			bootstrap_invocation_data_symbol_name(new_bootstrap_invocation_data_symbol_name),
			system_invocation_count_symbol_name(new_system_invocation_count_symbol_name) { }
};

class BuiltSystem {
public:
	uint64_t number_of_system_caps;
	std::vector<uint8_t> invocation_data;
	uint64_t invocation_data_size;
	std::vector<Invocation> bootstrap_invocations;
	std::vector<Invocation> system_invocations;
	BootInfo kernel_boot_info;
	MemoryRegion reserved_region;
	uint64_t fault_ep_cap_address;
	uint64_t reply_cap_address;
	std::unordered_map<uint64_t, std::string> cap_lookup;
	std::vector<uint64_t> tcb_caps;
	std::vector<uint64_t> sched_caps;
	std::vector<uint64_t> ntfn_caps;
	std::vector<std::vector<Region>> pd_elf_regions;
	std::vector<std::vector<uint64_t>> pd_setvar_values;
	std::vector<Object> kernel_objects;
	MemoryRegion initial_task_virt_region;
	MemoryRegion initial_task_phys_region;

	// Default constructor with initializations
	BuiltSystem() :
		number_of_system_caps(0),  // Initialize number of system capabilities to 0
		invocation_data(),         // Empty vector
		invocation_data_size(0),   // Initialize data size to 0
		bootstrap_invocations(),   // Empty vector
		system_invocations(),      // Empty vector
		kernel_boot_info(),        // Assumes default constructor for BootInfo
		reserved_region(),         // Assumes default constructor for MemoryRegion
		fault_ep_cap_address(0),   // Initialize to 0, indicating no address
		reply_cap_address(0),      // Initialize to 0, indicating no address
		cap_lookup(),              // Empty unordered_map
		tcb_caps(),                // Empty vector
		sched_caps(),              // Empty vector
		ntfn_caps(),               // Empty vector
		pd_elf_regions(),          // Empty vector of vectors
		pd_setvar_values(),        // Empty vector of vectors
		kernel_objects(),          // Empty vector
		initial_task_virt_region(),// Assumes default constructor for MemoryRegion
		initial_task_phys_region() // Assumes default constructor for MemoryRegion
	{}

	static uint64_t get_n_paging(const MemoryRegion& region, uint64_t bits) {
		uint64_t start = util::round_down(region.base, 1ULL << bits);
		uint64_t end = util::round_up(region.end, 1ULL << bits);

		return (end - start) >> bits;
	}

	static uint64_t get_arch_n_paging(const Config& config, const MemoryRegion& region) {
		if (config.arch == Arch::Aarch64) {
			constexpr uint64_t PT_INDEX_OFFSET = 12;
			constexpr uint64_t PD_INDEX_OFFSET = PT_INDEX_OFFSET + 9;
			constexpr uint64_t PUD_INDEX_OFFSET = PD_INDEX_OFFSET + 9;

			return get_n_paging(region, PUD_INDEX_OFFSET) + get_n_paging(region, PD_INDEX_OFFSET);
		} else if (config.arch == Arch::Riscv64 && config.riscv_pt_levels.has_value()) {
			switch(config.riscv_pt_levels.value()) {
			case RiscvVirtualMemory::Sv39: {
				constexpr uint64_t PT_INDEX_OFFSET = 12;
				constexpr uint64_t LVL1_INDEX_OFFSET = PT_INDEX_OFFSET + 9;
				constexpr uint64_t LVL2_INDEX_OFFSET = LVL1_INDEX_OFFSET + 9;

				return get_n_paging(region, LVL2_INDEX_OFFSET) + get_n_paging(region, LVL1_INDEX_OFFSET);
			}
			default:
				throw std::runtime_error("Unsupported RISC-V paging level");
			}
		} else {
			throw std::runtime_error("Unsupported architecture");
		}

		return 0; // To silence compiler warning, this part is theoretically unreachable.
	}

	static uint64_t rootserver_max_size_bits(const Config& config) {
		const uint64_t slot_bits = 5; // Assuming seL4_SlotBits is constant across uses
		const uint64_t root_cnode_bits = config.init_cnode_bits; // CONFIG_ROOT_CNODE_SIZE_BITS
		const uint64_t vspace_bits = config.fixed_size_bits(ObjectType::VSpace).value();

		const uint64_t cnode_size_bits = root_cnode_bits + slot_bits;
		return std::max(cnode_size_bits, vspace_bits);
	}

	static uint64_t calculate_rootserver_size(const Config& config, const MemoryRegion& initial_task_region) {
		// FIXME: These constants should ideally come from the config / kernel
		// binary not be hard coded here.
		// But they are constant so it isn't too bad.
		const uint64_t slot_bits = 5;  // seL4_SlotBits 5 32B
		const uint64_t root_cnode_bits = config.init_cnode_bits;  // CONFIG_ROOT_CNODE_SIZE_BITS 12 4k
		const uint64_t tcb_bits = config.fixed_size_bits(ObjectType::Tcb).value();  // seL4_TCBBits 11 2k
		const uint64_t page_bits = config.fixed_size_bits(ObjectType::SmallPage).value();  // seL4_PageBits 12 4k
		const uint64_t asid_pool_bits = 12;  // seL4_ASIDPoolBits 12
		const uint64_t vspace_bits = config.fixed_size_bits(ObjectType::VSpace).value();  // seL4_VSpaceBits 13 8k
		const uint64_t page_table_bits = config.fixed_size_bits(ObjectType::PageTable).value();  // seL4_PageTableBits 12 4k
		const uint64_t min_sched_context_bits = 7;  // seL4_MinSchedContextBits 7 128B

		uint64_t size = 0;
		size += 1ULL << (root_cnode_bits + slot_bits);
		size += 1ULL << tcb_bits;
		size += 2 * (1ULL << page_bits);
		size += 1ULL << asid_pool_bits;
		size += 1ULL << vspace_bits;
		size += get_arch_n_paging(config, initial_task_region) * (1ULL << page_table_bits);
		size += 1ULL << min_sched_context_bits;

		return size;
	}

	static BootInfo emulate_kernel_boot(
				const Config &config,
				const ElfFile kernel_elf,
				const MemoryRegion initial_task_phys_region,
				const MemoryRegion initial_task_virt_region,
				MemoryRegion reserved_region) {
		assert(initial_task_phys_region.size() == initial_task_virt_region.size());
		KernelPartialBootInfo partial_info = KernelPartialBootInfo::kernel_partial_boot(config, kernel_elf);
		DisjointMemoryRegion normal_memory = partial_info.normal_memory;
		DisjointMemoryRegion device_memory = partial_info.device_memory;
		MemoryRegion boot_region = partial_info.boot_region;

		normal_memory.remove_region(initial_task_phys_region.base, initial_task_phys_region.end);
		normal_memory.remove_region(reserved_region.base, reserved_region.end);

		uint64_t initial_objects_size = calculate_rootserver_size(config, initial_task_virt_region);
		uint64_t initial_objects_align = rootserver_max_size_bits(config);

		// Find an appropriate region of normal memory to allocate the objects
		// from; this follows the same algorithm used within the kernel boot code
		// (or at least we hope it does!)
		// TOOD: this loop could be done better in a functional way?
		// 找到一个适当的普通内存区域来分配对象
		// 这遵循内核启动代码中使用的相同算法
		// （或者至少我们希望如此！）
		std::optional<uint64_t> region_to_remove = normal_memory.get_base_from_end(initial_objects_size, initial_objects_align);
		if (region_to_remove.has_value()) {
			uint64_t start = region_to_remove.value();
			normal_memory.remove_region(start, start + initial_objects_size);
		} else {
			throw std::runtime_error("Couldn't find appropriate region for initial task kernel objects");
		}

		const uint64_t fixed_cap_count = 0x10; // 16 in hexadecimal
		const uint64_t sched_control_cap_count = 1;

		uint64_t paging_cap_count = get_arch_n_paging(config, initial_task_virt_region);
		uint64_t page_cap_count = initial_task_virt_region.size() / config.minimum_page_size;
		uint64_t first_untyped_cap = fixed_cap_count + paging_cap_count + sched_control_cap_count + page_cap_count;
		uint64_t sched_control_cap = fixed_cap_count + paging_cap_count;

		std::cout << "fixed_cap_count = " << std::hex << fixed_cap_count << std::endl;
		std::cout << "first_untyped_cap = " << std::hex << first_untyped_cap << std::endl;

		uint64_t max_bits;
		switch (config.arch) {
		case Arch::Aarch64:
			max_bits = 47;
			break;
		case Arch::Riscv64:
			max_bits = 38;
			break;
			// Include other cases as necessary
		default:
			throw std::runtime_error("Unsupported architecture.");
		}

		// Device regions concatenation
		std::vector<MemoryRegion> device_regions;
		std::vector<MemoryRegion> temp1 = reserved_region.aligned_power_of_two_regions(max_bits);
		std::vector<MemoryRegion> temp2 = device_memory.aligned_power_of_two_regions(max_bits);
		device_regions.insert(device_regions.end(), temp1.begin(), temp1.end());
		device_regions.insert(device_regions.end(), temp2.begin(), temp2.end());

		// Normal regions concatenation
		std::vector<MemoryRegion> normal_regions;
		temp1 = boot_region.aligned_power_of_two_regions(max_bits);
		temp2 = normal_memory.aligned_power_of_two_regions(max_bits);
		normal_regions.insert(normal_regions.end(), temp1.begin(), temp1.end());
		normal_regions.insert(normal_regions.end(), temp2.begin(), temp2.end());

		std::vector<UntypedObject> untyped_objects;

		uint64_t cap;
		for (size_t i = 0; i < device_regions.size(); ++i) {
			cap = i + first_untyped_cap;
			untyped_objects.push_back(UntypedObject(cap, device_regions[i], true));
		}

		uint64_t normal_regions_start_cap = first_untyped_cap + device_regions.size();
		for (size_t i = 0; i < normal_regions.size(); ++i) {
			cap = i + normal_regions_start_cap;
			untyped_objects.push_back(UntypedObject(cap, normal_regions[i], false));
		}

		uint64_t first_available_cap = normal_regions_start_cap + normal_regions.size();

		return BootInfo {
			.fixed_cap_count = fixed_cap_count,
			.sched_control_cap = sched_control_cap,
			.paging_cap_count = paging_cap_count,
			.page_cap_count = page_cap_count,
			.untyped_objects = untyped_objects,
			.first_available_cap = first_available_cap,
		};
	}

	static BuiltSystem build_system(
			const Config &config,
			const std::vector<ElfFile> &pd_elf_files,
			const ElfFile &kernel_elf,
			const ElfFile &monitor_elf,
			const SystemDescription &system,
			const uint64_t &invocation_table_size,
			const uint64_t &system_cnode_size) {
		assert(util::is_power_of_two(system_cnode_size));
		assert(invocation_table_size % config.minimum_page_size == 0);
		assert(invocation_table_size <= MAX_SYSTEM_INVOCATION_SIZE);

		std::unordered_map<uint64_t, std::string> cap_address_names;
		cap_address_names[INIT_NULL_CAP_ADDRESS] = "null";
		cap_address_names[INIT_TCB_CAP_ADDRESS] = "TCB: init";
		cap_address_names[INIT_CNODE_CAP_ADDRESS] = "CNode: init";
		cap_address_names[INIT_VSPACE_CAP_ADDRESS] = "VSpace: init";
		cap_address_names[INIT_ASID_POOL_CAP_ADDRESS] = "ASID Pool: init";
		cap_address_names[IRQ_CONTROL_CAP_ADDRESS] = "IRQ Control";
		cap_address_names[SMC_CAP_ADDRESS] = "SMC";

		unsigned long long system_cnode_bits = util::ilog2(system_cnode_size);

		// Emulate kernel boot

		// Determine physical memory region used by the monitor
		// 确定monitor使用的物理内存区域大小
		uint64_t initial_task_size = monitor_elf.phys_mem_region_from_elf(config.minimum_page_size).size();

		// Determine physical memory region for 'reserved' memory.
		//
		// The 'reserved' memory region will not be touched by seL4 during boot
		// and allows the monitor (initial task) to create memory regions
		// from this area, which can then be made available to the appropriate
		// protection domains
		// 确定‘保留’内存的物理内存区域大小。
		//
		// 在启动期间，seL4 不会触及‘保留’的内存区域
		// 这允许监视器（初始任务）从这一区域创建内存区域，
		// 然后可以将这些内存区域提供给适当的保护域。
		uint64_t pd_elf_size = 0;
		std::cout << "all pd elf files:" << std::endl;
		for (auto &pd_elf : pd_elf_files) {
			std::cout << pd_elf.get_elf_path().string() << std::endl;
			auto regions = pd_elf.phys_mem_regions_from_elf(config.minimum_page_size);
			for (const auto &region : regions) {
				pd_elf_size += region.size();
			}
		}

		uint64_t reserved_size = invocation_table_size + pd_elf_size;

		// Now that the size is determined, find a free region in the physical memory
		// space.
		// 找到物理内存中空闲的区域
		auto [available_memory, kernel_boot_region] = KernelPartialBootInfo::emulate_kernel_boot_partial(config, kernel_elf);

		uint64_t reserved_base = available_memory.allocate_from(reserved_size, kernel_boot_region.end);
		assert(kernel_boot_region.base < reserved_base);

		std::cout << "reserved_base = " << std::hex << reserved_base << std::endl;

		uint64_t initial_task_phys_base = available_memory.allocate_from(initial_task_size, reserved_base + reserved_size);
		assert(reserved_base < initial_task_phys_base);

		std::cout << "initial_task_phys_base = " << std::hex << initial_task_phys_base << std::endl;

		MemoryRegion initial_task_phys_region = MemoryRegion(initial_task_phys_base, initial_task_phys_base + initial_task_size);
		MemoryRegion initial_task_virt_region = monitor_elf.virt_mem_region_from_elf(config.minimum_page_size);

		MemoryRegion reserved_region = MemoryRegion(reserved_base, reserved_base + reserved_size);
	
		MemoryRegion invocation_table_region = MemoryRegion(reserved_base, reserved_base + invocation_table_size);

		BootInfo kernel_boot_info = emulate_kernel_boot(
			config,
			kernel_elf,
			initial_task_phys_region,
			initial_task_virt_region,
			reserved_region
		);

		for (const auto& ut : kernel_boot_info.untyped_objects) {
			std::ostringstream oss;
			std::string dev_str = ut.is_device ? " (device)" : "";
			oss << "Untyped @ 0x" << std::hex << ut.region.base << ":0x" << ut.region.size() << dev_str;
			cap_address_names[ut.cap] = oss.str();
		}

		// The kernel boot info allows us to create an allocator for kernel objects
		ObjectAllocator kao(kernel_boot_info);

		// 2. Now that the available resources are known it is possible to proceed with the
		// monitor task boot strap.
		//
		// The boot strap of the monitor works in two phases:
		//
		//   1. Setting up the monitor's CSpace
		//   2. Making the system invocation table available in the monitor's address
		//   space.

		// 2.1 The monitor's CSpace consists of two CNodes: a/ the initial task CNode
		// which consists of all the fixed initial caps along with caps for the
		// object create during kernel bootstrap, and b/ the system CNode, which
		// contains caps to all objects that will be created in this process.
		// The system CNode is of `system_cnode_size`. (Note: see also description
		// on how `system_cnode_size` is iteratively determined).
		// 2.1 监控器的 CSpace （能力空间）包含两个 CNode（能力节点）：a/ 初始任务 CNode，
		// 它包括所有固定的初始能力以及在内核引导时创建的对象的能力；b/ 系统 CNode，其中
		// 包含本进程将创建的所有对象的能力。
		// 系统 CNode 的大小为 system_cnode_size。（注：另见关于如何迭代确定 system_cnode_size 的描述）。
		//
		// The system CNode is not available at startup and must be created (by retyping
		// memory from an untyped object). Once created the two CNodes must be aranged
		// as a tree such that the slots in both CNodes are addressable.
		// system CNode 在启动时不可用，必须通过retype未类型化对象的内存来创建。
		// 一旦创建，两个 CNode 必须以树的形式组织，以便两个 CNode 中的槽位都可以寻址。
		//
		// The system CNode shall become the root of the CSpace. The initial CNode shall
		// be copied to slot zero of the system CNode. In this manner all caps in the initial
		// CNode will keep their original cap addresses. This isn't required but it makes
		// allocation, debugging and reasoning about the system more straight forward.
		// system CNode 应成为 CSpace 的根节点。初始 CNode 应被复制到system CNode 的第零槽位。
		// 通过这种方式，初始 CNode 中的所有能力（caps）将保持它们原始的能力地址。
		// 这不是必需的，但这样做使得系统的分配、调试和逻辑推理更为直接。
		//
		// The guard shall be selected so the least significant bits are used. The guard
		// for the root shall be:
		// 应选择护卫以便使用最低有效位。根的护卫应为：
		//
		//   64 - system cnode bits - initial cnode bits
		//
		// The guard for the initial CNode will be zero.
		//
		// 2.1.1: Allocate the *root* CNode. It is two entries:
		//  slot 0: the existing init cnode
		//  slot 1: our main system cnode
		int root_cnode_bits = 1;
		KernelAllocation root_cnode_allocation = kao.alloc((1 << root_cnode_bits) * (1 << SLOT_BITS));
		uint64_t root_cnode_cap = kernel_boot_info.first_available_cap;
		cap_address_names[root_cnode_cap] = "CNode: root";

		// 2.1.2: Allocate the *system* CNode. It is the cnodes that
		// will have enough slots for all required caps.
		KernelAllocation system_cnode_allocation = kao.alloc(system_cnode_size * (1 << SLOT_BITS));
		uint64_t system_cnode_cap = kernel_boot_info.first_available_cap + 1;
		cap_address_names[system_cnode_cap] = "CNode: system";

		// 2.1.3: Now that we've allocated the space for these we generate
		// the actual systems calls.
		// 2.1.3：现在我们已经为这些系统分配了空间，接下来生成实际的系统调用。
		//
		// First up create the root cnode
		std::vector<Invocation> bootstrap_invocations;

		std::unique_ptr<InvocationArgs> args_ptr;

		args_ptr = std::make_unique<UntypedRetypeArgs>(UntypedRetypeArgs(
				root_cnode_allocation.untyped_cap_address,  // the untyped capability to retype
				ObjectType::CNode,  // type
				root_cnode_bits,  //size
				INIT_CNODE_CAP_ADDRESS,  // root
				0,  // node_index
				0,  // node_depth
				root_cnode_cap,  // node_offset
				1));  // num_caps
		bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));

		// 2.1.4: Now insert a cap to the initial Cnode into slot zero of the newly
		// allocated root Cnode. It uses sufficient guard bits to ensure it is
		// completed padded to word size
		// 2.1.4: 现在将初始Cnode的cap插入到新分配的根Cnode的零号槽中。
		// 它使用足够的保护位来确保其填充到字大小。
		//
		// guard size is the lower bit of the guard, upper bits are the guard itself
		// which for out purposes is always zero.
		// 保护大小是保护位的低位，高位是保护位本身，对于我们的目的来说，它始终为零。
		uint64_t guard = config.cap_address_bits - root_cnode_bits - config.init_cnode_bits;
		args_ptr = std::make_unique<CnodeMint>(CnodeMint(
				root_cnode_cap,
				0,
				root_cnode_bits,
				INIT_CNODE_CAP_ADDRESS,
				INIT_CNODE_CAP_ADDRESS,
				config.cap_address_bits,
				static_cast<uint64_t>(Right::All),
				guard));
		bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));

		// 2.1.5: Now it is possible to switch our root Cnode to the newly create
		// root cnode. We have a zero sized guard. This Cnode represents the top
		// bit of any cap addresses.
		// 2.1.5: 现在我们可以将我们的根 Cnode 切换到新创建的根 cnode。
		// 我们有一个大小为零的保护。这个 Cnode 代表任何能力地址的最高位。
		uint64_t root_guard = 0;
		args_ptr = std::make_unique<TcbSetSpace>(TcbSetSpace(
				INIT_TCB_CAP_ADDRESS,
				INIT_NULL_CAP_ADDRESS,
				root_cnode_cap,
				root_guard,
				INIT_VSPACE_CAP_ADDRESS,
				0));
		bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));

		// 2.1.6: Now we can create our new system Cnode. We will place it into
    		// a temporary cap slot in the initial CNode to start with.
		args_ptr = std::make_unique<UntypedRetypeArgs>(UntypedRetypeArgs(
				system_cnode_allocation.untyped_cap_address,
				ObjectType::CNode,
				system_cnode_bits,
				INIT_CNODE_CAP_ADDRESS,
				0,
				0,
				system_cnode_cap,
				1));
		bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));

		// 2.1.7: Now that the we have create the object, we can 'mutate' it
		// to the correct place:
		// Slot #1 of the new root cnode
		uint64_t system_cap_address_mask = 1 << (config.cap_address_bits - 1);
		args_ptr = std::make_unique<CnodeMint>(CnodeMint(
				root_cnode_cap,
				1,
				root_cnode_bits,
				INIT_CNODE_CAP_ADDRESS,
				system_cnode_cap,
				config.cap_address_bits,
				static_cast<uint64_t>(Right::All),
				config.cap_address_bits - root_cnode_bits - system_cnode_bits));
		bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));

		// 2.2 At this point it is necessary to get the frames containing the
		// main system invocations into the virtual address space. (Remember the
		// invocations we are writing out here actually _execute_ at run time!
		// It is a bit weird that we talk about mapping in the invocation data
		// before we have even generated the invocation data!).
		// 2.2 此时，有必要将包含主系统调用的帧获取到虚拟地址空间中。
		// （请记住，我们在这里写出的调用实际上是在运行时执行的！
		// 在我们甚至还没有生成调用数据之前，我们讨论映射调用数据确实有点奇怪！）。
		//
		// This needs a few steps:
		//
		// 1. Turn untyped into page objects
		// 2. Map the page objects into the address space
		// 这需要几个步骤：
		//
		// 1. 将无类型数据转换为页面对象
		// 2. 将页面对象映射到地址空间中
		//

		// 2.2.1: The memory for the system invocation data resides at the start
		// of the reserved region. We can retype multiple frames as a time (
		// which reduces the number of invocations we need). However, it is possible
		// that the region spans multiple untyped objects.
		// At this point in time we assume we will map the area using the minimum
		// page size. It would be good in the future to use super pages (when
		// it makes sense to - this would reduce memory usage, and the number of
		// invocations required to set up the address space
		// 2.2.1：系统调用数据的内存位于保留区域的起始处。
		// 我们可以一次重新类型化多个帧（这样可以减少我们需要的调用次数）。然而，这个区域可能跨越多个无类型对象。
		// 此时，我们假设我们将使用最小页面大小来映射该区域。
		// 将来使用超级页面（只有在合适的时候 - 这将减少内存使用和建立地址空间所需的调用次数）会是一个不错的选择。
		uint64_t pages_required = invocation_table_size / config.minimum_page_size;
		uint64_t base_page_cap = 0;
		for (uint64_t pta = base_page_cap; pta < base_page_cap + pages_required; ++pta) {
			int cap_address = system_cap_address_mask | pta;
			cap_address_names[cap_address] = "SmallPage: monitor invocation table";
		}

		uint64_t remaining_pages = pages_required;
		std::vector<std::pair<UntypedObject*, uint64_t>> invocation_table_allocations;
		uint64_t cap_slot = base_page_cap;
		uint64_t phys_addr = invocation_table_region.base;

		std::cout << "phys_addr = " << phys_addr << std::endl;

		std::vector<UntypedObject*> boot_info_device_untypeds;
		for (auto& obj : kernel_boot_info.untyped_objects) {
			if (obj.is_device) {
				boot_info_device_untypeds.push_back(&obj);
			}
		}

		for (const auto& ut : boot_info_device_untypeds) {
			size_t ut_pages = ut->getRegion().size() / config.minimum_page_size;
			size_t retype_page_count = std::min(ut_pages, remaining_pages);

			std::cout << "ut_pages = " << ut_pages << std::endl;
			std::cout << "remaining_pages = " << remaining_pages << std::endl;
			size_t retypes_remaining = retype_page_count;
			while (retypes_remaining > 0) {
				size_t num_retypes = std::min(retypes_remaining, config.fan_out_limit);
				args_ptr = std::make_unique<UntypedRetypeArgs>(UntypedRetypeArgs(
						ut->cap,
						ObjectType::SmallPage,
						0,
						root_cnode_cap,
						1,
						1,
						cap_slot,
						num_retypes));
				bootstrap_invocations.push_back(Invocation(config, std::move(args_ptr)));
				
				retypes_remaining -= num_retypes;
				cap_slot += num_retypes;
			}

			remaining_pages -= retype_page_count;
			phys_addr += retype_page_count * config.minimum_page_size;
			std::cout << "phys_addr = " << phys_addr << std::endl;
			invocation_table_allocations.push_back(std::pair<UntypedObject*, uint64_t>(ut, phys_addr));
			if (remaining_pages == 0) {
				break;
			}
		}

		// 2.2.1: Now that physical pages have been allocated it is possible to setup
		// the virtual memory objects so that the pages can be mapped into virtual memory
		// At this point we map into the arbitrary address of 0x0.8000.0000 (i.e.: 2GiB)
		// We arbitrary limit the maximum size to be 128MiB. This allows for at least 1 million
		// invocations to occur at system startup. This should be enough for any reasonable
		// sized system.
		//
		// Before mapping it is necessary to install page tables that can cover the region.

		return {};
	}
};

struct Args {
	std::string system;
	std::string board;
	std::string config;
	std::string report;
	std::string output;
	std::vector<std::string> search_paths;

	Args() : report("report.txt"), output("loader.img") {}

	static Args parse(int argc, char *argv[], const std::vector<std::string> &available_boards) {
		std::vector<std::string> args(argv, argv + argc);
		Args parsed_args;

		std::string *system = nullptr;
		std::string *board = nullptr;
		std::string *config = nullptr;
		std::vector<std::string> unknown;
		bool in_search_path = false;

		if (argc <= 1) {
			print_usage(available_boards);
			std::exit(1);
		}

		for (int i = 1; i < argc; ++i) {
			if (args[i] == "-h" || args[i] == "--help") {
				print_help(available_boards);
				std::exit(0);
			} else if (args[i] == "-o" || args[i] == "--output") {
				in_search_path = false;
				if (i + 1 < argc) {
					parsed_args.output = args[++i];
				} else {
					std::cerr << "microkit: error: argument -o/--output: expected one argument" << std::endl;
					std::exit(1);
				}
			} else if (args[i] == "-r" || args[i] == "--report") {
				in_search_path = false;
				if (i + 1 < argc) {
					parsed_args.report = args[++i];
				} else {
					std::cerr << "microkit: error: argument -r/--report: expected one argument" << std::endl;
					std::exit(1);
				}
			} else if (args[i] == "--board") {
				in_search_path = false;
				if (i + 1 < argc) {
					board = &args[++i];
				} else {
					std::cerr << "microkit: error: argument --board: expected one argument" << std::endl;
					std::exit(1);
				}
			} else if (args[i] == "--config") {
				in_search_path = false;
				if (i + 1 < argc) {
					config = &args[++i];
				} else {
					std::cerr << "microkit: error: argument --config: expected one argument" << std::endl;
					std::exit(1);
				}
			} else if (args[i] == "--search-path") {
				in_search_path = true;
			} else {
				if (in_search_path) {
					parsed_args.search_paths.push_back(args[i]);
				} else if (!system) {
					system = &args[i];
				} else {
					unknown.push_back(args[i]);
				}
			}
		}

		if (!unknown.empty()) {
			print_usage(available_boards);
			std::cerr << "microkit: error: unrecognised arguments: ";
			for (const auto &arg : unknown) {
				std::cerr << arg << " ";
			}
			std::cerr << std::endl;
			std::exit(1);
		}

		std::vector<std::string> missing_args;
		if (!board) missing_args.push_back("--board");
		if (!config) missing_args.push_back("--config");
		if (!system) missing_args.push_back("system");

		if (!missing_args.empty()) {
			print_usage(available_boards);
			std::cerr << "microkit: error: the following arguments are required: ";
			for (const auto &arg : missing_args) {
				std::cerr << arg << " ";
			}
			std::cerr << std::endl;
			std::exit(1);
		}

		parsed_args.system = *system;
		parsed_args.board = *board;
		parsed_args.config = *config;

		return parsed_args;
	}

	static void print_usage(const std::vector<std::string> &available_boards) {
		std::cout << "Usage: program [OPTIONS] system\n"
					<< "Available boards:\n";
		for (const auto &board : available_boards) {
			std::cout << "  " << board << std::endl;
		}
	}

	static void print_help(const std::vector<std::string> &available_boards) {
		std::cout << "Help: \n"
			<< "Options:\n"
			<< "  -h, --help     Show this help message and exit\n"
			<< "  -o, --output   Specify output file\n"
			<< "  -r, --report   Specify report file\n"
			<< "  --board        Specify board\n"
			<< "  --config       Specify config\n"
			<< "  --search-path  Add search path\n";
		print_usage(available_boards);
	}
};

// 函数用于检查json中的布尔值
static bool json_str_as_bool(const nlohmann::json &json, const std::string &key)
{
	return json.contains(key) && json[key].is_boolean() && json[key].get<bool>();
}

std::optional<std::filesystem::path> get_full_path(const std::filesystem::path &image, const std::vector<std::filesystem::path> &search_paths) {
	for (const auto &base_path : search_paths) {
		std::filesystem::path full_path = base_path / image;
		if (std::filesystem::exists(full_path)) {
			return full_path;
		}
	}
	return std::nullopt;
}

int main(int argc, char *argv[])
{
	std::filesystem::path exe_path;
	const char *sdk_env;
	std::filesystem::path sdk_dir;

	try {
		// 获取可执行文件路径
		exe_path = std::filesystem::current_path();

		// 获取环境变量 MICROKIT_SDK
		sdk_env = std::getenv("MICROKIT_SDK");
		
		if (sdk_env) {
			sdk_dir = sdk_env;
		} else {
			// 当 MICROKIT_SDK 环境变量不存在时，使用可执行文件所在的上级目录作为 SDK 目录
			sdk_dir = exe_path.parent_path().parent_path();
		}
	} catch (const std::exception &e) {
		std::cerr << "Error: Could not read MICROKIT_SDK environment variable: " << e.what() << std::endl;
		return 1;
	}

	// 输出 SDK 目录
	std::cout << "SDK Directory: " << sdk_dir << std::endl;

	// 检查 SDK 目录是否存在
	if (!std::filesystem::exists(sdk_dir)) {
		std::cerr << "Error: SDK directory '" << sdk_dir << "' does not exist." << std::endl;
		std::exit(1);
	}

	// 检查是否有 'board' 子目录
	std::filesystem::path boards_path = sdk_dir / "board";
	if (!std::filesystem::exists(boards_path) || !std::filesystem::is_directory(boards_path)) {
		std::cerr << "Error: SDK directory '" << sdk_dir << "' does not have a 'board' sub-directory." << std::endl;
		std::exit(1);
	}

	// 找到可用的board
	std::vector<std::string> available_boards;

	try {
		for (const auto &entry : std::filesystem::directory_iterator(boards_path)) {
			if (entry.is_directory()) {
				available_boards.push_back(entry.path().filename().string());
			}
		}
	} catch (const std::filesystem::filesystem_error &e) {
		std::cerr << "Error accessing directory: " << e.what() << std::endl;
		return 1;
	}

	std::vector<std::string> env_args(argv, argv + argc);
	Args args = Args::parse(argc, argv, available_boards);

	std::filesystem::path board_path = boards_path / args.board;
	if (!std::filesystem::exists(board_path)) {
		std::cerr << "Error: board path '" << board_path << "' does not exist." << std::endl;
		std::exit(1);
	}

	std::cout << "Board_path = " << board_path << std::endl;

	std::vector<std::string> available_configs;
    try {
		for (const auto &entry : std::filesystem::directory_iterator(board_path)) {
			const auto &path = entry.path();

			if (path.filename() == "example") {
				continue;
			}

			if (entry.is_directory()) {
				available_configs.push_back(path.filename().string());
			}

			// std::cout << "@@@@@: available_config.push(" << path.filename().string() << ")" << std::endl;
		}
	} catch (const std::filesystem::filesystem_error &e) {
		std::cerr << "Error accessing directory: " << e.what() << std::endl;
		return 1;
	}

	if (std::find(available_configs.begin(), available_configs.end(), args.config) == available_configs.end()) {
		std::string joined_configs;
		for (const auto &c : available_configs) {
			if (!joined_configs.empty()) {
				joined_configs += ", ";
			}
			joined_configs += c;
		}

		std::cerr << "microkit: error: argument --config: invalid choice: '"
				<< args.config << "' (choose from: " << joined_configs << ")"
				<< std::endl;
	}

	// 找到loader.elf, sel4.elf, monitor.elf
	std::filesystem::path elf_path = sdk_dir / "board" / args.board / args.config / "elf";
	std::filesystem::path loader_elf_path = elf_path / "loader.elf";
	std::filesystem::path kernel_elf_path = elf_path / "sel4.elf";
	std::filesystem::path monitor_elf_path = elf_path / "monitor.elf";

	// 找到内核配置json文件
	std::filesystem::path kernel_config_path = sdk_dir / "board" / args.board / args.config / "include/kernel/gen_config.json";

	// 找到sel4内核调用json文件
	std::filesystem::path invocations_all_path = sdk_dir / "board" / args.board / args.config / "invocations_all.json";

#if 0
	std::cout << "Loader ELF path: " << loader_elf_path << std::endl;
	std::cout << "Kernel ELF path: " << kernel_elf_path << std::endl;
	std::cout << "Monitor ELF path: " << monitor_elf_path << std::endl;
	std::cout << "Kernel config path " << kernel_config_path << std::endl;
	std::cout << "Invocations all path " << invocations_all_path << std::endl;
#endif

	if (!std::filesystem::exists(elf_path)) {
		std::cerr << "Error: board ELF directory '" << elf_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	if (!std::filesystem::exists(loader_elf_path)) {
		std::cerr << "Error: loader ELF '" << loader_elf_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	if (!std::filesystem::exists(kernel_elf_path)) {
		std::cerr << "Error: kernel ELF '" << kernel_elf_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	if (!std::filesystem::exists(monitor_elf_path)) {
		std::cerr << "Error: monitor ELF '" << monitor_elf_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	if (!std::filesystem::exists(kernel_config_path)) {
		std::cerr << "Error: kernel configuration file '" << kernel_config_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	if (!std::filesystem::exists(invocations_all_path)) {
		std::cerr << "Error: invocations JSON file '" << invocations_all_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	// 获取.system系统描述文件
	std::filesystem::path system_path(args.system);
	if (!std::filesystem::exists(system_path)) {
		std::cerr << "Error: system description file '" << system_path << "' does not exist" << std::endl;
		std::exit(1);
	}

	// 读取系统描述文件
	std::ifstream system_ifstream(system_path);
	std::string system_xml;

	if (system_ifstream) {
		system_xml = std::string((std::istreambuf_iterator<char>(system_ifstream)), std::istreambuf_iterator<char>());
	} else {
		std::cerr << "Failed to read the system file." << std::endl;
		std::exit(1);
	}

	// 读取内核配置json文件
	std::ifstream kernel_config_ifstream(kernel_config_path);
	std::string kernel_config_content;
	nlohmann::json kernel_config_json;

	if (kernel_config_ifstream) {
		kernel_config_content = std::string((std::istreambuf_iterator<char>(kernel_config_ifstream)), std::istreambuf_iterator<char>());
		try {
			kernel_config_json = nlohmann::json::parse(kernel_config_content);
			// std::cout << "Kernel Config JSON:\n" << kernel_config_json.dump(4) << std::endl;  // 格式化输出
		} catch (nlohmann::json::parse_error &e) {
			std::cerr << "JSON parsing error: " << e.what() << '\n';
		}
	} else {
		std::cerr << "Failed to read the kernel config file.\n";
	}

	// 读取sel4内核调用json文件
	std::ifstream invocations_ifstream(invocations_all_path);
	std::string invocations_content;
	nlohmann::json invocations_labels;

	if (invocations_ifstream) {
		invocations_content = std::string((std::istreambuf_iterator<char>(invocations_ifstream)), std::istreambuf_iterator<char>());
		try {
			invocations_labels = nlohmann::json::parse(invocations_content);
			// std::cout << "Sel4 invocations JSON:\n" << invocations_labels.dump(4) << std::endl;  // 格式化输出
		} catch (nlohmann::json::parse_error &e) {
			std::cerr << "JSON parsing error: " << e.what() << std::endl;
		}
	} else {
		std::cerr << "Failed to read the kernel config file." << std::endl;
	}

	// 通过内核配置文件获取内核架构
	Arch arch;
	try {
		std::string arch_str;

		try {
			arch_str = kernel_config_json.at("SEL4_ARCH").get<std::string>();
		} catch (const nlohmann::json::out_of_range &e) {
			std::cerr << "Error: " << e.what() << "\n";
		}

		if (arch_str == "aarch64") {
			arch = Arch::Aarch64;
		} else if (arch_str == "riscv64") {
			arch = Arch::Riscv64;
		} else {
			throw std::runtime_error("Unsupported kernel config architecture");
		}
	} catch (const nlohmann::json::out_of_range &e) {
		std::cerr << "Error: " << e.what() << "\n";
	} catch (const std::runtime_error &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		std::exit(1);
	}

	// 获取是否支持hypervisor
	bool hypervisor;
	try {
		if (arch == Arch::Aarch64) {
			hypervisor = kernel_config_json.at("ARM_HYPERVISOR_SUPPORT").get<bool>();
		} else if (arch == Arch::Riscv64) {
			hypervisor = false;
		}
	} catch (const nlohmann::json::out_of_range &e) {
		std::cerr << "Error: " << e.what() << "\n";
		hypervisor = false;
	}

	// 获取物理地址位宽
	std::optional<int> armPaSizeBits;
	try {
		switch (arch) {
		case Arch::Aarch64:
			if (json_str_as_bool(kernel_config_json, "ARM_PA_SIZE_BITS_40")) {
				armPaSizeBits = 40;
				break;
			} else if (json_str_as_bool(kernel_config_json, "ARM_PA_SIZE_BITS_44")) {
				armPaSizeBits = 44;
				break;
			} else {
				throw std::runtime_error("Expected ARM platform to have 40 or 44 physical address bits");
				break;
			}
		case Arch::Riscv64:
			armPaSizeBits = std::nullopt;
			break;
		default:
			armPaSizeBits = std::nullopt;
			break;
		}

        if (armPaSizeBits) {
		std::cout << "Physical address bits: " << *armPaSizeBits << std::endl;
		} else {
		std::cout << "No specific physical address bits required." << std::endl;
		}
	} catch (const std::runtime_error& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	std::optional<bool> arm_smc;
	switch (arch) {
	case Arch::Aarch64:
		if (json_str_as_bool(kernel_config_json, "ALLOW_SMC_CALLS")) {
			arm_smc = true;
		} else {
			arm_smc = false;
		}
		break;
	default:
		arm_smc = false;
		break;
	}

	uint64_t kernel_frame_size;
	switch (arch) {
	case Arch::Aarch64:
		kernel_frame_size = 1 << 12;
		break;
	case Arch::Riscv64:
		kernel_frame_size = 1 << 21;
		break;
	default:
		std::cout << "Only support Aarch64 and Riscv64" << std::endl;
		std::exit(1);
	}

	Config kernel_config;
	try {
		kernel_config = {
			.arch = arch,
			.word_size = util::json_str_as_u64(kernel_config_json, "WORD_SIZE"),
			.minimum_page_size = 4096,
			.paddr_user_device_top = util::json_str_as_u64(kernel_config_json, "PADDR_USER_DEVICE_TOP"),
			.kernel_frame_size = kernel_frame_size,
			.init_cnode_bits = util::json_str_as_u64(kernel_config_json, "ROOT_CNODE_SIZE_BITS"),
			.cap_address_bits = 64,
			.fan_out_limit = util::json_str_as_u64(kernel_config_json, "RETYPE_FAN_OUT_LIMIT"),
			.hypervisor = hypervisor,
			.benchmark = args.config == "benchmark",
			.fpu = json_str_as_bool(kernel_config_json, "HAVE_FPU"),
			.arm_pa_size_bits = armPaSizeBits,
			.arm_smc = arm_smc,
			.riscv_pt_levels = RiscvVirtualMemory::Sv39,
			.invocations_labels = invocations_labels,
		};
	} catch (const std::exception &e) {
		std::cerr << "Failed to create config: " << e.what() << std::endl;
		std::exit(1);
	}

	try {
		if (kernel_config.arch == Arch::Aarch64) {
			assert(kernel_config.hypervisor && 
					"Microkit tool expects a kernel with hypervisor mode enabled on AArch64.");

			assert(kernel_config.arm_pa_size_bits.has_value() &&
					kernel_config.arm_pa_size_bits.value() == 40 &&
					"Microkit tool has assumptions about the ARM physical address size bits");
		}

		assert(kernel_config.word_size == 64 &&
				"Microkit tool has various assumptions about the word size being 64-bits.");
		
		std::cout << "All assertions passed." << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Assertion failed: " << e.what() << std::endl;
		std::exit(1);
	}

	SystemDescription system = SystemDescription::parse(args.system, system_xml, kernel_config);

	MonitorConfig monitor_config = MonitorConfig(
					"untyped_info",
					"bootstrap_invocation_count",
					"bootstrap_invocation_data",
					"system_invocation_count");
	
	ElfFile kernel_elf(kernel_elf_path);
        ElfFile monitor_elf(monitor_elf_path);

	std::cout << "monitor_elf_path = " << monitor_elf_path << std::endl;

	size_t loadable_segments_count = monitor_elf.count_loadable_segments();
        if (loadable_segments_count > 1) {
            std::cerr << "Monitor (" << monitor_elf_path << ") has " << loadable_segments_count
                      << " segments, it must only have one" << std::endl;
            std::exit(1);
        }
	
	std::vector<std::filesystem::path> search_paths;

	try {
		// 将当前目录添加到搜索路径
		search_paths.push_back(std::filesystem::current_path());

		// 将参数中指定的搜索路径添加到搜索路径
		for (auto search_path : args.search_paths) {
			search_paths.push_back(std::filesystem::path(search_path));
		}

		// 打印搜索路径来验证添加成功
		for (const auto &path : search_paths) {
			std::cout << "Search Path: " << path << std::endl;
		}
	} catch (const std::filesystem::filesystem_error &e) {
		std::cerr << "Error handling filesystem: " << e.what() << std::endl;
		std::exit(1);
	}

	std::vector<ElfFile> pd_elf_files;
	for (auto pd : system.protection_domains) {
		auto optional_path = get_full_path(pd.get_program_image(), search_paths);
		if (optional_path) {
			ElfFile elf_file = ElfFile::from_path(*optional_path);
			pd_elf_files.push_back(elf_file);
		} else {
			throw std::runtime_error(std::string("Unable to find program image: ") + pd.get_program_image().string());
		}
	}

	uint64_t invocation_table_size = kernel_config.minimum_page_size;
	uint64_t system_cnode_size = 2;

	BuiltSystem built_system = BuiltSystem::build_system(
		kernel_config,
		pd_elf_files,
		kernel_elf,
		monitor_elf,
		system,
		invocation_table_size,
		system_cnode_size
	);

	return 0;
}
