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

		uint64_t initial_task_phys_base = available_memory.allocate_from(initial_task_size, reserved_base + reserved_size);
		assert(reserved_base < initial_task_phys_base);

		MemoryRegion initial_task_phys_region = MemoryRegion(initial_task_phys_base, initial_task_phys_base + initial_task_size);
		MemoryRegion initial_task_virt_region = monitor_elf.virt_mem_region_from_elf(config.minimum_page_size);
	
		MemoryRegion invocation_table_region = MemoryRegion(reserved_base, reserved_base + invocation_table_size);

		// BootInfo kernel_boot_info = emulate_kernel_boot(
		// 	config,
		// 	kernel_elf,
		// 	initial_task_phys_region,
		// 	initial_task_virt_region,
		// 	reserved_region,
		// );

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
