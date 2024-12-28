#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <optional>

#include <sel4.hpp>
#include <sdf.hpp>

#include "nlohmann/json.hpp"
#include "tinyxml2.h"

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

static uint64_t json_str_as_u64(const nlohmann::json &json, const std::string &key)
{
	uint64_t value;
	try {
		auto ws_val = json.at("WORD_SIZE");
		if (ws_val.is_string()) {
			// 如果是字符串，尝试转换为数字
			value = std::stoull(ws_val.get<std::string>());
		} else {
			// 如果本身就是数字
			value = ws_val.get<uint64_t>();
		}
	} catch (const nlohmann::json::exception &e) {
		std::cerr << "Parsing error on 'WORD_SIZE': " << e.what() << '\n';
		// 处理错误，比如可以设置一个默认值
		value = -1; // 默认值
	}

	return value;
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
			.word_size = json_str_as_u64(kernel_config_json, "WORD_SIZE"),
			.minimum_page_size = 4096,
			.paddr_user_device_top = json_str_as_u64(kernel_config_json, "PADDR_USER_DEVICE_TOP"),
			.kernel_frame_size = kernel_frame_size,
			.init_cnode_bits = json_str_as_u64(kernel_config_json, "ROOT_CNODE_SIZE_BITS"),
			.cap_address_bits = 64,
			.fan_out_limit = json_str_as_u64(kernel_config_json, "RETYPE_FAN_OUT_LIMIT"),
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

	SystemDescription systemDescription = SystemDescription::parse(args.system, system_xml, kernel_config);

	return 0;
}
