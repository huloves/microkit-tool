#ifndef __SDF_HPP
#define __SDF_HPP

#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <sstream>
#include <variant>
#include <functional>

#include "sel4.hpp"
#include "tinyxml2.h"

const uint64_t PD_MAX_ID = 61;
const uint64_t VCPU_MAX_ID = PD_MAX_ID;

const uint8_t PD_MAX_PRIORITY = 254;
// In microseconds
const uint64_t BUDGET_DEFAULT = 1000;

// Default to a stack size of a single page
const uint64_t PD_DEFAULT_STACK_SIZE = 0x1000;
const uint64_t PD_MIN_STACK_SIZE = 0x1000;
const uint64_t PD_MAX_STACK_SIZE = 1024 * 1024 * 16;

bool str_to_bool(const std::string &s, bool &outBool) {
	if (s == "true") {
		outBool = true;
		return true;
	} else if (s == "false") {
		outBool = false;
		return true;
	}
	return false;
}

std::pair<uint64_t, std::string> sdf_parse_number(const std::string &s, const tinyxml2::XMLElement *node) {
	std::string to_parse;
	// Remove underscores from the string
	for (auto c : s) {
		if (c != '_') to_parse += c;
	}

	std::string final_str;
	int base = 10;

	// Check if the number is hexadecimal
	if (to_parse.rfind("0x", 0) == 0) { // starts with "0x"
		base = 16;
		final_str = to_parse.substr(2); // strip "0x"
	} else {
		final_str = to_parse;
	}

	// Parse the number
	try {
		size_t pos;
		uint64_t value = std::stoull(final_str, &pos, base);
		if (pos < final_str.size()) {
			throw std::invalid_argument("Extra characters");
		}
		return std::make_pair(value, "");
	} catch (std::exception& e) {
		std::ostringstream oss;
		oss << "Error: failed to parse integer '" << s << "' on element '"
			<< (node ? node->Value() : "unknown") << "': " << e.what();
		return std::make_pair(0, oss.str());
	}
}

struct XMLPosition {
    int line;   // Line number
};

std::optional<XMLPosition> getXMLPosition(tinyxml2::XMLElement *element) {
	if (element) {
		return XMLPosition{element->GetLineNum()};
	}
	return std::nullopt;
}

enum class SysMapPerms : uint8_t {
	None = 0,
	Read = 1,
	Write = 2,
	Execute = 4,
};

class SysMapPermsConverter {
public:
    static uint8_t from_str(const std::string& s) {
        uint8_t perms = static_cast<uint8_t>(SysMapPerms::None);

        for (char c : s) {
            switch (c) {
			case 'r':
				perms |= static_cast<uint8_t>(SysMapPerms::Read);
				break;
			case 'w':
				perms |= static_cast<uint8_t>(SysMapPerms::Write);
				break;
			case 'x':
				perms |= static_cast<uint8_t>(SysMapPerms::Execute);
				break;
			default:
				throw std::invalid_argument("Invalid permission character");
			}
        }

        return perms;
    }
};

class SysIrq {
private:
	uint64_t irq;
	uint64_t id;
	IrqTrigger trigger;

public:
	// 默认构造函数
	SysIrq()
		: irq(0), id(0), trigger(IrqTrigger::Level) {  // 这里选择 LevelLow 作为默认触发方法
	}

	// 参数化构造函数
	SysIrq(uint64_t irq, uint64_t id, IrqTrigger trigger)
		: irq(irq), id(id), trigger(trigger) {
	}

	// Getter 方法
	uint64_t getIrq() const { return irq; }
	uint64_t getId() const { return id; }
	IrqTrigger getTrigger() const { return trigger; }

	// Setter 方法（如果需要）
	void setIrq(uint64_t newIrq) { irq = newIrq; }
	void setId(uint64_t newId) { id = newId; }
	void setTrigger(IrqTrigger newTrigger) { trigger = newTrigger; }
};

// 定义表示虚拟地址变体的结构
struct Vaddr {
	uint64_t address;
};

// 定义表示物理地址变体的结构
struct Paddr {
	std::string region;
};

// 定义 SysSetVarKind 类型，使用 std::variant 来容纳不同的类型
using SysSetVarKind = std::variant<Vaddr, Paddr>;

// 辅助函数，用于访问并展示 SysSetVarKind 的内容
void printSysSetVarKind(const SysSetVarKind &kind) {
	std::visit([](auto &&arg) {
		using T = std::decay_t<decltype(arg)>;
		if constexpr (std::is_same_v<T, Vaddr>) {
			std::cout << "Vaddr with address: " << arg.address << std::endl;
		} else if constexpr (std::is_same_v<T, Paddr>) {
			std::cout << "Paddr with region: " << arg.region << std::endl;
		}
	}, kind);
}

class SysSetVar {
public:
	std::string symbol;
	SysSetVarKind kind;
};

// 定义 ChannelEnd 结构体
class ChannelEnd {
public:
	std::size_t pd;
	uint64_t id;
	bool notify;
	bool pp;
};

class Channel {
public:
	ChannelEnd end_a;
	ChannelEnd end_b;
};

class VirtualCpu {
public:
	uint64_t id;

	VirtualCpu(uint64_t id) : id(id) {}

	// Default copy constructor and move semantics are fine in this case
	friend bool operator==(const VirtualCpu& lhs, const VirtualCpu& rhs) {
		return lhs.id == rhs.id;
	}

	friend bool operator!=(const VirtualCpu& lhs, const VirtualCpu& rhs) {
		return !(lhs == rhs);
	}

	// For debugging
	friend std::ostream& operator<<(std::ostream& os, const VirtualCpu& vcpu) {
		return os << "VirtualCpu ID: " << vcpu.id;
	}
};

class XmlSystemDescription {
private:
	const std::string filename;  // Pointer to filename string
	tinyxml2::XMLDocument *doc;   // Pointer to the XMLDocument

public:
	// Constructor: Initialize references to an existing string and XMLDocument
	XmlSystemDescription(const std::string &filename, tinyxml2::XMLDocument *doc)
		: filename(filename), doc(doc) {}

	// Accessor functions
	const std::string &getFilename() const { return filename; }
	const tinyxml2::XMLDocument& getDocument() const { return *doc; }

	// Since tinyxml2 manages documents quite differently from roxmltree, let's make a practical example:
	void printRootName() const {
		const tinyxml2::XMLElement *root = doc->RootElement();
		if (root) {
			std::cout << "Root Element Name: " << root->Name() << std::endl;
		} else {
			std::cout << "No root element found." << std::endl;
		}
	}

	bool contains(const std::vector<std::string> &attributes, const std::string &name) const {
		return std::find(attributes.begin(), attributes.end(), name) != attributes.end();
	}

	void check_attributes(const tinyxml2::XMLElement *node, const std::vector<std::string> &attributes) const {
		if (!node) {
			throw std::invalid_argument("Node pointer is null in value_error function.");
		}

		const tinyxml2::XMLAttribute *attribute = node->FirstAttribute();
		while (attribute) {
			if (!contains(attributes, attribute->Name())) {
				std::string error_message = "Invalid attribute '" + std::string(attribute->Name()) + "'";
				std::cerr << filename << ": " << error_message << std::endl;  // Using std::cerr for error message similar to print in original
				throw std::runtime_error(error_message);
			}
			attribute = attribute->Next();
		}
	}

	std::string checked_lookup(const tinyxml2::XMLElement *node, const std::string &attribute) const {
		if (!node) {
			throw std::invalid_argument("Node pointer is null in value_error function.");
		}

		const char *value = node->Attribute(attribute.c_str());
		if (value != nullptr) {
			return std::string(value);
		} else {
			// Using tinyxml2 to gather line and column number for error reporting
			int row = node->GetLineNum();
			int col = 1; // tinyxml2 does not provide specific column numbers

			// Format the error message to closely resemble the Rust version
			std::stringstream err;
			err << "Error: Missing required attribute '" << attribute
				<< "' on element '" << (node->Value() ? node->Value() : "")
				<< "': " << filename
				<< ":" << row << ":" << col;

			throw std::runtime_error(err.str());
		}
	}

	std::string value_error(const tinyxml2::XMLElement *node, const std::string &err) const {
		if (!node) {
			throw std::invalid_argument("Node pointer is null in value_error function.");
		}

		int row = node->GetLineNum(); // Get line number of the node
		// tinyxml2 does not provide column number information directly
		int col = 1; // This is an assumed value since we don't have an exact column number

		std::stringstream error_message;
		error_message << "Error: " << err
				<< " on element '" << (node->Value() ? node->Value() : "")
				<< "': " << filename
				<< ":" << row << ":" << col;

		return error_message.str();
	}

	const tinyxml2::XMLElement *findSystemNode(void) {
		const tinyxml2::XMLElement *systemNode = doc->RootElement();  // Get the root element of the XML document
		if (!systemNode) {
			std::cerr << "Error: No system root element." << std::endl;
			return nullptr;  // Early return if there is no root element
		}
		return systemNode;
	}

	bool checkNoText(const tinyxml2::XMLNode *node) {
		if (node == nullptr) {
			return true;
		}

		// 处理文本节点
		if (const tinyxml2::XMLText *textNode = node->ToText()) {
			const char* text = textNode->Value();
			// 检查是否只有空白字符
			if (std::string(text).find_first_not_of(" \t\n\r\f\v") != std::string::npos) {
				int line = textNode->GetLineNum(); // 获取行号，用于错误报告
				std::cerr << "Error: Non-whitespace text found at line " << line << ": '" << text << "'" << std::endl;
				return false;
			}
		}

		// 递归检查所有子节点
		const tinyxml2::XMLNode *child = node->FirstChild();
		while (child) {
			if (!checkNoText(child)) {
				return false;
			}
			child = child->NextSibling();
		}

		return true;
	}
};

class SysMemoryRegion {
private:
	std::string name;
	uint64_t size;
	PageSize page_size;
	uint64_t page_count;
	std::optional<uint64_t> phys_addr;
	const tinyxml2::XMLElement *element;

public:
	// 默认构造函数
    SysMemoryRegion()
		: name(""), size(0), page_size(PageSize::Small), page_count(0), phys_addr(std::nullopt), element(nullptr) {}

    // 参数化构造函数
    SysMemoryRegion(std::string name, uint64_t size, PageSize page_size, uint64_t page_count, std::optional<uint64_t> phys_addr, const tinyxml2::XMLElement *element)
		: name(name), size(size), page_size(page_size), page_count(page_count), phys_addr(phys_addr), element(element) {}
	
	// Getters
	std::string getName() const { return name; }
	uint64_t getSize() const { return size; }
	PageSize getPageSize() const { return page_size; }
	uint64_t getPageCount() const { return page_count; }
	std::optional<uint64_t> getPhysAddr() const { return phys_addr; }
	const tinyxml2::XMLElement *getXMLElement() const { return element; }

	// Setters
	void setName(const std::string& newName) { name = newName; }
	void setSize(uint64_t newSize) { size = newSize; }
	void setPageSize(PageSize newPageSize) { page_size = newPageSize; }
	void setPageCount(uint64_t newPageCount) { page_count = newPageCount; }
	void setPhysAddr(const std::optional<uint64_t>& newPhysAddr) { phys_addr = newPhysAddr; }
	void setTextPos(tinyxml2::XMLElement * newTextPos) { element = newTextPos; }
	
	static PageSize from_uint64_to_pagesize(uint64_t value) {
		switch (value) {
		case static_cast<uint64_t>(PageSize::Small):
			return PageSize::Small;
		case static_cast<uint64_t>(PageSize::Large):
			return PageSize::Large;
		default:
			throw std::invalid_argument("Unsupported page size");
		}
	}

	uint64_t page_byte() {
		return static_cast<uint64_t>(page_size);
	}

	static SysMemoryRegion from_xml(
			const Config &config,
			const XmlSystemDescription &xml_sdf,
			const tinyxml2::XMLElement *node) {
		xml_sdf.check_attributes(node, {"name", "size", "page_size", "phys_addr"});

		std::string name;
		try {
			name = xml_sdf.checked_lookup(node, "name");
		} catch (std::exception &e) {
			std::string err_str = xml_sdf.value_error(node, e.what());
			throw std::runtime_error(err_str);
		}

		uint64_t size;
		auto parsed_size_result = sdf_parse_number(xml_sdf.checked_lookup(node, "size"), node);
		if (parsed_size_result.second.empty()) {
			size = parsed_size_result.first;
		} else {
			std::string err_str = xml_sdf.value_error(node, parsed_size_result.second);
			throw std::runtime_error(err_str);
		}

		uint64_t page_size;
		std::string xml_page_size;
		try {
			xml_page_size = xml_sdf.checked_lookup(node, "page_size");
			auto parsed_page_size_result = sdf_parse_number(xml_sdf.checked_lookup(node, "page_size"), node);
			if (!parsed_page_size_result.second.empty()) {
				std::string err_str = xml_sdf.value_error(node, std::string("Parse error: ") + parsed_page_size_result.second);
				throw std::runtime_error(err_str);
			}
			page_size = parsed_page_size_result.first;
		} catch (std::exception &e) {
			page_size = config.page_sizes()[0];
		}

		bool page_size_valid = std::find(config.page_sizes().begin(), config.page_sizes().end(), page_size) != config.page_sizes().end();
		if (!page_size_valid) {
			std::string err_str = xml_sdf.value_error(node, std::string("page size 0x") + std::to_string(page_size) + " not supported");
			throw std::runtime_error(err_str);
		}

		if (size % page_size != 0) {
			std::string err_str = xml_sdf.value_error(node, std::string("size is not a multiple of the page size"));
			throw std::runtime_error(err_str);
		}

		std::optional<uint64_t> phys_addr;
		auto parsed_phys_addr_result = sdf_parse_number(xml_sdf.checked_lookup(node, "size"), node);
		if (parsed_phys_addr_result.second.empty()) {
			phys_addr = parsed_phys_addr_result.first;
		} else {
			phys_addr = std::nullopt;
		}

		if (phys_addr.has_value() && phys_addr.value() % page_size != 0) {
			std::string err_str = xml_sdf.value_error(node, std::string("phys_addr is not aligned to the page size"));
			throw std::runtime_error(err_str);
		}

		uint64_t page_count = size / page_size;

		return SysMemoryRegion(name, size, from_uint64_to_pagesize(page_size), page_count, phys_addr, node);
	}
};

class SysMap {
public:
	std::string mr;					// 内存区域标识符
	uint64_t vaddr;					// 虚拟地址
	uint8_t perms;					// 权限，以 8 位整数编码
	bool cached;					// 缓存标志
	tinyxml2::XMLElement *element;	// XML文档中的可选位置

public:
	SysMap(const std::string &mr, uint64_t vaddr, uint8_t perms, bool cached,
		tinyxml2::XMLElement* text_pos = nullptr)
		: mr(mr), vaddr(vaddr), perms(perms), cached(cached), element(text_pos) {}

	void print() const {
		std::cout << "SysMap: MR=" << mr
					<< ", VAddr=" << vaddr
					<< ", Permissions=" << static_cast<int>(perms)
					<< ", Cached=" << (cached ? "true" : "false")
					<< (element ? (", Text Position: Line=" + std::to_string(element->GetLineNum())) : ", Text Position: n/a")
					<< std::endl;
	}

	static SysMap from_xml(const XmlSystemDescription &xml_sdf, const tinyxml2::XMLElement *node, const bool allow_setvar, const uint64_t max_vaddr) {
		std::vector<std::string> attrs = { "mr", "vaddr", "perms", "cached" };
		if (allow_setvar) {
			attrs.push_back("setvar_vaddr");
		}
		xml_sdf.check_attributes(node, attrs);

		std::string mr = xml_sdf.checked_lookup(node, "mr");
		uint64_t vaddr;
		auto parsed_result = sdf_parse_number(xml_sdf.checked_lookup(node, "vaddr"), node);
		if (!parsed_result.second.empty()) {
			throw std::runtime_error("Parse error: " + parsed_result.second);
		}
		vaddr = parsed_result.first;

		if (vaddr >= max_vaddr) {
			throw std::runtime_error("vaddr (0x" + std::to_string(vaddr) + ") must be less than 0x" + std::to_string(max_vaddr));
		}

		uint8_t perms;
		const char *xml_perms = node->Attribute("perms");
		if (xml_perms != nullptr) {
			perms = SysMapPermsConverter::from_str(std::string(xml_perms));
		} else {
			// Default to read-write
			perms = static_cast<uint8_t>(SysMapPerms::Read) | static_cast<uint8_t>(SysMapPerms::Write);
		}

		// On all architectures, the kernel does not allow write-only mappings
		if (perms == static_cast<uint8_t>(SysMapPerms::Write)) {
			throw std::runtime_error(std::string(node->Name()) + ": perms must not be 'w', write-only mappings are not allowed");
		}

		bool cached;
		const char *xml_cached = node->Attribute("cached");
		if (xml_cached != nullptr) {  // If attribute exists
			bool value;
			if (str_to_bool(xml_cached, value)) {
				cached = value;
			} else {
				throw std::runtime_error("passive must be 'true' or 'false'");
			}
		} else {
			// Default to cached
			cached = true;
		}

		return SysMap(mr, vaddr, cached, node);
	}
};

class VirtualMachine {
public:
	std::vector<VirtualCpu> vcpus;
	std::string name;
	std::vector<SysMap> maps;
	uint8_t priority;
	uint64_t budget;
	uint64_t period;

	VirtualMachine(const std::string& name, uint8_t priority, uint64_t budget, uint64_t period)
		: name(name), priority(priority), budget(budget), period(period) {}

	void addVcpu(const VirtualCpu& vcpu) {
		vcpus.push_back(vcpu);
	}

	void addMap(const SysMap& map) {
		maps.push_back(map);
	}

	// For debugging purposes
	void printDetails() const {
		std::cout << "VirtualMachine: " << name << "\n"
			<< "Priority: " << static_cast<int>(priority) << "\n"
			<< "Budget: " << budget << "\n"
			<< "Period: " << period << "\n"
			<< "Number of VCPUs: " << vcpus.size() << std::endl;
		for (const auto& cpu : vcpus) {
			std::cout << cpu << std::endl;
		}
	}
};

class ProtectionDomain {
private:
	std::optional<uint64_t> id;
	std::string name;
	uint8_t priority;
	uint64_t budget;
	uint64_t period;
	bool passive;
	uint64_t stack_size;
	bool smc;  // Secure Memory Call or similar
	std::filesystem::path program_image;
	std::vector<SysMap> maps;
	std::vector<SysIrq> irqs;
	std::vector<SysSetVar> setvars;
	std::optional<VirtualMachine> virtual_machine;  // Assuming VM instances are managed via smart pointers
	std::vector<ProtectionDomain> child_pds;
	bool has_children;
	std::optional<size_t> parent;
	const tinyxml2::XMLElement *text_pos;

public:
	ProtectionDomain(
		std::optional<uint64_t> id,
		std::string name,
		uint8_t priority,
		uint64_t budget,
		uint64_t period,
		bool passive,
		uint64_t stack_size,
		bool smc,
		std::filesystem::path program_image,
		std::vector<SysMap> maps,
		std::vector<SysIrq> irqs,
		std::vector<SysSetVar> setvars,
		std::optional<VirtualMachine> virtual_machine,
		std::vector<ProtectionDomain> child_pds,
		bool has_children,
		std::optional<size_t> parent,
		const tinyxml2::XMLElement *text_pos) :
			id(id),
			name(name),
			priority(priority),
			budget(budget),
			period(period),
			passive(passive),
			stack_size(stack_size),
			smc(smc),
			program_image(program_image),
			maps(maps),
			irqs(irqs),
			setvars(setvars),
			virtual_machine(virtual_machine),
			child_pds(child_pds),
			has_children(has_children),
			parent(parent),
			text_pos(text_pos) { }
	
	const std::optional<size_t> get_parent(void) { return parent; }
	void set_parent(size_t idx) { parent = idx; }

	static ProtectionDomain from_xml(const Config &config,
					const XmlSystemDescription &xml_sdf,
					const tinyxml2::XMLElement *element,
					bool is_child) {
		std::vector<std::string> attrs = {
			"name", "priority", "budget", "period", "passive", "stack_size", "smc"
		};

		// If it is a child node, add the 'id' attribute to the vector
		if (is_child) {
			attrs.push_back("id");
		}

		try {
			xml_sdf.check_attributes(element, attrs);
		} catch (std::runtime_error &e) {
			throw e;
		}

		std::string element_name = xml_sdf.checked_lookup(element, "name");

		std::optional<uint64_t> id;
		if (is_child) {
			try {
				std::string id_str = xml_sdf.checked_lookup(element, "id");
				auto parsed_id = sdf_parse_number(id_str, element); // assuming sdf_parse_number returns pair or throws
				
				if (!parsed_id.second.empty()) {
					throw std::runtime_error(parsed_id.second);
				}

				id = parsed_id.first;
			} catch (const std::exception &e) {
				throw; // rethrow to maintain error information
			}
		} else {
			id = {};
		}

		uint64_t budget;
		const char *attr = element->Attribute("budget");
		if (!attr) {
			budget = BUDGET_DEFAULT;
		} else {
			auto parsed_result = sdf_parse_number(attr, element);
			if (!parsed_result.second.empty()) {
				throw std::runtime_error("Parse error: " + parsed_result.second);
			}
			budget = parsed_result.first;
		}

		uint64_t period;
		attr = element->Attribute("period");
		if (!attr) {
			period = budget;
		} else {
			auto parsed_result = sdf_parse_number(attr, element);
			if (!parsed_result.second.empty()) {
				throw std::runtime_error("Parse error: " + parsed_result.second);
			}
			period = parsed_result.first;
		}

		if (budget > period) {
			std::string error_message = "budget (" + std::to_string(budget) + 
						") must be less than, or equal to, period (" 
						+ std::to_string(period) + ")";
			throw std::runtime_error(error_message);
		}

		bool passive;
		const char *xml_passive = element->Attribute("passive");
		if (xml_passive != nullptr) {  // If attribute exists
			bool value;
			if (str_to_bool(xml_passive, value)) {
				passive = value;
			} else {
				throw std::runtime_error("passive must be 'true' or 'false'");
			}
		} else {
			passive = false;  // Default value if attribute is not present
		}

		uint64_t stack_size;
		const char *xml_stack_size = element->Attribute("stack_size");
		if (xml_stack_size != nullptr) {
			auto parsed_result = sdf_parse_number(xml_stack_size, element);
			if (!parsed_result.second.empty()) {
				throw std::runtime_error("Parse error: " + parsed_result.second);
			}
			stack_size = parsed_result.first;
		} else {
			stack_size = PD_DEFAULT_STACK_SIZE;
		}

		bool smc = false;
		const char *xml_smc = element->Attribute("smc");
		if (xml_smc != nullptr) {
			bool value;
			if (str_to_bool(xml_passive, value)) {
				smc = value;
			} else {
				throw std::runtime_error("passive must be 'true' or 'false'");
			}
		}

		if (smc) {
			if (config.arm_smc.has_value()) {
				bool smc_allowed = config.arm_smc.value();  // Get the value from optional if it exists
				if (!smc_allowed) {
					std::string err_str = xml_sdf.value_error(element, std::string("Using SMC support without ARM SMC forwarding support enabled for this platform"));
					throw std::runtime_error(err_str);
				}
			} else {
				std::string err_str = xml_sdf.value_error(element, std::string("ARM SMC forwarding support is not available for this architecture"));
				throw std::runtime_error(err_str);
			}
		}

		if (stack_size < PD_MIN_STACK_SIZE || stack_size > PD_MAX_STACK_SIZE) {
			std::string err_str = "stack size must be between 0x" + std::to_string(PD_MIN_STACK_SIZE) +
								"bytes and 0x" + std::to_string(PD_MAX_STACK_SIZE) + "bytes";
			throw std::runtime_error(err_str);
		}

		if (stack_size % config.page_sizes()[0] != 0) {
			std::string err_str = "stack size must be aligned to the smallest page size, " +
								std::to_string(config.page_sizes()[0]) + "bytes";
			throw std::runtime_error(err_str);
		}

		std::vector<SysMap> maps;
		std::vector<SysIrq> irqs;
		std::vector<SysSetVar> setvars;
		std::vector<ProtectionDomain> child_pds;
		
		std::optional<std::filesystem::path> program_image = std::nullopt;
		std::optional<VirtualMachine> virtual_machine = std::nullopt;

		uint64_t priority;
		const char *xml_priority = element->Attribute("priority");
		if (xml_priority != nullptr) {
			auto parsed_result = sdf_parse_number(xml_priority, element);
			if (!parsed_result.second.empty()) {
				throw std::runtime_error("Parse error: " + parsed_result.second);
			}
			priority = parsed_result.first;
		} else {
			priority = 0;
		}

		if (priority > PD_MAX_PRIORITY) {
			throw std::runtime_error(element_name + ": priority must be between 0 and " + std::to_string(PD_MAX_PRIORITY));
		}

		// const tinyxml2::XMLElement *child = element->FirstChildElement();
		for (const tinyxml2::XMLElement *child = element->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
			std::string tagName = child->Name();
			if (tagName == "program_image") {
				xml_sdf.check_attributes(child, { "path" });
				if (program_image.has_value()) {
					throw std::runtime_error(element_name + "program_image must only be specified once" + std::to_string(__LINE__));
				}
				std::string program_image_path = xml_sdf.checked_lookup(child, "path");
				program_image = std::filesystem::path(program_image_path);
			} else if (tagName == "map") {
				uint64_t map_max_vaddr = config.pd_map_max_vaddr(stack_size);
				SysMap map = SysMap::from_xml(xml_sdf, child, true, map_max_vaddr);

				const char *xml_setvar = child->Attribute("setvar_vaddr");
				if (xml_setvar != nullptr) {
					std::string setvar_addr(xml_setvar);
					for (auto setvar : setvars) {
						if (setvar_addr == setvar.symbol) {
							throw std::runtime_error("setvar on symbol '" + setvar_addr + std::to_string(__LINE__));
						}
					}

					setvars.push_back(
						SysSetVar{
							.symbol = setvar_addr,
							.kind = Vaddr{ map.vaddr }
						}
					);
				}

				maps.push_back(map);
			} else if (tagName == "irq") {
				xml_sdf.check_attributes(child, { "irq", "id", "trigger" });
				uint64_t irq_num = std::atoi(xml_sdf.checked_lookup(child, "irq").c_str());
				int64_t id = std::atoi(xml_sdf.checked_lookup(child, "id").c_str());

				if (id > static_cast<int64_t>(PD_MAX_ID)) {
					throw std::runtime_error("id must be < " + std::to_string(PD_MAX_ID));
				}
				if (id < 0) {
					throw std::runtime_error("id must be >= 0");
				}

				IrqTrigger trigger;
				const char *xml_trigger = child->Attribute("trigger");
				if (xml_trigger != nullptr) {
					std::string trigger_str(xml_trigger);
					if (trigger_str == "level") {
						trigger = IrqTrigger::Level;
					} else if (trigger_str == "edge") {
						trigger = IrqTrigger::Edge;
					} else {
						throw std::runtime_error("trigger must be either 'level' or 'edge'");
					}
				} else {
					trigger = IrqTrigger::Level;
				}

				SysIrq irq = SysIrq(irq_num, static_cast<uint64_t>(id), trigger);
				
				irqs.push_back(irq);
			} else if (tagName == "setvar") {
				xml_sdf.check_attributes(child, { "symbol", "region_paddr" });
				std::string symbol = xml_sdf.checked_lookup(child, "symbol");
				std::string region = xml_sdf.checked_lookup(child, "region_paddr");

				for (auto setvar : setvars) {
					if (symbol == setvar.symbol) {
						throw std::runtime_error("setvar on symbol '" + symbol + "' already exists");
					}
				}

				setvars.push_back(
					SysSetVar {symbol, Paddr{region}}
				);
			} else if (tagName == "protection_domain") {
				child_pds.push_back(ProtectionDomain::from_xml(config, xml_sdf, child, true));
			} else if (tagName == "virtual_machine") {
				if (virtual_machine.has_value()) {
					throw std::runtime_error("virtual_machine must only be specified once");
				}
				throw std::runtime_error("not support virtual machine currently");
				// virtual_machine = VirtualMachine::from_xml();
			} else {
				throw std::runtime_error("Invalid XML element " + std::string(child->Name()) + std::to_string(child->GetLineNum()));
			}
		}

		if (!program_image.has_value()) {
			throw std::runtime_error("Error: missing 'program_image' element on protection_domain: '" + element_name + "'");
		}

		bool has_children = child_pds.empty();

		return ProtectionDomain(
				id,
				element_name,
				static_cast<uint8_t>(priority),
				budget,
				period,
				passive,
				stack_size,
				smc,
				program_image.value(),
				maps,
				irqs,
				setvars,
				virtual_machine,
				child_pds,
				has_children,
				std::nullopt,
				element);
	}

	static std::vector<ProtectionDomain> pd_tree_to_list(const XmlSystemDescription &xml_sdf, const ProtectionDomain &pd, size_t idx) {
		std::vector<uint64_t> child_ids;
		for (auto child_pd : pd.child_pds) {
			uint64_t child_id = child_pd.id.value();
			if (std::find(child_ids.begin(), child_ids.end(), child_id) != child_ids.end()) {
				std::string err_str = xml_sdf.value_error(child_pd.text_pos, "Error: duplicate id");
				throw std::runtime_error(err_str);
			}
			VirtualMachine vm = pd.virtual_machine.value();
			for (auto vcpu : vm.vcpus) {
				if (child_id == vcpu.id) {
					std::string err_str = xml_sdf.value_error(child_pd.text_pos, std::string("Error: duplicate id: ") + std::to_string(child_id) + "clashes with virtual machine vcpu id");
				}
			}
			child_ids.push_back(child_id);
		}

		std::vector<ProtectionDomain> new_child_pds;
		std::vector<ProtectionDomain> child_pds = pd.child_pds;
		for (auto child_pd : child_pds) {
			child_pd.set_parent(idx);
			std::vector<ProtectionDomain> temp_pd;
			temp_pd = ProtectionDomain::pd_tree_to_list(xml_sdf, child_pd, child_pds.size());
			new_child_pds.insert(new_child_pds.end(), temp_pd.begin(), temp_pd.end());
		}

		std::vector<ProtectionDomain> all = { pd };
		all.insert(all.end(), new_child_pds.begin(), new_child_pds.end());

		return all;
	}

	static std::vector<ProtectionDomain> pd_flatten(const XmlSystemDescription &xml_sdf, const std::vector<ProtectionDomain> &pds) {
		std::vector<ProtectionDomain> all_pds;

		for (auto pd : pds) {
			assert(pd.get_parent() == std::nullopt);
			std::vector<ProtectionDomain> temp_pd;
			temp_pd = ProtectionDomain::pd_tree_to_list(xml_sdf, pd, pds.size());
			all_pds.insert(all_pds.end(), temp_pd.begin(), temp_pd.end());
		}

		return all_pds;
	}
};

class SystemDescription {
public:
	std::vector<ProtectionDomain> protection_domains;
	std::vector<SysMemoryRegion> mem_regions;
	std::vector<Channel> channels;

	static SystemDescription parse(std::string &filename, std::string &xml, Config &config) {
		tinyxml2::XMLDocument *doc = new tinyxml2::XMLDocument;
		tinyxml2::XMLError result = doc->Parse(xml.c_str());

		if (result != tinyxml2::XML_SUCCESS) {
			// If parsing failed, construct and return an error message using the filename
			std::string error_message = "Could not parse '" + filename + "': " + doc->ErrorName();
			throw std::runtime_error(error_message);
		}

		XmlSystemDescription xml_sdf(filename, doc);

		std::vector<ProtectionDomain> root_pds;
		std::vector<SysMemoryRegion> mrs;
		std::vector<Channel> channels;

		const tinyxml2::XMLElement *systemNode = xml_sdf.findSystemNode();
		if (systemNode) {
			std::cout << "Found 'system' node: " << systemNode->Name() << std::endl;
		} else {
			std::cout << "System node not found in the XML document." << std::endl;
				std::string error_message = "Could not find system node";
				throw std::runtime_error(error_message);
		}

		const tinyxml2::XMLNode *root = doc->RootElement();
		if (xml_sdf.checkNoText(root)) {
			std::cout << "No non-whitespace text found in the XML document." << std::endl;
		} else {
			std::cerr << "There is non-whitespace text in the XML document." << std::endl;
		}

		// Channels cannot be parsed immediately as they refer to a particular protection domain
		// via an index in the list of PDs. This means that we have to parse all PDs first and
		// then parse the channels.
		std::vector<const tinyxml2::XMLElement *> channel_nodes;

		for (const tinyxml2::XMLElement *child = root->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
			const char *child_name = child->Name();

			if (strcmp(child_name, "protection_domain") == 0) {
				try {
					root_pds.push_back(ProtectionDomain::from_xml(config, xml_sdf, child, false));
				} catch (std::exception &e) {
					throw std::runtime_error(std::string("Failed to parse protection domain: ") + e.what());
				}
			} else if (strcmp(child_name, "channel") == 0) {
				channel_nodes.push_back(child);
			} else if (strcmp(child_name, "memory_region") == 0) {
				try {
					mrs.push_back(SysMemoryRegion::from_xml(config, xml_sdf, child));
				} catch (std::exception &e) {
					throw std::runtime_error(std::string("Failed to parse memory region: ") + e.what());
				}
			} else {
				std::string err_str = xml_sdf.value_error(child, std::string("Invalid XML element '") + child_name + "': " + child->Name());
				throw std::runtime_error(err_str);
			}
		}

		std::vector<ProtectionDomain> pds = ProtectionDomain::pd_flatten(xml_sdf, root_pds);

		return { root_pds, mrs, channels };
	}
};

#endif /* SDF_HPP */
