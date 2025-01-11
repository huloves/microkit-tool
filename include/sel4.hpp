#ifndef __SEL4_HPP
#define __SEL4_HPP

#include <iostream>
#include <optional>
#include <algorithm>
#include <nlohmann/json.hpp>

#include "util.hpp"

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

enum class Right {
	None = 0x0,
	Write = 0x1,
	Read = 0x2,
	Grant = 0x4,
	GrantReply = 0x8,
	All = 0xf,
};

enum class IrqTrigger {
	Level = 0,
	Edge = 1,
};

enum class ObjectType {
	Untyped,
	Tcb,
	Endpoint,
	Notification,
	CNode,
	SchedContext,
	Reply,
	HugePage,
	VSpace,
	SmallPage,
	LargePage,
	PageTable,
	Vcpu,
};

enum class InvocationLabel {
	// Untyped
	UntypedRetype,
	// TCB
	TCBReadRegisters,
	TCBWriteRegisters,
	TCBCopyRegisters,
	TCBConfigure,
	TCBSetPriority,
	TCBSetMCPriority,
	TCBSetSchedParams,
	TCBSetTimeoutEndpoint,
	TCBSetIPCBuffer,
	TCBSetSpace,
	TCBSuspend,
	TCBResume,
	TCBBindNotification,
	TCBUnbindNotification,
	TCBSetTLSBase,
	// CNode
	CNodeRevoke,
	CNodeDelete,
	CNodeCancelBadgedSends,
	CNodeCopy,
	CNodeMint,
	CNodeMove,
	CNodeMutate,
	CNodeRotate,
	// IRQ
	IRQIssueIRQHandler,
	IRQAckIRQ,
	IRQSetIRQHandler,
	IRQClearIRQHandler,
	// Domain
	DomainSetSet,
	// Scheduling
	SchedControlConfigureFlags,
	SchedContextBind,
	SchedContextUnbind,
	SchedContextUnbindObject,
	SchedContextConsume,
	SchedContextYieldTo,
	// ARM VSpace
	ARMVSpaceCleanData,
	ARMVSpaceInvalidateData,
	ARMVSpaceCleanInvalidateData,
	ARMVSpaceUnifyInstruction,
	// ARM SMC
	ARMSMCCall,
	// ARM Page table
	ARMPageTableMap,
	ARMPageTableUnmap,
	// ARM Page
	ARMPageMap,
	ARMPageUnmap,
	ARMPageCleanData,
	ARMPageInvalidateData,
	ARMPageCleanInvalidateData,
	ARMPageUnifyInstruction,
	ARMPageGetAddress,
	// ARM Asid
	ARMASIDControlMakePool,
	ARMASIDPoolAssign,
	// ARM vCPU
	ARMVCPUSetTCB,
	ARMVCPUInjectIRQ,
	ARMVCPUReadReg,
	ARMVCPUWriteReg,
	ARMVCPUAckVppi,
	// ARM IRQ
	ARMIRQIssueIRQHandlerTrigger,
	// RISC-V Page Table
	RISCVPageTableMap,
	RISCVPageTableUnmap,
	// RISC-V Page
	RISCVPageMap,
	RISCVPageUnmap,
	RISCVPageGetAddress,
	// RISC-V ASID
	RISCVASIDControlMakePool,
	RISCVASIDPoolAssign,
	// RISC-V IRQ
	RISCVIRQIssueIRQHandlerTrigger,
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

	std::optional<uint64_t> fixed_size_bits(ObjectType obj_type) const ;
};

// 基类：所有调用参数的泛型类型
class InvocationArgs {
public:
	virtual InvocationLabel to_label(const Config& config) const = 0;
	virtual std::string to_label_string(const Config& config) const = 0;
	virtual ~InvocationArgs() = default;
};

// UntypedRetype 参数的具体类
class UntypedRetypeArgs : public InvocationArgs {
public:
	uint64_t untyped;
	ObjectType object_type;
	uint64_t size_bits;
	uint64_t root;
	uint64_t node_index;
	uint64_t node_depth;
	uint64_t node_offset;
	uint64_t num_objects;

	UntypedRetypeArgs(uint64_t untyped, ObjectType object_type, uint64_t size_bits,
			uint64_t root, uint64_t node_index, uint64_t node_depth,
			uint64_t node_offset, uint64_t num_objects)
		: untyped(untyped), object_type(object_type), size_bits(size_bits), 
		root(root), node_index(node_index), node_depth(node_depth), 
		node_offset(node_offset), num_objects(num_objects) {}
	
	InvocationLabel to_label(const Config& config) const override {
        return InvocationLabel::UntypedRetype;
    }

	std::string to_label_string(const Config& config) const override {
        return std::string("UntypedRetype");
    }
};

// TcbSetSchedParams 参数的具体类
class TcbSetSchedParams : public InvocationArgs {
public:
	uint64_t tcb;
	uint64_t authority;
	uint64_t mcp;
	uint64_t priority;
	uint64_t sched_context;
	uint64_t fault_ep;

	TcbSetSchedParams(uint64_t tcb, uint64_t authority, uint64_t mcp, uint64_t priority,
			uint64_t sched_context, uint64_t fault_ep)
		: tcb(tcb), authority(authority), mcp(mcp), priority(priority),
		sched_context(sched_context), fault_ep(fault_ep) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBSetSchedParams;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBSetSchedParams");
    }
};

// TcbSetSpace 类型具体定义
class TcbSetSpace : public InvocationArgs {
public:
	uint64_t tcb;
	uint64_t fault_ep;
	uint64_t cspace_root;
	uint64_t cspace_root_data;
	uint64_t vspace_root;
	uint64_t vspace_root_data;

	TcbSetSpace(uint64_t tcb, uint64_t fault_ep, uint64_t cspace_root, uint64_t cspace_root_data,
			uint64_t vspace_root, uint64_t vspace_root_data)
		: tcb(tcb), fault_ep(fault_ep), cspace_root(cspace_root),
		cspace_root_data(cspace_root_data), vspace_root(vspace_root),
		vspace_root_data(vspace_root_data) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBSetSpace;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBSetSpace");
    }
};

// TcbSetIpcBuffer 类定义
class TcbSetIpcBuffer : public InvocationArgs {
public:
	uint64_t tcb;
	uint64_t buffer;
	uint64_t buffer_frame;

	TcbSetIpcBuffer(uint64_t tcb, uint64_t buffer, uint64_t buffer_frame)
		: tcb(tcb), buffer(buffer), buffer_frame(buffer_frame) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBSetIPCBuffer;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBSetIPCBuffer");
    }
};

// TcbResume 类定义
class TcbResume : public InvocationArgs {
public:
	uint64_t tcb;  // Thread Control Block 指针

	explicit TcbResume(uint64_t tcb) : tcb(tcb) {}

	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBResume;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBResume");
    }
};

// TcbWriteRegisters 类定义
class TcbWriteRegisters : public InvocationArgs {
public:
	uint64_t tcb;                 // Thread Control Block 指针
	bool resume;                  // 是否在写入寄存器后恢复运行
	uint8_t arch_flags;           // 架构特定标志
	uint64_t count;               // 寄存器数量
	std::vector<std::pair<std::string, uint64_t>> regs;  // 存储寄存器名和对应的值

	TcbWriteRegisters(uint64_t tcb, bool resume, uint8_t arch_flags, std::vector<std::pair<std::string, uint64_t>> regs)
		: tcb(tcb), resume(resume), arch_flags(arch_flags), regs(std::move(regs)) {
		count = regs.size();
	}

	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBWriteRegisters;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBWriteRegisters");
    }
};

class TcbBindNotification : public InvocationArgs {
public:
	uint64_t tcb;          // Thread Control Block address
	uint64_t notification; // Notification identifier

	TcbBindNotification(uint64_t tcb, uint64_t notification)
		: tcb(tcb), notification(notification) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::TCBBindNotification;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("TCBBindNotification");
    }
};

class AsidPoolAssign : public InvocationArgs {
public:
	uint64_t asid_pool;
	uint64_t vspace;

	AsidPoolAssign(uint64_t asid_pool, uint64_t vspace)
		: asid_pool(asid_pool), vspace(vspace) {}
	
	InvocationLabel to_label(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return InvocationLabel::ARMASIDPoolAssign;
		case Arch::Riscv64: return InvocationLabel::RISCVASIDPoolAssign;
		}
	}

	std::string to_label_string(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return std::string("ARMASIDPoolAssign");
		case Arch::Riscv64: return std::string("RISCVASIDPoolAssign");
		}
    }
};

class IrqControlGetTrigger : public InvocationArgs {
public:
	uint64_t irq_control;
	uint64_t irq;
	IrqTrigger trigger;
	uint64_t dest_root;
	uint64_t dest_index;
	uint64_t dest_depth;

	InvocationLabel to_label(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return InvocationLabel::ARMIRQIssueIRQHandlerTrigger;
		case Arch::Riscv64: return InvocationLabel::RISCVIRQIssueIRQHandlerTrigger;
		}
	}

	std::string to_label_string(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return std::string("ARMIRQIssueIRQHandlerTrigger");
		case Arch::Riscv64: return std::string("RISCVIRQIssueIRQHandlerTrigger");
		}
    }
};

class IrqHandlerSetNotification : public InvocationArgs {
public:
	uint64_t irq_handler;
	uint64_t notification;

	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::IRQSetIRQHandler;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("IRQSetIRQHandler");
    }
};

class PageTableMap : public InvocationArgs {
public:
	uint64_t page_table;
	uint64_t vspace;
	uint64_t vaddr;
	uint64_t attr;

	InvocationLabel to_label(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return InvocationLabel::ARMPageTableMap;
		case Arch::Riscv64: return InvocationLabel::RISCVPageTableMap;
		}
	}

	std::string to_label_string(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return std::string("ARMPageTableMap");
		case Arch::Riscv64: return std::string("RISCVPageTableMap");
		}
    }
};

class PageMap : public InvocationArgs {
public:
	uint64_t page;
	uint64_t vspace;
	uint64_t vaddr;
	uint64_t rights;
	uint64_t attr;

	InvocationLabel to_label(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return InvocationLabel::ARMPageMap;
		case Arch::Riscv64: return InvocationLabel::RISCVPageMap;
		}
	}

	std::string to_label_string(const Config& config) const override {
		switch (config.arch) {
		case Arch::Aarch64: return std::string("ARMPageMap");
		case Arch::Riscv64: return std::string("RISCVPageMap");
		}
    }
};

class CnodeCopy : public InvocationArgs {
public:
	uint64_t cnode;
	uint64_t dest_index;
	uint64_t dest_depth;
	uint64_t src_root;
	uint64_t src_obj;
	uint64_t src_depth;
	uint64_t rights;

	CnodeCopy(uint64_t cnode, uint64_t dest_index, uint64_t dest_depth, uint64_t src_root, uint64_t src_obj, uint64_t src_depth, uint64_t rights)
		: cnode(cnode), dest_index(dest_index), dest_depth(dest_depth), src_root(src_root),
		src_obj(src_obj), src_depth(src_depth), rights(rights) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::CNodeCopy;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("CNodeCopy");
    }
};

class CnodeMint : public InvocationArgs {
public:
	uint64_t cnode;
	uint64_t dest_index;
	uint64_t dest_depth;
	uint64_t src_root;
	uint64_t src_obj;
	uint64_t src_depth;
	uint64_t rights;
	uint64_t badge;

	CnodeMint(uint64_t cnode, uint64_t dest_index, uint64_t dest_depth, uint64_t src_root,
		uint64_t src_obj, uint64_t src_depth, uint64_t rights, uint64_t badge)
		: cnode(cnode), dest_index(dest_index), dest_depth(dest_depth), src_root(src_root),
		src_obj(src_obj), src_depth(src_depth), rights(rights), badge(badge) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::CNodeMint;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("CNodeMint");
    }
};

class SchedControlConfigureFlags : public InvocationArgs {
public:
	uint64_t sched_control;
	uint64_t sched_context;
	uint64_t budget;
	uint64_t period;
	uint64_t extra_refills;
	uint64_t badge;
	uint64_t flags;

	SchedControlConfigureFlags(uint64_t schedControl, uint64_t schedContext, uint64_t budget,
				uint64_t period, uint64_t extraRefills, uint64_t badge, uint64_t flags)
		: sched_control(schedControl), sched_context(schedContext), budget(budget),
		period(period), extra_refills(extraRefills), badge(badge), flags(flags) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::SchedControlConfigureFlags;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("SchedControlConfigureFlags");
    }
};

class ArmVcpuSetTcb : public InvocationArgs {
public:
    uint64_t vcpu;
    uint64_t tcb;

    ArmVcpuSetTcb(uint64_t vcpu, uint64_t tcb)
        : vcpu(vcpu), tcb(tcb) {}
	
	InvocationLabel to_label(const Config& config) const override {
		return InvocationLabel::ARMVCPUSetTCB;
	}

	std::string to_label_string(const Config& config) const override {
        return std::string("ARMVCPUSetTCB");
    }
};

class Invocation {
public:
	InvocationLabel label;
	uint32_t label_raw;
	std::unique_ptr<InvocationArgs> args;
	std::optional<std::pair<uint32_t, std::shared_ptr<InvocationArgs>>> repeat;

public:
	// 构造函数，初始化InvocationArgs
	explicit Invocation(InvocationLabel label, uint32_t label_new, std::unique_ptr<InvocationArgs> args)
		: label(label), label_raw(label_new), args(std::move(args)) {}

	// 设置repeat的函数
	void set_repeat(uint32_t count, std::shared_ptr<InvocationArgs> repeat_args) {
		repeat.emplace(count, repeat_args);
	}

	static uint32_t get_label_raw(const Config& config, InvocationLabel label, InvocationArgs &args) {
		// Convert the enum value to string (assume you have a function for this)
		std::string label_str = args.to_label_string(config);

		// Access and convert the raw label
		if (config.invocations_labels.contains(label_str) && config.invocations_labels[label_str].is_number_unsigned()) {
			return config.invocations_labels[label_str].get<uint32_t>();
		} else {
			throw std::runtime_error("Label raw value is not available or not a valid unsigned number.");
		}
	}

	Invocation(const Config& config, std::unique_ptr<InvocationArgs> args)
		: label(args->to_label(config)),
		label_raw(get_label_raw(config, label, *args)),
		args(std::move(args)),
		repeat(std::nullopt) {}
};

class ElfFile;
class Region {
public:
	std::string name;
	uint64_t addr;
	uint64_t size;
	size_t segment_idx;

	Region(const std::string& name, uint64_t addr, uint64_t size, size_t segment_idx)
		: name(name), addr(addr), size(size), segment_idx(segment_idx) {}
	
	std::vector<uint8_t> data(ElfFile& elf) const;

	friend std::ostream& operator<<(std::ostream& os, const Region& region) {
		return os << "<Region name=" << region.name
			<< " addr=0x" << std::hex << region.addr
			<< " size=" << std::dec << region.size << ">";
	}
};

class MemoryRegion {
public:
	/// Note: base is inclusive, end is exclusive
	/// MemoryRegion(1, 5) would have a size of 4
	/// and cover [1, 2, 3, 4]
	uint64_t base;
	uint64_t end;

	MemoryRegion() : base(0), end(0) {}
	MemoryRegion(uint64_t base, uint64_t end) : base(base), end(end) {}

	uint64_t size(void) const {
		return end - base;
	}

	std::vector<MemoryRegion> aligned_power_of_two_regions(uint64_t max_bits) {
		std::vector<MemoryRegion> regions;
		uint64_t base = this->base;
		uint64_t bits;
		while (base != this->end) {
			uint64_t size = this->end - base;
			uint64_t size_bits = util::msb(size);
			if (base == 0) {
				bits = size_bits;
			} else {
				bits = std::min(size_bits, util::lsb(base));
			}

			if (bits > max_bits) {
				bits = max_bits;
			}
			uint64_t sz = 1ULL << bits;
			regions.push_back(MemoryRegion(base, base + sz));
			base += sz;
		}

		return regions;
	}
};

class DisjointMemoryRegion {
private:
	std::vector<MemoryRegion> regions;

	void check(void) const; // Ensures regions are sorted and non-overlapping

public:
	DisjointMemoryRegion(void) {}
	void insert_region(uint64_t base, uint64_t end);
	void remove_region(uint64_t base, uint64_t end);
	uint64_t allocate_from(uint64_t size, uint64_t lower_bound);
	std::optional<uint64_t> get_base_from_end(uint64_t size, uint64_t align);
	std::vector<MemoryRegion> aligned_power_of_two_regions(uint64_t max_bits);
};

class UntypedObject {
public:
	uint64_t cap;
	MemoryRegion region;
	bool is_device;

public:
	UntypedObject(uint64_t cap, MemoryRegion region, bool is_device)
		: cap(cap), region(region), is_device(is_device) {}
	
	uint64_t getCap() const {
		return cap;
	}

	MemoryRegion getRegion() const {
		return region;
	}

	bool getIsDevice() const {
		return is_device;
	}

	uint64_t base() const {
		return region.base;
	}

	uint64_t end() const {
		return region.end;
	}

	uint64_t sizeBits() const {
		return util::lsb(region.size());
	}
};

class KernelAllocation {
public:
	uint64_t untyped_cap_address;  // FIXME: possibly this is an object, not an int?
	uint64_t phys_addr;

	// Default constructor
	KernelAllocation(uint64_t cap_address = 0, uint64_t physical_address = 0)
		: untyped_cap_address(cap_address), phys_addr(physical_address) {}
};

class UntypedAllocator {
public:
	UntypedObject untyped_object;
	uint64_t allocation_point;
	std::vector<KernelAllocation> allocations;

public:
	// Constructor
	UntypedAllocator(const UntypedObject& untyped_object, uint64_t allocation_point, const std::vector<KernelAllocation>& allocations)
		: untyped_object(untyped_object), allocation_point(allocation_point), allocations(allocations) {}

	// Accessor methods
	uint64_t base() const {
		return untyped_object.region.base;
	}

	uint64_t end() const {
		return untyped_object.region.end;
	}
};

struct BootInfo {
public:
	uint64_t fixed_cap_count;
	uint64_t sched_control_cap;
	uint64_t paging_cap_count;
	uint64_t page_cap_count;
	std::vector<UntypedObject> untyped_objects;
	uint64_t first_available_cap;
};

class ObjectAllocator {
private:
	uint64_t allocation_idx;
	std::vector<UntypedAllocator> untyped;

public:
	// Constructor from BootInfo, assuming BootInfo and UntypedObject classes are defined
	explicit ObjectAllocator(const BootInfo& kernel_boot_info) : allocation_idx(0) {
		for (const auto& untyped_object : kernel_boot_info.untyped_objects) {
			if (untyped_object.is_device) {
				continue; // Skip device memory as per Rust code
			}
			untyped.emplace_back(untyped_object, 0, std::vector<KernelAllocation>());
		}
	}

	// Allocate a single allocation
	KernelAllocation alloc(uint64_t size) {
		return alloc_n(size, 1);
	}

	// Allocate n units of the given size
	KernelAllocation alloc_n(uint64_t size, uint64_t count) {
		assert(util::is_power_of_two(size));
		assert(count > 0);

		for (auto& utAllocator : untyped) {
			uint64_t start = util::round_up(utAllocator.base() + utAllocator.allocation_point, size);
			if (start + (count * size) <= utAllocator.end()) {
				utAllocator.allocation_point = (start - utAllocator.base()) + (count * size);
				++allocation_idx;
				KernelAllocation allocation(utAllocator.untyped_object.cap, start);
				utAllocator.allocations.push_back(allocation);
				return allocation;
			}
		}

		throw std::runtime_error("Can't allocate memory - no space available.");
	}
};

class Object {
public:
	ObjectType object_type; // Type of kernel object
	uint64_t cap_addr;      // Capability address (example purpose)
	uint64_t phys_addr;     // Physical memory address of the kernel object

	Object(ObjectType type, uint64_t capAddr, uint64_t physAddr)
		: object_type(type), cap_addr(capAddr), phys_addr(physAddr) {}
};

#endif /* __SEL4_HPP */
