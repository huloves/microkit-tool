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

class ObjectType {
	enum Type {
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

private:
	Type value;

public:
	ObjectType(Type v) : value(v) {}
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

// 基类：所有调用参数的泛型类型
class InvocationArgs {
public:
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
};

// TcbSetIpcBuffer 类定义
class TcbSetIpcBuffer : public InvocationArgs {
public:
	uint64_t tcb;
	uint64_t buffer;
	uint64_t buffer_frame;

	TcbSetIpcBuffer(uint64_t tcb, uint64_t buffer, uint64_t buffer_frame)
		: tcb(tcb), buffer(buffer), buffer_frame(buffer_frame) {}
};

// TcbResume 类定义
class TcbResume : public InvocationArgs {
public:
	uint64_t tcb;  // Thread Control Block 指针

	explicit TcbResume(uint64_t tcb) : tcb(tcb) {}
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
};

class TcbBindNotification : public InvocationArgs {
public:
	uint64_t tcb;          // Thread Control Block address
	uint64_t notification; // Notification identifier

	TcbBindNotification(uint64_t tcb, uint64_t notification)
		: tcb(tcb), notification(notification) {}
};

class AsidPoolAssign : public InvocationArgs {
public:
	uint64_t asid_pool;
	uint64_t vspace;

	AsidPoolAssign(uint64_t asid_pool, uint64_t vspace)
		: asid_pool(asid_pool), vspace(vspace) {}
};

class IrqControlGetTrigger : public InvocationArgs {
public:
	uint64_t irq_control;
	uint64_t irq;
	IrqTrigger trigger;
	uint64_t dest_root;
	uint64_t dest_index;
	uint64_t dest_depth;
};

class IrqHandlerSetNotification : public InvocationArgs {
public:
	uint64_t irq_handler;
	uint64_t notification;
};

class PageTableMap : public InvocationArgs {
public:
	uint64_t page_table;
	uint64_t vspace;
	uint64_t vaddr;
	uint64_t attr;
};

class PageMap : public InvocationArgs {
public:
	uint64_t page;
	uint64_t vspace;
	uint64_t vaddr;
	uint64_t rights;
	uint64_t attr;
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
};

class ArmVcpuSetTcb : public InvocationArgs {
public:
    uint64_t vcpu;
    uint64_t tcb;

    ArmVcpuSetTcb(uint64_t vcpu, uint64_t tcb)
        : vcpu(vcpu), tcb(tcb) {}
};

class Invocation {
public:
	InvocationLabel label;
	uint32_t label_new;
	InvocationArgs args;
	std::optional<std::pair<uint32_t, InvocationArgs>> repeat;
};

class Region {
public:
	std::string name;
	uint64_t addr;
	uint64_t size;
	size_t segment_idx;

	Region(const std::string& name, uint64_t addr, uint64_t size, size_t segment_idx)
		: name(name), addr(addr), size(size), segment_idx(segment_idx) {}
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
};

void DisjointMemoryRegion::check() const {
	uint64_t last_end = 0; // Using 0 instead of Option in Rust. Assume no region starts at 0.
	bool is_first_region = true;

	for (const auto &region : regions) {
		if (!is_first_region) {
			assert(region.base >= last_end);
		}
		is_first_region = false;
		last_end = region.end;
	}
}

void DisjointMemoryRegion::insert_region(uint64_t base, uint64_t end) {
	size_t insert_idx = regions.size(); // Start with assumption that region is to be inserted at the end.

	for (size_t idx = 0; idx < regions.size(); ++idx) {
		if (end <= regions[idx].base) {
			insert_idx = idx;
			break;
		}
	}

	// FIXME: Should extend here if adjacent rather than inserting now
	regions.insert(regions.begin() + insert_idx, MemoryRegion(base, end));
	this->check();
}

void DisjointMemoryRegion::remove_region(uint64_t base, uint64_t end) {
	int maybe_idx = -1;
	for (size_t i = 0; i < regions.size(); ++i) {
		if (base >= regions[i].base && end <= regions[i].end) {
			maybe_idx = i;
			break;
		}
	}
	if (maybe_idx == -1) {
		throw std::runtime_error("Internal error: attempting to remove region [0x" + std::to_string(base) + "-0x" + std::to_string(end) + ") that is not currently covered.");
	}

	MemoryRegion region = regions[maybe_idx];

	if (region.base == base && region.end == end) {
		// Covers exactly, so just remove
		regions.erase(regions.begin() + maybe_idx);
	} else if (region.base == base) {
		// Trim the start of the region
		regions[maybe_idx] = MemoryRegion(end, region.end);
	} else if (region.end == end) {
		// Trim the end of the region
		regions[maybe_idx] = MemoryRegion(region.base, base);
	} else {
		// Splitting the region into two
		regions[maybe_idx] = MemoryRegion(region.base, base);
		regions.insert(regions.begin() + maybe_idx + 1, MemoryRegion(end, region.end));
	}

	this->check();  // Ensures regions are correctly configured after modification.
}

uint64_t DisjointMemoryRegion::allocate_from(uint64_t size, uint64_t lower_bound) {
	MemoryRegion* region_to_remove = nullptr;

	for (auto& region : regions) {
		if (size <= region.size() && region.base >= lower_bound) {
			region_to_remove = &region;
			break;
		}
	}

	if (region_to_remove != nullptr) {
		uint64_t allocation_base = region_to_remove->base;
		remove_region(region_to_remove->base, size);
		return allocation_base;
	} else {
		std::stringstream error;
		error << "Unable to allocate 0x" << std::hex << size << " bytes from lower bound 0x"
			<< std::hex << lower_bound;
		throw std::runtime_error(error.str());
	}
}

class UntypedObject {
public:
	uint64_t cap;
	MemoryRegion region;
	bool is_device;
};

class BootInfo {
public:
	uint64_t fixed_cap_count;
	uint64_t sched_control_cap;
	uint64_t paging_cap_count;
	uint64_t page_cap_count;
	std::vector<UntypedObject> untyped_objects;
	uint64_t first_available_cap;

// public:
	// static BootInfo emulate_kernel_boot(
	// 		Config &config,
	// 		ElfFile &kernel_elf,
	// 		MemoryRegion &initial_task_phys_region,
	// 		MemoryRegion &initial_task_virt_region,
	// 		MemoryRegion &reserved_region) {
	// 	assert(initial_task_phys_region.size() = initial_task_virt_region.size());
	// }
};

class Object {
public:
	ObjectType object_type; // Type of kernel object
	uint64_t cap_addr;      // Capability address (example purpose)
	uint64_t phys_addr;     // Physical memory address of the kernel object

	Object(ObjectType type, uint64_t capAddr, uint64_t physAddr)
		: object_type(type), cap_addr(capAddr), phys_addr(physAddr) {}
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
