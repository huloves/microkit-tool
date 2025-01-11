#include "sel4.hpp"
#include "elf.hpp"

std::vector<uint8_t> Region::data(ElfFile& elf) const {
	const char *cdata = elf.get_elf()->segments[segment_idx]->get_data();
	size_t length = std::strlen(cdata) + 1; // +1 to include null terminator
	return std::vector<uint8_t>(cdata, cdata + length);
}

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

	for (auto& region : this->regions) {
		if (size <= region.size() && region.base >= lower_bound) {
			region_to_remove = &region;
			break;
		}
	}

	if (region_to_remove != nullptr) {
		uint64_t allocation_base = region_to_remove->base;
		this->remove_region(region_to_remove->base, region_to_remove->base + size);
		return allocation_base;
	} else {
		std::stringstream error;
		error << "Unable to allocate 0x" << std::hex << size << " bytes from lower bound 0x"
			<< std::hex << lower_bound;
		throw std::runtime_error(error.str());
	}
}

std::optional<uint64_t> DisjointMemoryRegion::get_base_from_end(uint64_t size, uint64_t align) {
	std::optional<uint64_t> base = std::nullopt;
	for (auto it = this->regions.rbegin(); it != this->regions.rend(); ++it) {
		uint64_t start = util::round_down(it->end - size, 1ULL << align);
		if (start >= it->base) {
			base = start;
			break;
		}
	}
	return base;
}

std::vector<MemoryRegion> DisjointMemoryRegion::aligned_power_of_two_regions(uint64_t max_bits) {
	std::vector<MemoryRegion> aligned_regions;
	for (auto region : this->regions) {
		std::vector<MemoryRegion> subregions = region.aligned_power_of_two_regions(max_bits);
		aligned_regions.insert(aligned_regions.end(), subregions.begin(), subregions.end());
	}
	return aligned_regions;
}

std::optional<uint64_t> Config::fixed_size_bits(ObjectType obj_type) const {
	switch (obj_type) {
	case ObjectType::Tcb:
		if (this->arch == Arch::Aarch64) {
			return std::make_optional(11);
		} else if (this->arch == Arch::Riscv64) {
			return this->fpu ? std::make_optional(11) : std::make_optional(10);
		}
		break;
	case ObjectType::Endpoint:
		return std::make_optional(4);
	case ObjectType::Notification:
		return std::make_optional(6);
	case ObjectType::Reply:
		return std::make_optional(5);
	case ObjectType::VSpace:
		if (this->arch == Arch::Aarch64) {
			if (this->hypervisor) {
				if (this->arm_pa_size_bits.has_value()) {
					switch (this->arm_pa_size_bits.value()) {
					case 40:
						return std::make_optional(13);
					case 44:
						return std::make_optional(12);
					default:
						throw std::runtime_error(
							"Unexpected ARM PA size bits when determining VSpace size bits"
						);
					}
				}
			} else {
				return std::make_optional(12);
			}
		} else if (this->arch == Arch::Riscv64) {
			return std::make_optional(12);
		}
		break;
	case ObjectType::PageTable:
		return std::make_optional(12);
	case ObjectType::HugePage:
		return std::make_optional(30);
	case ObjectType::LargePage:
		return std::make_optional(21);
	case ObjectType::SmallPage:
		return std::make_optional(12);
	case ObjectType::Vcpu:
		if (this->arch == Arch::Aarch64) {
		return std::make_optional(12);
		} else {
		throw std::runtime_error("Unexpected architecture asking for vCPU size bits");
		}
	default:
		return std::nullopt;
	}
	return std::nullopt;
}
