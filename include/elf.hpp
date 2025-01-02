#ifndef __ELF_HPP
#define __ELF_HPP

#include <iostream>
#include <filesystem>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// #include <libelf.h>
// #include <gelf.h>

#include "util.hpp"
#include "elfio/elfio.hpp"

// using namespace ELFIO;

class ElfFile {
private:
	std::filesystem::path elfPath;
	ELFIO::elfio *elf;

private:
	// 查找符号表段
	ELFIO::section *find_symbol_section() const {
		for (const auto& sec : elf->sections) {
			if (sec->get_type() == ELFIO::SHT_SYMTAB || sec->get_type() == ELFIO::SHT_DYNSYM) {
				// 返回找到的第一个符号表
				return sec.get();
			}
		}
		throw std::runtime_error("No symbol table found");
	}

public:
	ElfFile() {}

	ELFIO::elfio *get_elf(void) { return elf; };
	std::filesystem::path get_elf_path(void) const { return elfPath; }

	explicit ElfFile(const std::filesystem::path &elf_path) : elfPath(elf_path) {
		elf = new ELFIO::elfio();
		if (!elf->load(elf_path.string())) {
			throw std::runtime_error("Failed to load ELF file: " + elf_path.string());
		}
	}

	static ElfFile from_path(const std::filesystem::path &path) {
		try {
			ElfFile elfFile(path);
			return elfFile;
		} catch (...) { // 捕获所有可能的异常
			throw; // 重新抛出异常供上层处理
		}
	}

	size_t count_loadable_segments() const {
		size_t loadable_count = 0;
		const auto &segments = elf->segments;

		for (size_t i = 0; i < segments.size(); ++i) {
			if (segments[i]->get_type() == ELFIO::PT_LOAD) {
				loadable_count++;
			}
		}

		return loadable_count;
	}

	/// Determine the physical memory regions for an ELF file with a given
	/// alignment.
	///
	/// The returned region shall be extended (if necessary) so that the start
	/// and end are congruent with the specified alignment (usually a page size).
	std::vector<MemoryRegion> phys_mem_regions_from_elf(uint64_t alignment) const {
		assert(alignment > 0);
		std::vector<MemoryRegion> regions;

		for (const auto& segment : elf->segments) {
			if (segment->get_type() == ELFIO::PT_LOAD) {  // Check if segment is loadable
				uint64_t phys_addr = segment->get_physical_address();
				uint64_t data_len = segment->get_memory_size();  // Segment data length
				MemoryRegion region(util::round_down(phys_addr, alignment),
						    util::round_up(phys_addr + data_len, alignment));
				regions.push_back(region);
			}
		}

		return regions;
	}

	/// Determine a single physical memory region for an ELF.
	///
	/// Works as per phys_mem_regions_from_elf, but checks the ELF has a single
	/// segment, and returns the region covering the first segment.
	MemoryRegion phys_mem_region_from_elf(uint64_t alignment) const {
		assert(alignment > 0);
		auto regions = phys_mem_regions_from_elf(alignment);
		if (regions.size() != 1) {
			throw std::runtime_error("Expected exactly one loadable segment");
		}
		return regions[0];
	}

	/// Determine the virtual memory regions for an ELF file with a given
	/// alignment.

	/// The returned region shall be extended (if necessary) so that the start
	/// and end are congruent with the specified alignment (usually a page size).
	std::vector<MemoryRegion> virt_mem_regions_from_elf(uint64_t alignment) const {
		assert(alignment > 0); // Ensure alignment is not zero
		
		std::vector<MemoryRegion> memory_regions;
		const ELFIO::segment* seg;

		// Iterate over all segments
		for (int i = 0; i < elf->segments.size(); ++i) {
			seg = elf->segments[i];
			if (seg->get_type() == ELFIO::PT_LOAD) { // Check if the segment is loadable
				uint64_t virt_addr = seg->get_virtual_address();
				uint64_t mem_size = seg->get_memory_size();
				uint64_t start = util::round_down(virt_addr, alignment);
				uint64_t end = util::round_up(virt_addr + mem_size, alignment);

				memory_regions.emplace_back(start, end);
			}
		}

		return memory_regions;
	}

	MemoryRegion virt_mem_region_from_elf(uint64_t alignment) const {
		assert(alignment > 0);
		assert(std::count_if(elf->segments.begin(), elf->segments.end(), [](const std::unique_ptr<ELFIO::segment>& seg) {
			return seg->get_type() == ELFIO::PT_LOAD; }) == 1);

		return virt_mem_regions_from_elf(alignment)[0];
	}

	// 查找符号
	std::optional<std::pair<uint64_t, uint64_t>> find_symbol(const std::string& variable_name) const {
		// 检索所有符号表
		const ELFIO::symbol_section_accessor symbols(*elf, find_symbol_section());
		uint32_t num_symbols = symbols.get_symbols_num();
		bool found = false;
		std::pair<uint64_t, uint64_t> symbol_info;

		for (uint32_t i = 0; i < num_symbols; ++i) {
			std::string name;
			ELFIO::Elf64_Addr value;
			ELFIO::Elf_Xword size;
			unsigned char bind;
			unsigned char type;
			ELFIO::Elf_Half section_index;
			unsigned char other;

			symbols.get_symbol(i, name, value, size, bind, type, section_index, other);

			if (name == variable_name) {
				if (found) {
					// 如果已经发现过一次，则抛出异常
					throw std::runtime_error("Found multiple symbols with name '" + variable_name + "'");
				}
				symbol_info = {value, size};
				found = true;
			}
		}

		if (!found) {
			throw std::runtime_error("No symbol named '" + variable_name + "' found");
		}

		return symbol_info;
	}

	// 获取特定地址和大小的数据
	const std::vector<uint8_t> get_data(uint64_t vaddr, uint64_t size) const {
		const auto &segments = elf->segments;

		for (const auto &seg : segments) {
			if (seg->get_type() == ELFIO::PT_LOAD) {
				auto seg_virt_addr = seg->get_virtual_address();
				auto seg_file_size = seg->get_file_size();

				// 检查虚拟地址是否在当前段的范围内
				if (vaddr >= seg_virt_addr && vaddr + size <= seg_virt_addr + seg_file_size) {
					uint64_t offset = vaddr - seg_virt_addr;
					const char *pdata = seg->get_data();

					// 从段中复制数据到 vector 中
					std::vector<uint8_t> data(size);
					std::copy(pdata + offset, pdata + offset + size, data.begin());

					return data;
				}
			}
		}

		// 如果找不到符合条件的段，返回空 vector
		return std::vector<uint8_t>();
	}

	std::vector<const ELFIO::segment*> loadable_segments(void) const {
		std::vector<const ELFIO::segment*> result;

		ELFIO::Elf_Half seg_num = elf->segments.size();
		for (int i = 0; i < seg_num; ++i) {
			const ELFIO::segment* seg = elf->segments[i];
			if (seg->get_type() == ELFIO::PT_LOAD) { // PT_LOAD is used to denote loadable segments
				result.push_back(seg);
			}
		}

		return result;
	}
};

// class ElfFile {
// private:
// 	int fd;
// 	Elf* elf;

// public:
// 	ElfFile(void) : fd(-1), elf(nullptr) { }

// 	ElfFile(int fd, Elf *elf) : fd(fd), elf(elf) { }

// 	Elf *get_elf(void) { return elf; }

	// ElfFile(const std::string path) : fd(-1), elf(nullptr) {
	// 	if (elf_version(EV_CURRENT) == EV_NONE) {
	// 		throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));
	// 	}

	// 	fd = open(path.c_str(), O_RDONLY, 0);
	// 	if (fd < 0) {
	// 		throw std::runtime_error("Failed to open file");
	// 	}

	// 	elf = elf_begin(fd, ELF_C_READ, nullptr);
	// 	if (!elf) {
	// 		throw std::runtime_error("elf_begin failed: " + std::string(elf_errmsg(-1)));
	// 	}

	// 	if (elf_kind(elf) != ELF_K_ELF) {
	// 		throw std::runtime_error("Not an ELF file");
	// 	}
	// }

// 	size_t count_loadable_segments(void) const {
// 		size_t loadable_count = 0;
// 		size_t num = 0;

// 		if (elf_getphdrnum(elf, &num) != 0) {
// 			throw std::runtime_error("Failed to get number of segments: " + std::string(elf_errmsg(-1)));
// 		}

// 		for (size_t i = 0; i < num; ++i) {
// 			GElf_Phdr phdr;
// 			if (gelf_getphdr(elf, i, &phdr) == nullptr) {
// 				throw std::runtime_error("Failed to get program header: " + std::string(elf_errmsg(-1)));
// 			}

// 			if (phdr.p_type == PT_LOAD) {
// 				++loadable_count;
// 			}
// 		}

// 		return loadable_count;
// 	}

// 	// ElfFile elf_file(*optional_path);
// 	// void from_path(std::filesystem::path &path);

// 	static ElfFile from_path(std::filesystem::path &path) {
// 		// 打开文件
// 		int fd = open(path.c_str(), O_RDONLY);
// 		if (fd < 0) {
// 			throw std::runtime_error(path.string() + ": " + "Failed to open file");
// 		}

// 		// 准备 libelf
// 		if (elf_version(EV_CURRENT) == EV_NONE) {
// 			close(fd);
// 			fd = -1;
// 			throw std::runtime_error(path.string() + ": " + std::string("ELF library initialization failed: ") + elf_errmsg(-1));
// 		}

// 		// 初始化 Elf
// 		Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
// 		if (!elf) {
// 			close(fd);
// 			fd = -1;
// 			throw std::runtime_error(path.string() + ": " + std::string("elf_begin() failed: ") + elf_errmsg(-1));
// 		}

// 		return ElfFile(fd, elf);
// 	}
// };

#endif /* __ELF_HPP */
