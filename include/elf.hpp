#ifndef __ELF_HPP
#define __ELF_HPP

#include <iostream>
#include <filesystem>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class ElfFile {
private:
	int fd;
	Elf* elf;

public:
	ElfFile(int fd, Elf *elf) : fd(fd), elf(elf) { }

	ElfFile(const std::string path) : fd(-1), elf(nullptr) {
		if (elf_version(EV_CURRENT) == EV_NONE) {
			throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));
		}

		fd = open(path.c_str(), O_RDONLY, 0);
		if (fd < 0) {
			throw std::runtime_error("Failed to open file");
		}

		elf = elf_begin(fd, ELF_C_READ, nullptr);
		if (!elf) {
			throw std::runtime_error("elf_begin failed: " + std::string(elf_errmsg(-1)));
		}

		if (elf_kind(elf) != ELF_K_ELF) {
			throw std::runtime_error("Not an ELF file");
		}
	}

	size_t count_loadable_segments(void) const {
		size_t loadable_count = 0;
		size_t num = 0;

		if (elf_getphdrnum(elf, &num) != 0) {
			throw std::runtime_error("Failed to get number of segments: " + std::string(elf_errmsg(-1)));
		}

		for (size_t i = 0; i < num; ++i) {
			GElf_Phdr phdr;
			if (gelf_getphdr(elf, i, &phdr) == nullptr) {
				throw std::runtime_error("Failed to get program header: " + std::string(elf_errmsg(-1)));
			}

			if (phdr.p_type == PT_LOAD) {
				++loadable_count;
			}
		}

		return loadable_count;
	}

	// ElfFile elf_file(*optional_path);
	// void from_path(std::filesystem::path &path);

	static ElfFile from_path(std::filesystem::path &path) {
		// 打开文件
		int fd = open(path.c_str(), O_RDONLY);
		if (fd < 0) {
			throw std::runtime_error(path.string() + ": " + "Failed to open file");
		}

		// 准备 libelf
		if (elf_version(EV_CURRENT) == EV_NONE) {
			close(fd);
			fd = -1;
			throw std::runtime_error(path.string() + ": " + std::string("ELF library initialization failed: ") + elf_errmsg(-1));
		}

		// 初始化 Elf
		Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
		if (!elf) {
			close(fd);
			fd = -1;
			throw std::runtime_error(path.string() + ": " + std::string("elf_begin() failed: ") + elf_errmsg(-1));
		}

		return ElfFile(fd, elf);
	}

	~ElfFile() {
		if (elf) {
			elf_end(elf);
		}
		if (fd >= 0) {
			close(fd);
		}
	}
};

#endif /* __ELF_HPP */
