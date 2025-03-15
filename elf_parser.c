#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

void error_exit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

bool elf_check_file(Elf32_Ehdr *elf_header)
{
    if (((char *)elf_header)[0] != 0x7f)
        return false;
    if (strncmp((char *)elf_header + 1, "ELF", 3) != 0)
        return false;
    return true;
}

void parse_elf32_header(Elf32_Ehdr *elf_header)
{
    puts("ELF Header:");
    printf("  Magic:\t\t");
    for (int i = 0; i < EI_NIDENT; i++)
    {
        printf("%.2x ", elf_header->e_ident[i]);
    }
    puts("");
    printf("  e_type:\t\t%hu\n", elf_header->e_type);
    printf("  e_machine:\t\t%hu\n", elf_header->e_machine);
    printf("  e_version:\t\t%u\n", elf_header->e_version);
    printf("  e_entry:\t\t0x%x\n", elf_header->e_entry);
    printf("  e_phoff:\t\t%u\n", elf_header->e_phoff);
    printf("  e_shoff:\t\t%u\n", elf_header->e_shoff);
    printf("  e_flags:\t\t0x%x\n", elf_header->e_flags);
    printf("  e_ehsize:\t\t%hu\n", elf_header->e_ehsize);
    printf("  e_phentsize:\t\t%hu\n", elf_header->e_phentsize);
    printf("  e_phnum:\t\t%hu\n", elf_header->e_phnum);
    printf("  e_shentsize:\t\t%hu\n", elf_header->e_shentsize);
    printf("  e_shnum:\t\t%hu\n", elf_header->e_shnum);
    printf("  e_shstrndx:\t\t%hu\n", elf_header->e_shstrndx);
}

void print_segment_type(uint32_t ptype)
{
    switch (ptype)
    {
    case 0:
        printf("  PT_NULL%11s", "");
        break;
    case 1:
        printf("  PT_LOAD%11s", "");
        break;
    case 2:
        printf("  PT_DYNAMIC%8s", "");
        break;
    case 3:
        printf("  PT_INTERP%9s", "");
        break;
    case 4:
        printf("  PT_NOTE%11s", "");
        break;
    case 5:
        printf("  PT_SHLIB%10s", "");
        break;
    case 6:
        printf("  PT_PHDR%11s", "");
        break;
    case 7:
        printf("  PT_TLS%12s", "");
        break;
    case 8:
        printf("  PT_NUM%12s", "");
        break;
    case 0x60000000:
        printf("  PT_LOOS%11s", "");
        break;
    case 0x6474e550:
        printf("  PT_GNU_EH_FRAME%3s", "");
        break;
    case 0x6474e551:
        printf("  PT_GNU_STACK%6s", "");
        break;
    case 0x6474e552:
        printf("  PT_GNU_RELRO%6s", "");
        break;
    case 0x6474e553:
        printf("  PT_GNU_PROPERTY%9s", "");
        break;
    default:
        break;
    }
}

void print_segment_flags(uint32_t flags)
{
    char f[3] = "   ";
    if (flags & 4)
    {
        f[0] = 'R';
    }
    if (flags & 2)
    {
        f[1] = 'W';
    }
    if (flags & 1)
    {
        f[2] = 'X';
    }
    printf("%s%9s", f, "");
}

const char *get_section_type_name(uint32_t type)
{
    switch (type)
    {
    case SHT_NULL:
        return "NULL (Unused)";
    case SHT_PROGBITS:
        return "PROGBITS (Program Data)";
    case SHT_SYMTAB:
        return "SYMTAB (Symbol Table)";
    case SHT_STRTAB:
        return "STRTAB (String Table)";
    case SHT_RELA:
        return "RELA (Relocations with Addends)";
    case SHT_HASH:
        return "HASH (Symbol Hash Table)";
    case SHT_DYNAMIC:
        return "DYNAMIC (Dynamic Linking Info)";
    case SHT_NOTE:
        return "NOTE (Notes)";
    case SHT_NOBITS:
        return "NOBITS (BSS)";
    case SHT_REL:
        return "REL (Relocations without Addends)";
    case SHT_SHLIB:
        return "SHLIB (Reserved)";
    case SHT_DYNSYM:
        return "DYNSYM (Dynamic Symbol Table)";
    case SHT_INIT_ARRAY:
        return "INIT_ARRAY (Constructors)";
    case SHT_FINI_ARRAY:
        return "FINI_ARRAY (Destructors)";
    case SHT_PREINIT_ARRAY:
        return "PREINIT_ARRAY (Pre-constructors)";
    case SHT_GROUP:
        return "GROUP (Section Group)";
    case SHT_SYMTAB_SHNDX:
        return "SYMTAB_SHNDX (Extended Section Indices)";
    case SHT_NUM:
        return "NUM (Number of Defined Types)";
    case SHT_LOOS:
        return "LOOS (Start OS-specific)";
    case SHT_GNU_ATTRIBUTES:
        return "GNU_ATTRIBUTES (Object Attributes)";
    case SHT_GNU_HASH:
        return "GNU_HASH (GNU-Style Hash Table)";
    case SHT_GNU_LIBLIST:
        return "GNU_LIBLIST (Prelink Library List)";
    case SHT_CHECKSUM:
        return "CHECKSUM (Checksum for DSO Content)";
    case SHT_LOSUNW:
        return "LOSUNW (Sun-Specific Low Bound)";
    case SHT_SUNW_COMDAT:
        return "SUNW_COMDAT";
    case SHT_SUNW_syminfo:
        return "SUNW_syminfo";
    case SHT_GNU_verdef:
        return "GNU_verdef (Version Definition Section)";
    case SHT_GNU_verneed:
        return "GNU_verneed (Version Needs Section)";
    case SHT_GNU_versym:
        return "GNU_versym (Version Symbol Table)";
    case SHT_LOPROC:
        return "LOPROC (Start of Processor-Specific)";
    case SHT_HIPROC:
        return "HIPROC (End of Processor-Specific)";
    case SHT_LOUSER:
        return "LOUSER (Start of Application-Specific)";
    case SHT_HIUSER:
        return "HIUSER (End of Application-Specific)";
    default:
        return "UNKNOWN";
    }
}

void get_section_flags(unsigned int flags, char *buffer, size_t size)
{
    int pos = 0;

    if (flags & SHF_WRITE)
        buffer[pos++] = 'W';
    if (flags & SHF_ALLOC)
        buffer[pos++] = 'A';
    if (flags & SHF_EXECINSTR)
        buffer[pos++] = 'X';
    if (flags & SHF_MERGE)
        buffer[pos++] = 'M';
    if (flags & SHF_STRINGS)
        buffer[pos++] = 'S';
    if (flags & SHF_INFO_LINK)
        buffer[pos++] = 'I';
    if (flags & SHF_LINK_ORDER)
        buffer[pos++] = 'L';
    if (flags & SHF_OS_NONCONFORMING)
        buffer[pos++] = 'O';
    buffer[pos] = '\0';
}

void parse_elf32_shdr(int fd, Elf32_Ehdr *elf_header)
{
    uint32_t shder_entry_size = elf_header->e_shentsize;
    uint32_t shder_nums_entry = elf_header->e_shnum;
    uint32_t shder_offset = elf_header->e_shoff;
    uint32_t shder_size = shder_entry_size * shder_nums_entry;
    char *elf_section_header_table = (char *)malloc(shder_size);
    off_t offset = lseek(fd, shder_offset, SEEK_SET);
    if (offset == -1)
    {
        error_exit("Couldn't lseek file, errno");
    }
    ssize_t rd = read(fd, (void *)elf_section_header_table, shder_size);
    if (rd < 0)
    {
        error_exit("Couldn't read file");
    }
    assert(rd == (ssize_t)shder_size);
    uint32_t shstrtab_index = elf_header->e_shstrndx;
    Elf32_Shdr *elf_shder = (Elf32_Shdr *)(elf_section_header_table + (shstrtab_index * shder_entry_size));
    // memcpy((char *)&elf_shder, elf_section_header_table + (shstrtab_index * shder_entry_size), shder_entry_size);
    uint32_t shstrtab_offset = elf_shder->sh_offset;
    uint32_t shstrtab_size = elf_shder->sh_size;
    char *elf_shstrtab_table = (char *)malloc(shstrtab_size);
    offset = lseek(fd, shstrtab_offset, SEEK_SET);
    if (offset == -1)
    {
        error_exit("Couldn't lseek file");
    }
    rd = read(fd, (void *)elf_shstrtab_table, (size_t)shstrtab_size);
    if (rd < 0)
    {
        error_exit("Couldn't read file");
    }
    assert(rd == shstrtab_size);
    puts("Section Headers:");
    printf("  [Nr]   %-20s   %-40s %6s  %6s    %6s %6s    %s   %2s  %6s  %4s\n",
           "Name", "Type", "Addr", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al");
    for (uint32_t i = 0; i < shder_nums_entry; ++i)
    {
        elf_shder = (Elf32_Shdr *)(elf_section_header_table + (i * shder_entry_size));
        // memcpy((char *)elf_shder, elf_section_header_table + (i * shder_entry_size), shder_entry_size);
        char flag_str[9];
        get_section_flags(elf_shder->sh_flags, flag_str, sizeof(flag_str));
        printf("  [%2d] ", i);
        printf("  %-20s ", (char *)(elf_shstrtab_table + elf_shder->sh_name));
        printf("  %-40s ", get_section_type_name(elf_shder->sh_type));
        printf("  0x%.4x ", elf_shder->sh_addr);
        printf("  0x%.4x ", elf_shder->sh_offset);
        printf("  0x%.4x ", elf_shder->sh_size);
        printf("  0x%.2x ", elf_shder->sh_entsize);
        printf("  %-2s ", flag_str);
        printf("  0x%.2x ", elf_shder->sh_link);
        printf("  0x%.2x ", elf_shder->sh_info);
        printf("  0x%.2x \n", elf_shder->sh_addralign);
    }
    free(elf_section_header_table);
    free(elf_shstrtab_table);
}

void parse_elf32_phdr(int fd, Elf32_Ehdr *elf_header)
{
    uint32_t phder_entry_size = elf_header->e_phentsize;
    uint32_t phder_nums_entry = elf_header->e_phnum;
    uint32_t phder_offset = elf_header->e_phoff;
    uint32_t phder_size = phder_entry_size * phder_nums_entry;
    char *elf_prog_header_table = (char *)malloc(phder_size);
    off_t offset = lseek(fd, phder_offset, SEEK_SET);
    if (offset == -1)
    {
        error_exit("Couldn't lseek file");
    }
    ssize_t rd = read(fd, (void *)elf_prog_header_table, (size_t)phder_size);
    if (rd < 0)
    {
        error_exit("Couldn't read file");
    }
    assert(rd == phder_size);
    puts("Program Headers:");

    printf("  p_type%12sp_offset    p_vaddr     p_paddr     p_filesz    p_memsz     p_flags     p_align\n", "");
    for (uint32_t i = 0; i < phder_nums_entry; ++i)
    {
        Elf32_Phdr elf_prog_header;
        memcpy((char *)&elf_prog_header, (elf_prog_header_table + (i * phder_entry_size)), sizeof(Elf32_Phdr));
        print_segment_type(elf_prog_header.p_type);
        printf("0x%.8x  ", elf_prog_header.p_offset);
        printf("0x%.8x  ", elf_prog_header.p_vaddr);
        printf("0x%.8x  ", elf_prog_header.p_paddr);
        printf("0x%.8x  ", elf_prog_header.p_filesz);
        printf("0x%.8x  ", elf_prog_header.p_memsz);
        print_segment_flags(elf_prog_header.p_flags);
        printf("0x%.8x  ", elf_prog_header.p_align);
        puts("");
    }
    free(elf_prog_header_table);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        error_exit("must provide a file");
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
    {
        error_exit("Couldn't open file");
    }
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    int rd = read(fd, (void *)elf_header, sizeof(Elf32_Ehdr));
    if (rd < 0)
    {
        error_exit("Couldn't read file");
    }
    if (!elf_check_file(elf_header))
    {
        error_exit("Not an ELF file");
    }
    parse_elf32_header(elf_header);
    printf("\n\n");
    parse_elf32_phdr(fd, elf_header);
    printf("\n\n");
    parse_elf32_shdr(fd, elf_header);
    free(elf_header);
}
