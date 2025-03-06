#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

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
        printf("Couldn't lseek file, errno %d\n", errno);
        exit(-1);
    }
    ssize_t rd = read(fd, (void *)elf_prog_header_table, phder_size);
    if (rd < 0)
    {
        printf("Couldn't read file, errno %d\n", errno);
        exit(-1);
    }
    //int ffd = open("./file", O_WRONLY);
    puts("Program Headers:");

    printf("  p_type%12sp_offset    p_vaddr     p_paddr     p_filesz    p_memsz     p_flags     p_align\n", "");
    for (uint32_t i = 0; i < phder_nums_entry; ++i)
    {
        Elf32_Phdr elf_prog_header;
        memcpy((char *)&elf_prog_header, (char *)(elf_prog_header_table + (i * phder_entry_size)), sizeof(Elf32_Phdr));
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
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        puts("must provide a file");
        exit(-1);
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
    {
        printf("Couldn't open file, errno %d\n", errno);
        exit(-1);
    }
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    int rd = read(fd, (void *)elf_header, sizeof(Elf32_Ehdr));
    if (rd < 0)
    {
        printf("Couldn't read file, errno %d\n", errno);
        exit(-1);
    }
    if (!elf_check_file(elf_header))
    {
        printf("Not an ELF file\n");
        exit(-1);
    }
    parse_elf32_header(elf_header);
    printf("\n\n");
    parse_elf32_phdr(fd, elf_header);
}
