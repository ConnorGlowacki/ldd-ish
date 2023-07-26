#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <elf.h>
#include <limits.h>
#include <unistd.h>

void start_scan(char *prog_name);

int main(int argc, char **argv){

    if (argc > 1){
        start_scan(argv[1]);
        return 0;
    } 
    else {
        perror("No argument passed");
        exit(1);
    }
}

void start_scan(char *prog_name) {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr_tab;
    Elf64_Shdr strtab_shdr;
    Elf64_Sym *sym_tab;


    FILE *fp = fopen(prog_name, "rb");
    
    if (!fp) {
        perror("File not found");
        errno = ENOENT;
    }
    printf("%s:\n", prog_name);

    fread(&ehdr, sizeof(Elf64_Ehdr), 1, fp);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
       printf("ELF header loaded\n");
    }

    printf("ELF Type: %x\n", ehdr.e_type);

    fseek(fp, ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shstrndx), SEEK_SET);
    fread(&strtab_shdr, sizeof(Elf64_Shdr), 1, fp);

    char *string_table = malloc(strtab_shdr.sh_size);
    fseek(fp, strtab_shdr.sh_offset, SEEK_SET);
    fread(string_table, 1, strtab_shdr.sh_size, fp);

    shdr_tab = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    fseek(fp, ehdr.e_shoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_shnum; i++) {
        fread(&shdr_tab[i], ehdr.e_shentsize, 1, fp);
    }
    int symbolic_entries = 0;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdr_tab[i].sh_type == SHT_DYNSYM) {
            printf("Section Header #: %d\n", i);
            printf("Section Header Type: %x\n", shdr_tab[i].sh_type);
            printf("Section Header Entry Size: %d\n", shdr_tab[i].sh_entsize);
            symbolic_entries = shdr_tab[i].sh_size / shdr_tab[i].sh_entsize;
            sym_tab = malloc(shdr_tab[i].sh_size);
            fseek(fp, shdr_tab[i].sh_offset, SEEK_SET);
            fread(sym_tab, shdr_tab[i].sh_size, 1, fp);

            for (int j = 0; j < symbolic_entries; j++) {
                // Elf64_Sym *sym_entry = &sym_tab[j];
                const char *sym_name = string_table + sym_tab[j].st_name;
                printf("Symbol Name: %s\n", sym_name);
                printf("Symbol Value: %x\n", sym_tab[j].st_info);
            }
            break;
        }
        else 
        {
            printf("Section Header #: %d\n", i);
            printf("Section Header Type: %x\n", shdr_tab[i].sh_type);
        }
        
    }
    

    phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);
    fseek(fp, ehdr.e_phoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_phnum; i++) {
        fread(&phdr[i], ehdr.e_phentsize, 1, fp);
    }

    Elf64_Dyn dyns;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            printf("Program Header Entry Type: %x\n", phdr[i].p_type);
            fseek(fp, phdr[i].p_offset, SEEK_SET);
            fread(&dyns, sizeof(Elf64_Dyn), 1, fp);
            printf("Dynamic Section Tag: %x\n", dyns.d_tag);
            printf("Dynamic Section Value: %x\n", dyns.d_un.d_val);
            printf("Dynamic Section Address: %x\n", dyns.d_un.d_ptr);
            const char *dyn_name = string_table + dyns.d_un.d_val;
            printf("Symbol Name: %s\n", dyn_name);
        }
        else if (phdr[i].p_type == PT_INTERP)
        {
            printf("Program Header Entry Type: %x\n", phdr[i].p_type);
        }
        
    }
    // char *lib_name = string_table + dyns.d_un.d_val;
    // printf("Lib: %s\n", lib_name);

    // char path[pathconf("/", _PC_NAME_MAX)];
    // printf("%d\n", sizeof(path));
    // void *handle = dlopen(realpath(prog_name, path), RTLD_NOW);
    free(string_table);
    // dlclose(handle);
    free(sym_tab);
    free(phdr);
    fclose(fp);
    return;
}