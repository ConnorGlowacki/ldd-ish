#define _GNU_SOURCE 
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <linux/limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include "graph.h"

void start_scan(char *prog_name);
char* string_table_lookup(char *str_tab, size_t str_idx);
static int dl_phdr_callback(struct dl_phdr_info *info, size_t size, void *data);
void scan_phdr(Elf64_Phdr *phdr, size_t phnum, Elf64_Addr base_addr);
void print_ehdr_info(Elf64_Ehdr elfh);
void print_shdr_table(Elf64_Shdr *shdr_tab, size_t hdr_num, char *shstrtab);
void print_dyn_table(Elf64_Dyn *dyntab);

int dl_exe_name_skipped = 0;

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
    Elf64_Shdr *shdrtab;
    Elf64_Dyn *dyntab;
    char *shstrtab;
    char *strtab;

    FILE *fp = fopen(prog_name, "rb");
    
    if (!fp) {
        perror("File not found");
        errno = ENOENT;
    }

    // LOAD ELF HEADER
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, fp);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
        // print_ehdr_info(ehdr);
    } else {
        perror("Not an ELF Header");
        exit(1);
    }


    // LOAD SHDR TABLE
    shdrtab = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    fseek(fp, ehdr.e_shoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_shnum; i++) {
        fread(&shdrtab[i], ehdr.e_shentsize, 1, fp);
    }

    // LOAD PERTINENT SPECIAL SECTIONS
    for (size_t i = 0; i < ehdr.e_shnum; i++)
    {   
        // LOAD DYNAMIC SECTION
        if(shdrtab[i].sh_type == SHT_DYNAMIC) {
            dyntab = malloc(shdrtab[i].sh_size);
            fseek(fp, shdrtab[i].sh_offset, SEEK_SET);
            fread(dyntab, shdrtab[i].sh_size, 1, fp);
        }
        // LOAD STR TABLE
        if (shdrtab[i].sh_type == SHT_STRTAB && i != ehdr.e_shstrndx) {
            strtab = malloc(shdrtab[i].sh_size);
            fseek(fp, shdrtab[i].sh_offset, SEEK_SET);
            fread(strtab, shdrtab[i].sh_size, 1, fp);
        }
        // LOAD SECTION HEADER STR TABLE
        if (i == ehdr.e_shstrndx) {
            shstrtab = malloc(shdrtab[i].sh_size);
            fseek(fp, shdrtab[i].sh_offset, SEEK_SET);
            fread(shstrtab, shdrtab[i].sh_size, 1, fp);
        }
    }

    // print_shdr_table(shdrtab, ehdr.e_shnum, shstrtab);
    // print_dyn_table(dyntab);

    char *dynstrtab;
    size_t idx = 0;
    size_t dynstrtab_sz;
    // FIND DT_STRTAB SIZE
    while(dyntab[idx].d_tag != DT_NULL)
    {   
        if (dyntab[idx].d_tag == DT_STRSZ) {
            dynstrtab_sz = dyntab[idx].d_un.d_val;
        }
        idx++;
    }
    // LOAD .dynstr TABLE
    idx = 0;
    while(dyntab[idx].d_tag != DT_NULL)
    {   
        if (dyntab[idx].d_tag == DT_STRTAB) {
            dynstrtab = malloc(dynstrtab_sz);
            fseek(fp, dyntab[idx].d_un.d_val, SEEK_SET);
            fread(dynstrtab, dynstrtab_sz, 1, fp);
        }
        idx++;
    }
    // FIND NEEDED LIBRARIES
    idx = 0;
    while(dyntab[idx].d_tag != DT_NULL)
    {   
        if (dyntab[idx].d_tag == DT_NEEDED) {
            char * libname = string_table_lookup(dynstrtab, dyntab[idx].d_un.d_val);
            void *dlhandle = dlopen(libname, RTLD_NOW || RTLD_GLOBAL);
			if (dlhandle == NULL) {
				printf("%s\n", dlerror());
				fflush(stdout);
				exit(1);
			}
            printf("EXE needs: %s\n", libname);
            // printf("0x%016lx\n", dlhandle);
            dl_iterate_phdr(dl_phdr_callback, NULL);
            dlclose(dlhandle);
        }
        idx++;
    }
    
    free(shstrtab);
    free(dynstrtab);
    free(shdrtab);
    free(dyntab);
    free(strtab);
    fclose(fp);
    return;
}

char *string_table_lookup(char *str_tab, size_t str_idx) {

    size_t str_len = 0;
    while (str_tab[str_idx + str_len] != '\0') {
        str_len++;
    }

    char* strbuf = (char*)malloc(str_len + 1);
    if (!strbuf) {
        perror("Memory allocation failed");
        exit(1);
    }

    for (size_t i = 0; i < str_len; i++) {
        strbuf[i] = str_tab[str_idx + i];
    }
    strbuf[str_len] = '\0';
    return strbuf;
}

static int dl_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size;
    (void) data;

    if(strlen(info->dlpi_name) == 0) {
        return 0;
    }

    printf("Shared Object: %s, Base Address: 0x%016lx\n", info->dlpi_name, (void *)info->dlpi_addr);
    scan_phdr(info->dlpi_phdr, info->dlpi_phnum, info->dlpi_addr);
    return 0;
}

void scan_phdr(Elf64_Phdr *phdr, size_t phnum, Elf64_Addr base_addr) {

    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            if (phdr[i].p_memsz == 0) {
                return;
            }
            Elf64_Dyn *dyns = (Elf64_Dyn *) (base_addr + phdr[i].p_vaddr);
            size_t dyn_num = phdr[i].p_memsz / sizeof(Elf64_Dyn);
            char* dynstrtab;
            for (int j = 0; j < dyn_num; j++) {
                if (dyns[j].d_tag == DT_STRTAB) {
                    dynstrtab = (char*)(dyns[j].d_un.d_val);
                }
            }
            for (int j = 0; j < dyn_num; j++) {
                if (dyns[j].d_tag == DT_NEEDED) {
                    printf("needs library: %s\n", (char*)(string_table_lookup(dynstrtab, dyns[j].d_un.d_val)));
                }
            }
        }
    }
}

void print_ehdr_info(Elf64_Ehdr elfh) {
    printf("ELFH: Type-> %x\n", elfh.e_type);
    printf("ELFH: Header Size-> %x\n", elfh.e_ehsize);
    printf("ELFH: PHDR Table Offset-> %lx\n", elfh.e_phoff);
    printf("ELFH: PHDR Num->%d\n", elfh.e_phnum);
    printf("ELFH: PHDR Size-> %x\n", elfh.e_phentsize);
    printf("ELFH: SHDR Table Offset-> %lx\n", elfh.e_shoff);
    printf("ELFH: SHDR Num-> %d\n", elfh.e_shnum);
    printf("ELFH: SHDR Size-> %x\n", elfh.e_shentsize);
    printf("ELFH: SHDR Str Table Index-> %d\n", elfh.e_shstrndx);
    return;
}

void print_shdr_table(Elf64_Shdr *shdr_tab, size_t hdr_count, char *shstrtab) {
    for (size_t i = 0; i < hdr_count; i++)
    {
        printf("Section Header #: %ld\n", i);
        printf("%s\n", string_table_lookup(shstrtab,shdr_tab[i].sh_name));
        printf("Section Header Type: %x\n", shdr_tab[i].sh_type);
        printf("Section Header Size: %lx\n", shdr_tab[i].sh_size);
        printf("Section Header Entry Size: %ld\n", shdr_tab[i].sh_entsize);
    }
    return;
}

void print_dyn_table(Elf64_Dyn *dyntab) {
    size_t i = 0;
    while(dyntab[i].d_tag != DT_NULL)
    {
        printf("Dynamic Entry #: %ld\n", i);
        printf("Dynamic Entry Type: %lx\n", dyntab[i].d_tag);
        printf("Dynamic Entry Val: %lx\n", dyntab[i].d_un.d_val);
        printf("Dynamic Entry Ptr: %ld\n", dyntab[i].d_un.d_ptr);
        i++;
    }
    return;
}