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

void start_scan(char *prog_name);
void print_ehdr_info(Elf64_Ehdr elfh);
void print_shdr_table(Elf64_Shdr *shdr_tab, size_t hdr_num, char *shstrtab);
char* string_table_lookup(char *str_tab, size_t str_idx);
void print_dyn_table(Elf64_Dyn *dyntab);
static int dl_phdr_callback(struct dl_phdr_info *info, size_t size, void *data);

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

char* string_table_lookup(char *str_tab, size_t str_idx) {
    size_t bufsize = 16;
    char *strbuf = malloc(bufsize);
    int i = 0;
    while (str_tab[str_idx] != '\0') {
        if (i >= bufsize) {
            bufsize *= 2; // Double the buffer size
            strbuf = (char*)realloc(strbuf, bufsize);
            if (!strbuf) {
                perror("Memory reallocation failed");
                exit(1);
            }
        }

        // Copy the character to readString
        strbuf[i] = str_tab[str_idx];
        str_idx++;
        i++;
    }
    return strbuf;
}

static int dl_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size;
    (void) data;
    if (!dl_exe_name_skipped){
        dl_exe_name_skipped = 1;
        return 0;
    }
    printf("Shared Object: %s, Base Address: %p\n", info->dlpi_name, (void *)info->dlpi_addr);
    // printf("0x%016lx\n", (void *)info->dlpi_addr);
    return 0;
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
            // printf("%s\n", libname);
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