#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define STACK_SIZE (1024 * 1024)    /* Stack size for test process */
#define BUF_SIZE 1048576

void* entry_point;

int is_image_valid(Elf32_Ehdr *hdr)
{
    return 1;
}

void *resolve(const char* sym)
{
    static void *handle = NULL;
    if (handle == NULL) {
        handle = dlopen("libc.so", RTLD_NOW);
    }
    return dlsym(handle, sym);
}

void relocate(Elf32_Shdr* sectionHdr, const Elf32_Sym* syms, const char* strings, const char* src, char* dst)
{
    Elf32_Rel* rel = (Elf32_Rel*)(src + sectionHdr->sh_offset);
    int j;
    for(j = 0; j < sectionHdr->sh_size / sizeof(Elf32_Rel); j += 1) {
        const char* sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;
        switch(ELF32_R_TYPE(rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                *(Elf32_Word*)(dst + rel[j].r_offset) = (Elf32_Word)resolve(sym);
                break;
        }
    }
}


void* find_sym(const char* name, Elf32_Shdr* sectionHdr, const char* strings, const char* src, char* dst)
{
    Elf32_Sym* syms = (Elf32_Sym*)(src + sectionHdr->sh_offset);
    int i;
    for(i = 0; i < sectionHdr->sh_size / sizeof(Elf32_Sym); i += 1) {
        if (strcmp(name, strings + syms[i].st_name) == 0) {
            return dst + syms[i].st_value;
        }
    }
    return NULL;
}

void *image_load (char *buffer, unsigned int size, void* stack)
{
    Elf32_Ehdr *elfhdr        = NULL;
    Elf32_Phdr *programHdr    = NULL;
    Elf32_Shdr *sectionHdr    = NULL;
    Elf32_Sym  *syms          = NULL;
    char *strings      = NULL;
    char *start_addr   = NULL;
    char *dest_addr    = NULL;
    void *entry_addr   = NULL;
    int i = 0;
    char *exec_mem = NULL;
    char *bss = NULL;

    //Read the ELF Structure
    elfhdr = (Elf32_Ehdr *) buffer;
    fprintf(stderr, "Created ELF header\n");
    if(!is_image_valid(elfhdr)) {
        fprintf(stderr, "image_load:: invalid ELF image\n");
        return 0;
    }
    entry_point = (Elf32_Addr*) elfhdr->e_entry;

    //Allocate memory for the Program 
    exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	//Protection Permissions: The allocated memory should be allowed READ, WRITE, EXECUTE permissions
	//MAP_PRIVATE: Changes made in this memory do not need to be written back to the disk
	//MAP_ANONYMOUS: The memory is not backed by a file on the disk 
    fprintf(stderr, "Allocated memory for the text and data segment..\n");
    if(!exec_mem) {
        fprintf(stderr, "image_load:: error allocating memory\n");
        return 0;
    }

    // Start with clean memory.(would be needed for the BSS section) 
    memset(exec_mem, 0x0, size);

    programHdr = (Elf32_Phdr *)(buffer + elfhdr->e_phoff);
    
    
    Elf32_auxv_t *stackTop = (Elf32_auxv_t *) stack;

    printf("Changing the Test auxv values\n");
    fprintf(stderr, "StackTop : 0x%08x\n", stackTop);
    for ( ; stackTop->a_type != AT_NULL; stackTop++) {
        fprintf(stderr, "Stack value : 0x%08x\n", getauxval(stackTop->a_type));
        if(stackTop->a_type == AT_PHDR){
	    stackTop->a_un.a_val = programHdr;
	    fprintf(stderr, "Programheader found : 0x%08x\n", programHdr);
	}
    }

    fprintf(stderr, "Extracted Program header \n"); 
    for(i=0; i < elfhdr->e_phnum; ++i) {
        /*Program header LOAD section contains the details of the location 
        from where the virtual addresses of the child program are supposed to start 
        And if the Filesize increases the memory size return with error code*/
        if(programHdr[i].p_type != PT_LOAD) {
            continue;
        }
        if(programHdr[i].p_filesz > programHdr[i].p_memsz) {
            fprintf(stderr, "image_load:: p_filesz > p_memsz\n");
            munmap(exec_mem, size);
            return 0;
        }
        if(!programHdr[i].p_filesz) {
            continue;
        }

        // p_filesz can be smaller than p_memsz,
        // the difference is zeroe'd out.
        start_addr = buffer + programHdr[i].p_offset;
        dest_addr = programHdr[i].p_vaddr + exec_mem;
        fprintf(stderr, "Loading the instrcutions into the allocated memory...\n");
        memmove(dest_addr, start_addr, programHdr[i].p_filesz);
        //Setting the permissions of the memeory based on the permissions in program header 
        if(!(programHdr[i].p_flags & PF_W)) {
            // Setting permissions to Read-only
            mprotect((unsigned char *) dest_addr,
                         programHdr[i].p_memsz,
                         PROT_READ);
        }

        if(programHdr[i].p_flags & PF_X) {
            // Setting permissions to be Exec
            mprotect((unsigned char *) dest_addr,
                            programHdr[i].p_memsz,
                            PROT_EXEC);
        }
    }

    fprintf(stderr, "Starting with dynamic loading...\n");
    entry_addr = elfhdr->e_entry + exec_mem;
    
    sectionHdr = (Elf32_Shdr *)(buffer + elfhdr->e_shoff);

    //The entry for the main function needs to be determined from the symbol table and then call libc with it... 
    for(i=0; i < elfhdr->e_shnum; ++i) {
        if (sectionHdr[i].sh_type == SHT_DYNSYM) {
            syms = (Elf32_Sym*)(buffer + sectionHdr[i].sh_offset);
            strings = buffer + sectionHdr[sectionHdr[i].sh_link].sh_offset;
            entry_addr = find_sym("main", sectionHdr + i, strings, buffer, exec_mem);
            break;
        }
    }

    for(i=0; i < elfhdr->e_shnum; ++i) {
        if (sectionHdr[i].sh_type == SHT_REL) {
            relocate(sectionHdr + i, syms, strings, buffer, exec_mem);
        }
    }

    /*//Code to traverse through the Section 
    for(i=0; i < elfhdr->e_shnum; ++i) {
        if (sectionHdr[i].sh_type == SHT_NOBITS) {
            if (sectionHrd[i].sh_name == ".bss"){
	         bss = sectionHrd[i].sh_addr +sectionHrd[i].sh_offset;
                 printf("bss : %s", bss);
	    }
        }
    }*/

   return entry_addr;

}/* image_load */

void* create_auxv(char** envp, void* stack){
    Elf32_auxv_t *auxv;
    while (*envp++ != NULL)
	;
    /* and find ELF auxiliary vectors (if this was an ELF binary) */
    auxv = (Elf32_auxv_t *) envp;
    Elf32_auxv_t *stackTop = (Elf32_auxv_t *) stack;
    stackTop->a_type = AT_NULL;
    stackTop->a_un.a_val = NULL;

    printf("Creating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        //printf("type : 0x%08x\n", getauxval(auxv->a_type));
        stackTop--;
        stackTop->a_type = auxv->a_type; 
	stackTop->a_un.a_val = getauxval(auxv->a_type);
    }
    fprintf(stderr, "Stack top : 0x%08x\n", stackTop);
    return stackTop;
}

void* push_args_stack(int argc, char** argv, char** envp, void* stack){
    void* stackTop = stack + sizeof(Elf32_auxv_t) ; 
    char* stackTopChar = (char*)stackTop;
    while(*envp++ != NULL){
        stackTopChar--;
        *stackTopChar = *envp;
    }
    stackTopChar--;
    *stackTopChar = "\0";
    
    *argv++;
    while(*argv++ != NULL){
        stackTopChar--;
        *stackTopChar = *argv;
    }
    stackTopChar--;
    *stackTopChar = "\0";
    //stackTopChar--;
    stackTop = stackTopChar;
    stackTop = stackTop - sizeof(int);
    *((int*)stackTop) = argc - 1; 
    return stackTop;
}


int main(int argc, char** argv, char** envp)
{
    int (*ptr)(int, char **, char**);
    static char buffer[BUF_SIZE];
    if(argc < 2 ){
        fprintf(stderr, "No File provided in as argument\n");
	return 0;
    }
    fprintf(stderr, "Opening the File\n");
    FILE* elf = fopen(argv[1], "rb");
    fread(buffer, BUF_SIZE, 1, elf);
    fprintf(stderr, "Starting Loading.. \n");
    //Create the stack 
    //char *stack;                    /* Start of stack buffer */
    //char *stackTop;                 /* End of stack buffer */
    void *stack = mmap(0,STACK_SIZE,PROT_WRITE|PROT_READ,MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS,0,0);
    //stack = malloc(STACK_SIZE);
    if (stack == NULL)
        fprintf(stderr, "unable to allocate memeory for the stack using malloc");
    //stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */
    fprintf(stderr, "Stack top : 0x%08x\n", stack);
    stack = create_auxv(envp, stack);
    ptr=image_load(buffer, BUF_SIZE, stack);
    argc = argc -1;
    fprintf(stderr, "Starting with test program at 0x%08x\n", ptr);
    fprintf(stderr,"ENTRY POINT:0x%08x\n",entry_point); 
    __asm__("movl %0, %%esp;": :"r"(stack):"%esp");
    //__asm__("jmp 0x000004d0");
    return ptr(argc, argv+1, envp);
}
