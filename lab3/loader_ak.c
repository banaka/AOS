#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <gelf.h>
#include <fcntl.h>

#define STACK_SIZE (1024 * 1024)    /* Stack size for test process */
#define BUF_SIZE 1048576


#define PAGE_SIZE getpagesize()
//Could use bitwise XOR TOO
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (PAGE_SIZE-1))
#define ELF_PAGEALIGN(_v) (((_v) + PAGE_SIZE -1) & ~(PAGE_SIZE - 1))


void* entry_point;

unsigned int auxv_phnum, auxv_phdr, auxv_entry, auxv_phent, pHdr_count;

//USE TO FIND BSS
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

void* load_image(char *file, void* stack) {
    Elf* elf;
    GElf_Ehdr elfHdr;
    GElf_Phdr pHdr;
    GElf_Shdr sHdr;
    GElf_Sym  *syms;
    char *strings      = NULL;
    char *start_addr   = NULL;
    char *dest_addr    = NULL;
    void *entry_addr   = NULL;
    int i = 0;
    char *exec_mem = NULL;
    int fd = 0;
    unsigned long bss = NULL;
    int pcount = 0;

    //Read the ELF Structure
    //1. Create the file descriptor 
    printf("Exce given as argument : %s\n", file);
    if(fd = open(file, O_RDWR, 0) < 0){
	fprintf(stderr, "Unable to open the executable\n");
    }
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){
	 fprintf(stderr, "Unable to create Elf: %s\n", elf_errmsg(-1));
    }
    if (gelf_getehdr(elf, &elfHdr) != NULL){
         fprintf(stderr, "Unable to create Elf Header \n");
    }

    pHdr_count = elfHdr.e_phnum;
    auxv_phent = elfHdr.e_phentsize;
    auxv_entry = elfHdr.e_entry;
    entry_addr = elfHdr.e_entry;

    for( i=0; i < pHdr_count ; i++){
	if (gelf_getphdr(elf, i, &pHdr) != &pHdr){
            fprintf(stderr, "Unable to get program Header no %d \n", i);
	return 0;
	}
	if(pHdr.p_type != PT_LOAD){
	   continue;
	}

	printf("PageStart : %x, offset : %x, filesize : %d\n", pHdr.p_vaddr, pHdr.p_offset , pHdr.p_filesz);
        printf("pageEnd : %x, Endoffset :%x", (void*)ELF_PAGESTART(pHdr.p_vaddr), (pHdr.p_offset - ELF_PAGEOFFSET(pHdr.p_vaddr)));

        if(!pHdr.p_filesz)
            continue;

        int prot = PROT_READ;
        if (pHdr.p_flags & PF_W)
            prot |= PROT_WRITE;

        if (pHdr.p_flags & PF_X)
          prot |= PROT_EXEC;

      if((unsigned long)(ELF_PAGESTART(pHdr.p_vaddr)^(unsigned long) (PAGE_SIZE-1)) == 0)
          printf("WARNING: NOT ALIGNED\n");

      char* map = mmap((void*)ELF_PAGESTART(pHdr.p_vaddr), (pHdr.p_filesz + ELF_PAGEOFFSET(pHdr.p_vaddr)), prot,
                        MAP_FIXED | MAP_PRIVATE, fd, (pHdr.p_offset - ELF_PAGEOFFSET(pHdr.p_vaddr)));
        printf("mapping = %x\n", map);
        if(map == MAP_FAILED)
          strerror("Mapping failed");

   }
   fprintf(stderr, "Main address: %x\n", entry_addr );
   return entry_addr;

}

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
    //fprintf(stderr, "Opening the File\n");
    //FILE* elf = fopen(argv[1], "rb");
    //fread(buffer, BUF_SIZE, 1, elf);
    //fprintf(stderr, "Starting Loading.. \n");
    //Create the stack 
    //char *stack;                    /* Start of stack buffer */
    //char *stackTop;                 /* End of stack buffer */
    void *stack = mmap(0, STACK_SIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, 0, 0);
    //stack = malloc(STACK_SIZE);
    if (stack == NULL)
        fprintf(stderr, "unable to allocate memeory for the stack using malloc");
    //stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */
    fprintf(stderr, "Stack top : 0x%08x\n", stack);
    stack = create_auxv(envp, stack);
    ptr=load_image(argv[1], stack);
    argc = argc -1;
    //fprintf(stderr, "Main starting with test program at 0x%08x\n", ptr);
    fprintf(stderr,"ENTRY POINT:0x%08x\n",entry_point); 
    pid_t pid = getpid();
    ptrace(PTRACE_DETACH, pid, 0, 0);
    //dump_stack();
    __asm__("movq %0, %%rsp;": :"r"(stack):"%rsp");
    //__asm__("movl %0, %%esp;": :"r"(stack):"%esp"); // For 32 Bit compilation 
    //__asm__("jmp *entry_point");
    return ptr(argc, argv+1, envp);
}
