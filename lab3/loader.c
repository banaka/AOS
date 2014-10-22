#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <gelf.h>
#include <fcntl.h>

#define BUF_SIZE 1048576

#define PAGE_SIZE getpagesize()
#define ELF_MIN_ALIGN   PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (PAGE_SIZE-1))
#define ELF_PAGEALIGN(_v) (((_v) + PAGE_SIZE -1) & ~(PAGE_SIZE - 1))

#define STACK_SIZE (PAGE_SIZE * 2)
	
void* entry_point;
void* base;
unsigned int auxv_phnum, auxv_phdr, auxv_entry, auxv_phent, pHdr_count;

static int padzero(unsigned long elf_bss, unsigned long nbyte){
	if (nbyte) {
		memset((void*)elf_bss, 0x0, nbyte);
	}
	return 0;
}


void* load_image(char *file_exe) {
    Elf* elf;
    GElf_Ehdr elfHdr;
    GElf_Phdr pHdr;
    GElf_Shdr sHdr;
    char *strings      = NULL;
    unsigned long start_addr   = NULL;
    unsigned long dest_addr;
    unsigned long entry_addr;
    int i = 0;
    char *exec_mem = NULL;
    int fd = 0;
    unsigned long bss = NULL;
    int pcount = 0;

    //Read the ELF Structure
    //1. Create the file descriptor 
    printf("Exce given as argument : %s\n", file_exe);
    if((fd = open(file_exe,  O_RDWR, 0)) < 0){
	fprintf(stderr, "Unable to open the executable\n");
    }
	
    //2. Create the Elf Variable
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){
	 fprintf(stderr, "Unable to create Elf: %s\n", elf_errmsg(-1));
    }
	//3. Get the Elf header
    if (gelf_getehdr(elf, &elfHdr) == NULL){
         fprintf(stderr, "Unable to create Elf Header \n");
    }

    pHdr_count = elfHdr.e_phnum;
    auxv_phent = elfHdr.e_phentsize;
    auxv_entry = elfHdr.e_entry;
    entry_addr = elfHdr.e_entry;
	auxv_phnum = elfHdr.e_phnum;
    int k = 0;
	//4. For each of the Load segment, call mmap
    for( i=0; i < pHdr_count ; i++){
		if (gelf_getphdr(elf, i, &pHdr) != &pHdr){
            fprintf(stderr, "Unable to get program Header no %d \n", i);
		}
		
		if(pHdr.p_type == PT_NOTE){
			//Check the build id matches the build Id of the loader
			fprintf(stderr,"Can be used to get the build Id of the process.... \n");
		}
		if(pHdr.p_type != PT_LOAD){
	   		continue;
		}
	
		dest_addr = ELF_PAGESTART(pHdr.p_vaddr);
		printf("PageVirtAddr : %x, LoadOffset : %x, Filesize : %d, MemSize : %d, PageStartAddr : %x \n", pHdr.p_vaddr, pHdr.p_offset , pHdr.p_filesz,pHdr.p_memsz, dest_addr);

		if(!pHdr.p_filesz)
	   		continue;
		if(pHdr.p_filesz > pHdr.p_memsz){
			printf("load_image: p_filesz > p_memsz\n");
	    	continue;
		}
    
        int pbits = PROT_READ;
        if (pHdr.p_flags & PF_W)
            pbits = pbits | PROT_WRITE;

        if (pHdr.p_flags & PF_X)
            pbits = pbits | PROT_EXEC;


		unsigned long offsetadjustment = ELF_PAGEOFFSET(pHdr.p_vaddr);
		//Instead of for the filesz call this for memsz.. and then set the values after address to 0 
		//char* exev_mem = mmap(dest_addr, (pHdr.p_memsz + offsetadjustment), pbits, MAP_FIXED | MAP_PRIVATE, fd, (pHdr.p_offset - offsetadjustment));
        char* exev_mem = mmap(dest_addr, (pHdr.p_filesz + offsetadjustment), pbits, MAP_FIXED | MAP_PRIVATE, fd, (pHdr.p_offset - offsetadjustment));
        if (k == 0) {
			base = exec_mem;
			k = 1;	
		}
        if(exev_mem == MAP_FAILED)
            fprintf(stderr, "Mapping failed\n");
		else
	    	printf("Succesful mapping 0x%x\n", exev_mem);

        if (pHdr.p_memsz > pHdr.p_filesz) {
            // We have a .bss segment
            dest_addr = pHdr.p_vaddr + pHdr.p_filesz;
			dest_addr = ELF_PAGESTART(( dest_addr + PAGE_SIZE - 1));
			char *bss_mem = mmap(dest_addr, (pHdr.p_memsz - pHdr.p_filesz), pbits, MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0);
			if(bss_mem == MAP_FAILED)
				fprintf(stderr, "Mapping for bss segment failed\n");
		    else{
				printf("Succesful mapping of bss 0x%x\n", bss_mem);
				padzero(bss_mem, (pHdr.p_memsz - pHdr.p_filesz));
				//memset(bss_mem, 0x0, (pHdr.p_memsz - pHdr.p_filesz));
			}
			//Maybe the allocation needs to be done for the whole of memzize and not for filesz.. 
        }
	}

   fprintf(stderr, "Entry Point address: %x\n", entry_addr );
   return entry_addr;
}

unsigned long *create_auxv_new(char** envp, unsigned long *stack, char **argv, int argc){
     unsigned long *stackTop =  stack;
	*stackTop = argc;
    printf("\nHAHDHDHDHHDDH%d\n", *stackTop);
	stackTop++;
	//char* stackTopChar = (char*)stackTopInt;
	//*stackTop = "dhfdhdf";
    //printf("\nHAHDHDHidgndDHHDDH%s\n", *stackTop);
	*argv++;
    char *exec_name = *argv;
	printf("Exe name : %s", exec_name);
    while(*argv++ != NULL){
        stackTop++;
        *stackTop = *argv;
		printf("\n%x", stackTop);
    }
    stackTop++;
    *stackTop = NULL;

    while(*envp++ != NULL){
        stackTop++;
        *stackTop = *envp;
		printf("\n%x envp : %s", stackTop, *envp);
    }
    stackTop++;
    *stackTop = NULL;

    Elf64_auxv_t *auxv;
    // and find ELF auxiliary vectors (if this was an ELF binary) 
    auxv = (Elf64_auxv_t *) envp;
    stackTop++;
	Elf64_auxv_t *stackTop_auxv = (Elf64_auxv_t *) stackTop;

    printf("\nCreating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        printf("stack:0x%08x  type : %d\n", stackTop_auxv ,auxv->a_type);
        stackTop_auxv++;
        stackTop_auxv->a_type = auxv->a_type; 
		switch (auxv->a_type) {
			case AT_PHENT : stackTop_auxv->a_un.a_val = auxv_phent;
				printf("AT_PHENT = %d\n", stackTop_auxv->a_un.a_val);
				break;
			case AT_PHNUM : stackTop_auxv->a_un.a_val = auxv_phnum;
				printf("AT_Phnum = %d\n", stackTop_auxv->a_un.a_val);
				break;
			case AT_BASE : stackTop_auxv->a_un.a_val = base ;
				printf("AT_base = %x\n", stackTop_auxv->a_un.a_val);
				break;
			case AT_ENTRY : stackTop_auxv->a_un.a_val = auxv_entry;
				printf("AT_entry = %x\n", stackTop_auxv->a_un.a_val);
				break;
			case AT_EXECFN : stackTop_auxv->a_un.a_val = exec_name;
				printf("AT_execfn = %s\n", stackTop_auxv->a_un.a_val);
				break;
			default: stackTop_auxv->a_un.a_val = auxv->a_un.a_val;
				break;
		}

    }
	stackTop_auxv++;
    stackTop_auxv->a_type = AT_NULL;
    stackTop_auxv->a_un.a_val = NULL;
	auxv++;
	stackTop_auxv++;
	int *pad = stackTop_auxv;
	*pad = 0;
	
	printf("padding at the bottomm -> %d\n", *pad);
	char *cur_stack = pad;
	*cur_stack = "";
	*(cur_stack++) = "";

	return stack;
}

void auxv_new(char **envp, char *exec_name){
	while(*envp++ != NULL)
		;

	Elf64_auxv_t *auxv;
	auxv = (Elf64_auxv_t *) envp;

    printf("\nModifying auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
		switch (auxv->a_type) {
			case AT_PHENT : auxv->a_un.a_val = auxv_phent;
				break;
			case AT_PHNUM : auxv->a_un.a_val = auxv_phnum;
				printf("AT_Phnum = %d\n", auxv->a_un.a_val);
				break;
			case AT_BASE : auxv->a_un.a_val = base ;
				printf("AT_base = %x\n", auxv->a_un.a_val);
				break;
			case AT_ENTRY : auxv->a_un.a_val = auxv_entry;
				printf("AT_entry = %x\n", auxv->a_un.a_val);
				break;
			case AT_EXECFN : auxv->a_un.a_val = exec_name;
				printf("AT_execfn = %s\n", auxv->a_un.a_val);
				break;
			default:
				break;
		}
    }
}


int main(int argc, char** argv, char** envp)
{
    if(argc < 2 ){
        fprintf(stderr, "No File provided in as argument\n");
		return 0;
    }
    if(elf_version(EV_CURRENT) == EV_NONE){
		fprintf(stderr,"Unable to determine the ELF version stored..%s\n", elf_errmsg(-1));
    }
	
	unsigned long *stack_orig = (unsigned long *)(&argv[0]);
	*((int *)(stack_orig)) = argc - 1;
/*
    unsigned long *stack = mmap(0, 1200, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED)
        fprintf(stderr, "Unable to allocate memeory for the stack using malloc");
	printf("\n Stack Value : %d\n", *(stack+1));
	*stack = argc;
	printf("\n Value in stack with argv : %d\n", *(stack));
    printf("Stack top : 0x%08x, nextaddress in stack : 0x%08x\n", stack, stack + 1);
	unsigned long* stack_new =  stack;
*/
    void* ptr;
	printf("Value in Stack ->%d\n\n", *(stack_orig)); 
	ptr = load_image(argv[1]);
	auxv_new(envp, argv[1]);
	//fprintf(stderr, "Stack top : 0x%08x\n", stack);
	//unsigned long *stack_bottom = create_auxv_new(envp, stack, argv, argc);
	//char *stack_bottom = create_auxv_down(envp, stack, argv, argc);
	//stack = create_stack_from_loader(envp, stack, argv, argc);

    printf("ENTRY ptr:0x%08x\n",ptr); 
    printf("STACK ptr:%x\n",stack_orig); 
   
	__asm__("xor %%rdx, %%rdx" : : :"%rdx"); 
	__asm__("xor %%rax, %%rax" : : :"%rax"); 
	__asm__("xor %%rbx, %%rbx" : : :"%rbx"); 
	__asm__("xor %%rcx, %%rcx" : : :"%rcx");
    __asm__("xor %%r8, %%r8" : : :"%r8"); 
	__asm__("xor %%r9, %%r9" : : :"%r9"); 
	__asm__("xor %%r10, %%r10" : : :"%r10"); 
	__asm__("xor %%r11, %%r11" : : :"%r11"); 
	__asm__("xor %%r12, %%r12" : : :"%r12"); 
	__asm__("xor %%r13, %%r13" : : :"%r13"); 
	__asm__("xor %%r14, %%r14" : : :"%r14"); 
	__asm__("xor %%r15, %%r15" : : :"%r15"); 
	__asm__("xor %%rdi, %%rdi" : : :"%rdi"); 
    __asm__("xor %%rsi, %%rsi" : : :"%rsi");
	__asm__("xor %%rdi, %%rdi" : : :"%rdi");
	__asm__("movq %0, %%rsp;": :"a"(stack_orig):"%rsp");
	__asm__("xor %%rax, %%rax" : : :"%rax"); 
	__asm__("xor %%rdx, %%rdx" : : :"%rdx"); 
    __asm__("jmp *%0": :"a"(ptr):);
    
	return 0; // ptr(argc, argv+1, envp);
}
