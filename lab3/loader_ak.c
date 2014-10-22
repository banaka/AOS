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

#define STACK_SIZE (1024 * 1024)    /* Stack size for test process */
#define BUF_SIZE 1048576


#define PAGE_SIZE getpagesize()
#define ELF_MIN_ALIGN   PAGE_SIZE
//Could use bitwise XOR TOO
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (PAGE_SIZE-1))
#define ELF_PAGEALIGN(_v) (((_v) + PAGE_SIZE -1) & ~(PAGE_SIZE - 1))
	

void* entry_point;
void* base;

unsigned int auxv_phnum, auxv_phdr, auxv_entry, auxv_phent, pHdr_count;

static int padzero(unsigned long elf_bss){
	unsigned long nbyte;
	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		//if (clear_user((void __user *) elf_bss, nbyte))
		//	return -EFAULT;
		memset((void*)elf_bss, 0x0, nbyte);
	}
	return 0;
}


void* load_image(char *file_exe, void* stack) {
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
    int k = 0;
	//4. For each of the Load segment, call mmap
    for( i=0; i < pHdr_count ; i++){
		if (gelf_getphdr(elf, i, &pHdr) != &pHdr){
            fprintf(stderr, "Unable to get program Header no %d \n", i);
		}
		if(pHdr.p_type != PT_LOAD){
	   		continue;
		}
	
		dest_addr = ELF_PAGESTART(pHdr.p_vaddr);
		printf("PageVirtAddr : %x, LoadOffset : %x, Filesize : %d, MemSize : %d, PageStartAddr : %x \n", pHdr.p_vaddr, pHdr.p_offset , pHdr.p_filesz,pHdr.p_memsz, dest_addr);

		if(!pHdr.p_filesz)
	   		continue;
		if(pHdr.p_filesz > pHdr.p_memsz){
			fprintf(stderr, "load_image: p_filesz > p_memsz\n");
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
            void *bss_vaddr = pHdr.p_vaddr + pHdr.p_filesz;
			//Maybe the allocation needs to be done for the whole of memzize and not for filesz.. 
            //bss_vaddr = ELF_PAGESTART((unsigned long)(bss_vaddr + PAGE_SIZE - 1)); 
            size_t bss_size = (pHdr.p_memsz - pHdr.p_filesz);
            //char *bss_map = mmap((void*)bss_vaddr, bss_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            //if (bss_map == MAP_FAILED)
            //  fprintf(stderr,"bss Section mapping failed");
			//padzero(bss_vaddr);
        }



   }
	
	//Create BSS Mmap 

   fprintf(stderr, "Entry Point address: %x\n", entry_addr );
   return entry_addr;
}


void* create_stack_from_loader(char** envp, void* stack, char **argv, int argc){    
	printf("Getting into Create stack");
	char *exec_name = *argv;
    printf("Exe name : %s", exec_name);

    while(*envp++ != NULL)
		; 
	Elf64_auxv_t *auxv;
	auxv = (Elf64_auxv_t *) envp;
	for ( ; auxv->a_type != AT_NULL; auxv++)
		;
	auxv++;//crossing the auxv when it is = AT_NULL
	char *cur_stack = (char*)auxv;
    int i=0;
	for(i =0; i < 16; i++){
        cur_stack++;
    }
    for(;*cur_stack !=NULL; cur_stack++)
		;	
	char* stackTop =(char*) stack;

	while(cur_stack != argv){
		*stackTop = *cur_stack; 
		cur_stack--; 
		stackTop--;
		printf("stack:%x  newStack:%x  value:%s", cur_stack, stackTop, *cur_stack);
	}
	//need to push the argc onto the stack.. 
    
	char* new_envp = stackTop;
	while(*new_envp++ !=NULL)//Going over the agrv
		;
	new_envp++;
    while(*new_envp++ !=NULL)//Going over the envp
        ;

    auxv = (Elf64_auxv_t *) new_envp;
    printf("\nEditing the auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        printf("stack:0x%08x  type : %d\n", auxv, auxv->a_type);
		switch (auxv->a_type) {
			case AT_PHENT : auxv->a_un.a_val = auxv_phent;
				break;
			case AT_PHNUM : auxv->a_un.a_val = auxv_phnum;
				break;
			case AT_BASE : auxv->a_un.a_val = base ;
				break;
			case AT_ENTRY : auxv->a_un.a_val = auxv_phent;
				break;
			case AT_EXECFN : auxv->a_un.a_val = exec_name;
				break;
			default:
				break;
		}
    }
	return stackTop;
}

/*
void* create_auxv_down(char** envp, void* stack, char **argv, int argc){
    int* stackTopInt = (int*) stack;
	*stackTopInt = argc;
	stackTopInt--;
    printf("\n%x", stackTopInt);
	char* stackTopChar = (char*)stackTopInt;
	*argv++;
    char *exec_name = *argv;
	printf("Exe name : %s", exec_name);
    while(*argv++ != NULL){
        stackTopChar--;
        *stackTopChar = *argv;
		printf("\n%x", stackTopChar);
    }
    stackTopChar--;
    *stackTopChar = NULL;

    while(*envp++ != NULL){
        stackTopChar--;
        *stackTopChar = *envp;
		printf("\n%x envp : %s", stackTopChar, *envp);
    }
    stackTopChar--;
    *stackTopChar = NULL;

    Elf64_auxv_t *auxv;
    // and find ELF auxiliary vectors (if this was an ELF binary) 
    auxv = (Elf64_auxv_t *) envp;
    stackTopChar--;
	Elf64_auxv_t *stackTop = (Elf64_auxv_t *) stackTopChar;

    printf("\nCreating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        printf("stack:0x%08x  type : %d\n", stackTop ,auxv->a_type);
        stackTop--;
        stackTop->a_type = auxv->a_type; 
		switch (auxv->a_type) {
			case AT_PHENT : stackTop->a_un.a_val = auxv_phent;
				break;
			case AT_PHNUM : stackTop->a_un.a_val = auxv_phnum;
				break;
			case AT_BASE : stackTop->a_un.a_val = base ;
				break;
			case AT_ENTRY : stackTop->a_un.a_val = auxv_phent;
				break;
			case AT_EXECFN : stackTop->a_un.a_val = exec_name;
				break;
			default: stackTop->a_un.a_val = getauxval(auxv->a_type);
				break;
		}

    }
	stackTop--;
    stackTop->a_type = AT_NULL;
    stackTop->a_un.a_val = NULL;
	auxv++;
	stackTop--;
	char *cur_stack = (char*)auxv;
	char *stackTopvoid = (char*)stackTop;
	int i=0;
	for(i =0; i < 16; i++){
	    *stackTopvoid = *cur_stack;
        printf("\n%x stack : %x", stackTopvoid, *cur_stack);
        stackTopvoid--;
        cur_stack++;

	}
	while(*cur_stack !=NULL){
        *stackTopvoid = *cur_stack;
        printf("\n%x stack : %x", stackTopvoid, *cur_stack);
		stackTopvoid--;
		cur_stack++;
	}
	*stackTopvoid = NULL;
	return stackTop;
}
*/

void* create_auxv(char** envp, void* stack, char **argv, int argc){
    int* stackTopInt = (int*) stack;
	*stackTopInt = argc;
	stackTopInt++;
    printf("\n%x", stackTopInt);
	char* stackTopChar = (char*)stackTopInt;
	*argv++;
    char *exec_name = *argv;
	printf("Exe name : %s", exec_name);
    while(*argv++ != NULL){
        stackTopChar++;
        *stackTopChar = *argv;
		printf("\n%x", stackTopChar);
    }
    stackTopChar++;
    *stackTopChar = NULL;

    while(*envp++ != NULL){
        stackTopChar++;
        *stackTopChar = *envp;
		printf("\n%x envp : %s", stackTopChar, *envp);
    }
    stackTopChar++;
    *stackTopChar = NULL;

    Elf64_auxv_t *auxv;
    // and find ELF auxiliary vectors (if this was an ELF binary) 
    auxv = (Elf64_auxv_t *) envp;
    stackTopChar++;
	Elf64_auxv_t *stackTop = (Elf64_auxv_t *) stackTopChar;

    printf("\nCreating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        printf("stack:0x%08x  type : %d\n", stackTop ,auxv->a_type);
        stackTop++;
        stackTop->a_type = auxv->a_type; 
		switch (auxv->a_type) {
			case AT_PHENT : stackTop->a_un.a_val = auxv_phent;
				break;
			case AT_PHNUM : stackTop->a_un.a_val = auxv_phnum;
				break;
			case AT_BASE : stackTop->a_un.a_val = base ;
				break;
			case AT_ENTRY : stackTop->a_un.a_val = auxv_phent;
				break;
			case AT_EXECFN : stackTop->a_un.a_val = exec_name;
				break;
			default: stackTop->a_un.a_val = getauxval(auxv->a_type);
				break;
		}

    }
	stackTop++;
    stackTop->a_type = AT_NULL;
    stackTop->a_un.a_val = NULL;
	auxv++;
	stackTop++;
	char *cur_stack = (char*)auxv;
	char *stackTopvoid = (char*)stackTop;
	int i=0;
	for(i =0; i < 16; i++){
	    *stackTopvoid = *cur_stack;
        printf("\n%x stack : %x", stackTopvoid, *cur_stack);
        stackTopvoid++;
        cur_stack++;

	}
	while(*cur_stack !=NULL){
        *stackTopvoid = *cur_stack;
        printf("\n%x stack : %x", stackTopvoid, *cur_stack);
		stackTopvoid++;
		cur_stack++;
	}
	*stackTopvoid = NULL;
	
	return stackTop;
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
    void *stack = mmap(0, STACK_SIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, 0, 0);
    if (stack == NULL)
        fprintf(stderr, "Unable to allocate memeory for the stack using malloc");
    fprintf(stderr, "Stack top : 0x%08x\n", stack);
    printf("argv_1 : %s\n", argv[1]);
    char* ptr=load_image(argv[1], stack);
	argc = argc-1;
	//stack = stack + (STACK_SIZE);
    fprintf(stderr, "Stack top : 0x%08x\n", stack);
	char *stack_bottom = create_auxv(envp, stack, argv, argc);
	//char *stack_bottom = create_auxv_down(envp, stack, argv, argc);
	//char *stack_top = create_stack_from_loader(envp, stack, argv[1], argc);
	//printf("CONFIG_STACK_GROWSUP %d\n",CONFIG_STACK_GROWSUP);
    //fprintf(stderr, "Main starting with test program at 0x%08x\n", ptr);
    fprintf(stderr,"ENTRY POINT:0x%08x\n",ptr); 
   

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
	__asm__("movq %0, %%rsp;": :"r"(stack):"%rsp");
	//ptr = "000000000200105e";
    __asm__("jmp *%0": :"a"(ptr):);
    
	return 0; // ptr(argc, argv+1, envp);
}
