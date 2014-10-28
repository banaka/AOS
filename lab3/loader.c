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
#include <errno.h>

#define PAGE_SIZE getpagesize()
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (PAGE_SIZE-1))
#define ELF_PAGEALIGN(_v) (((_v) + PAGE_SIZE -1) & ~(PAGE_SIZE - 1))
#define EXIT_SUCCESS 1
#define EXIT_FAILURE 0
#define STACK_SIZE (PAGE_SIZE * 1000)
	
void* entry_point;
void* auxv_base;
unsigned int auxv_phnum, auxv_phdr, auxv_entry, auxv_phent, pHdr_count;

unsigned long memory=0;

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
    unsigned long dest_addr;
    unsigned long entry_addr;
    int i = 0;
    int fd = 0;
    unsigned long bss = NULL;
    int pcount = 0;

    //Read the ELF Structure
    //1. Create the file descriptor 
    printf("\nExce given as argument : %s", file_exe);
    if((fd = open(file_exe,  O_RDWR, 0)) < 0){
		fprintf(stderr, "\nUnable to open the executable");
    }
	
    //2. Create the Elf Variable
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){
	 fprintf(stderr, "\nUnable to create Elf: %s", elf_errmsg(-1));
    }
	//3. Get the Elf header
    if (gelf_getehdr(elf, &elfHdr) == NULL){
         fprintf(stderr, "\nUnable to create Elf Header: %s", elf_errmsg(-1));
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
            fprintf(stderr, "\nUnable to get program Header no %d :%s", i, elf_errmsg(-1));
		}
		
		if(pHdr.p_type != PT_LOAD){
	   		continue;
		}
	
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

		dest_addr = ELF_PAGESTART(pHdr.p_vaddr);
        //printf("\nPageVirtAddr : %x, LoadOffset : %x, Filesize : %d, MemSize : %d, PageStartAddr : %x \n", pHdr.p_vaddr, pHdr.p_offset , pHdr.p_filesz,pHdr.p_memsz, dest_addr);

		unsigned long offsetadjustment = ELF_PAGEOFFSET(pHdr.p_vaddr);
		//Instead of for the filesz Can call this for memsz.. And then set the values after address filesz to 0
		//printf("\ndest_addr:%x pHdr.p_filesz:%x offsetadjustment:%x pHdr.p_offset:%x",dest_addr, pHdr.p_filesz, offsetadjustment, pHdr.p_offset );
        char* exev_mem = mmap(dest_addr, (pHdr.p_filesz + offsetadjustment), pbits, MAP_FIXED | MAP_PRIVATE, fd, (pHdr.p_offset - offsetadjustment));
        if (k == 0) {
			auxv_base = exev_mem;
			k = 1;	
		}
        if(exev_mem == MAP_FAILED)
            fprintf(stderr, "\nMapping failed");
		else{
	    	printf("\nSuccesful mapping 0x%x", exev_mem);
			memory = memory + pHdr.p_memsz;
		}
        if (pHdr.p_memsz > pHdr.p_filesz) {
            // We have a .bss segment
            dest_addr = pHdr.p_vaddr + pHdr.p_filesz;
			dest_addr = ELF_PAGESTART(( dest_addr + PAGE_SIZE - 1)); 
			char *bss_mem = mmap(dest_addr, (pHdr.p_memsz - pHdr.p_filesz), pbits, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0);
			if(bss_mem == MAP_FAILED)
				fprintf(stderr, "\nMapping for bss segment failed");
		    else{
				printf("\nSuccesful mapping of bss 0x%x\n", bss_mem);
				padzero(bss_mem, (pHdr.p_memsz - pHdr.p_filesz));
				//memory = memory + pHdr.p_memsz - pHdr.p_filesz;
				//memset(bss_mem, 0x0, (pHdr.p_memsz - pHdr.p_filesz));
			}
        }
	}
   //fprintf(stderr, "\nEntry Point address: %x", entry_addr );
   return entry_addr;
}

/*Used this function to debug the stack*/
void print_stack( unsigned long *stack, char **argv){
    printf("\nArgc : %d ", *stack);
    while((*argv != NULL) &&( *stack != NULL)){
        stack++;
		argv++;
		printf("\nargv:%s, *argv: %s", *stack, *argv);
    }
	argv++;
	stack++;
    while((*argv != NULL) && (*stack != NULL)){
		printf("\nenvp : %s, %s", *stack, *argv);
        stack++;
		argv++;
    }

    Elf64_auxv_t *auxv;
	argv++;
    auxv = (Elf64_auxv_t *) argv;
    stack++;
	Elf64_auxv_t *stackTop_auxv = (Elf64_auxv_t *) stack;
    printf("\nCreating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        printf("\nstack:0x%08x  type : %d value: %x, type:%d value: %x", stackTop_auxv, stackTop_auxv->a_type, stackTop_auxv->a_un.a_val, auxv->a_type, auxv->a_un.a_val );
        stackTop_auxv++;
    }
	auxv++;
	stackTop_auxv++;
	int *pad = stackTop_auxv;
	printf("\nPadding at the bottomm -> %d", *pad);
	return ;
}

unsigned long *create_auxv_new(char** envp, unsigned long *stack, char **argv, int argc){
     unsigned long *stackTop =  stack;
	*stackTop = argc;
    //printf("\nArgc : %d", *stackTop);
    char *exec_name = argv[1];
	//printf("\nExe name : %s, stackTop:%d", exec_name, *stackTop);
    while(*argv++ != NULL){
        stackTop++;
        *stackTop = *argv;
		//printf("\nargv:%s", *stackTop);
    }
    //stackTop+;
    *stackTop = NULL;

    while(*envp != NULL){
        stackTop++;
        *stackTop = *envp;
		//printf("\nstack:%x envp : %s", stackTop, *stackTop);
		envp++;
    }
    stackTop++;
	*stackTop = NULL;
	envp++;
    Elf64_auxv_t *auxv;
    auxv = (Elf64_auxv_t *) envp;
    stackTop++;
    //printf("\nstack:%x envp : %s", stackTop, *stackTop);
	Elf64_auxv_t *stackTop_auxv;
	stackTop_auxv =  stackTop;
/*	*stackTop_auxv = *auxv;
    printf("\nstack:%x auxv : %d", stackTop_auxv, stackTop_auxv->a_type);
	stackTop_auxv++;
    printf("\nstack:%x auxv : %d", stackTop_auxv, stackTop_auxv->a_type);
*/
    //printf("\nCreating auxv\n");
    for ( ; auxv->a_type != AT_NULL; auxv++) {
        *stackTop_auxv = *auxv; 
		switch (auxv->a_type) {
			case AT_PHENT : stackTop_auxv->a_un.a_val = auxv_phent;
				printf("\nAT_PHENT = %d", stackTop_auxv->a_un.a_val);
				break;
			case AT_PHNUM : stackTop_auxv->a_un.a_val = auxv_phnum;
				printf("\nAT_Phnum = %d", stackTop_auxv->a_un.a_val);
				break;
			case AT_BASE : stackTop_auxv->a_un.a_val = auxv_base ;
				printf("\nAT_base = %x", stackTop_auxv->a_un.a_val);
				break;
			case AT_ENTRY : stackTop_auxv->a_un.a_val = auxv_entry;
				printf("\nAT_entry = %x", stackTop_auxv->a_un.a_val);
				break;
			case AT_EXECFN : stackTop_auxv->a_un.a_val = exec_name;
				printf("\nAT_execfn = %s", stackTop_auxv->a_un.a_val);
				break;
			default: stackTop_auxv->a_un.a_val = auxv->a_un.a_val;
				break;
		}
       // printf("\nstack:%x  type : %d value: %x", stackTop_auxv, stackTop_auxv->a_type, stackTop_auxv->a_un.a_val );
        stackTop_auxv++;
    }
	//stackTop_auxv++;
    stackTop_auxv->a_type = AT_NULL;
    stackTop_auxv->a_un.a_val = NULL;
	auxv++;
	stackTop_auxv++;
	int *pad;
	pad = stackTop_auxv;
	*pad = 0;
	
	//printf("padding at the bottomm -> %d\n", *pad);
	++pad;
	char *cur_stack;
    cur_stack  = pad;
	*cur_stack = "";
	++cur_stack;
	*cur_stack ="";
    //printf("\nRETURNING ++++++> %x\n", stack);
	return stack;
}
/*Used this function to Test the Memory allocation. Basically makes use of the Loader stack for the tst program*/
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
			case AT_BASE : auxv->a_un.a_val = auxv_base ;
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


/*Method to extract the build Id from the input file and the loader file*/
char* get_buildId(char* fileName){
    FILE *file;
    struct stat sb;
    int fd = 0;
    int i=0;
    Elf64_Ehdr *eHdr;
    Elf64_Phdr *pHdr;
    Elf64_Nhdr *nHdr;
    //Read the file in binary Mode...
    file = fopen(fileName,"rb");
    fd = fileno(file);
    if (fd <= 0) {
        fprintf(stderr, "unable to open the file:%s", strerror(errno));
        return EXIT_FAILURE;
    }
    fstat(fd, &sb);
    unsigned long size = sb.st_size;
    eHdr = (Elf64_Ehdr*) mmap(0, size, PROT_READ | PROT_WRITE , MAP_PRIVATE, fd, 0);
    //pHdr = (Elf64_Phdr*)(eHdr->e_phoff + (size_t)eHdr);
    for(pHdr = (Elf64_Phdr*)(eHdr->e_phoff + (size_t)eHdr); pHdr->p_type != PT_NOTE; pHdr++)
        ;
    //nHdr = (Elf32_Nhdr*)(pHdr->p_offset + (size_t)eHdr);
    for (nHdr = (Elf64_Nhdr*)(pHdr->p_offset + (size_t)eHdr); nHdr->n_type != NT_GNU_BUILD_ID;)
    {
        nHdr = (Elf64_Nhdr*)((size_t)nHdr + sizeof(Elf64_Nhdr) + nHdr->n_namesz + nHdr->n_descsz);
    }
    size = nHdr->n_descsz;
    unsigned char * buildId = (unsigned char *)malloc(size);
    memcpy(buildId, (void *)((size_t)nHdr + sizeof(Elf64_Nhdr) + nHdr->n_namesz), size);
    printf("\nFor File : %s ID:",fileName);
    for (i = 0 ; i < size ; ++i)
    {
        printf("%08x",buildId[i]);
    }
    printf("\n");
    fclose(file);
    return buildId;
}

int main(int argc, char** argv, char** envp)
{
    if(argc < 2 ){
        fprintf(stderr, "\nNo File provided in as argument");
		return 0;
    }
    if(elf_version(EV_CURRENT) == EV_NONE){
		fprintf(stderr,"\nUnable to determine the ELF version stored..%s", elf_errmsg(-1));
    }
    char *loader = get_buildId(argv[0]);
    char *test = get_buildId(argv[1]);

    if( strcmp(loader,test) == 0 ){
        printf("\nERROR : Trying to Load the loader....");
        return EXIT_FAILURE;
    }

	//unsigned long *stack = (unsigned long *)(&argv[0]);
	//*((int *)(stack)) = argc - 1;

    unsigned long *stack = mmap(0, STACK_SIZE, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED)
        fprintf(stderr, "\nUnable to allocate memeory for the stack using mmap");
	*stack = argc;
	//printf("Stack top : 0x%08x, top value in stack : %d\n", stack, *stack );
	unsigned long* stack_new;
	stack_new =  stack;

    void* ptr;
	ptr = load_image(argv[1]);
	//auxv_new(envp, argv[1]);
	//fprintf(stderr, "Stack top : 0x%08x\n", stack);
	unsigned long *stack_bottom = create_auxv_new(envp, stack, argv, argc);
	//print_stack(stack, argv);
    printf("\nENTRY ptr:0x%08x",ptr); 
    printf("\nSTACK ptr:%x Memory used :%d\n",stack, memory); 

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
	__asm__("movq %0, %%rsp;": :"a"(stack_new):"%rsp");
    __asm__("jmp *%0": :"a"(ptr):);
	return 0; 
}
