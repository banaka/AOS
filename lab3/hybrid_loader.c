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
#include <signal.h>

#define PAGE_SIZE getpagesize()
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (PAGE_SIZE-1))
#define ELF_PAGEALIGN(_v) (((_v) + PAGE_SIZE -1) & ~(PAGE_SIZE - 1))
#define EXIT_SUCCESS 1
#define EXIT_FAILURE 0
#define STACK_SIZE (PAGE_SIZE * 1000)
#define PAGE_LOAD_SIZE PAGE_SIZE *2


#define handler_error(msg) do { perror(msg); exit(-1); } while (0)
typedef int bool;
#define true 1
#define false 0
	
void* entry_point;
void* auxv_base;
unsigned int auxv_phnum, auxv_phdr, auxv_entry, auxv_phent, pHdr_count;

unsigned long memory = 0;

struct load_details{
    unsigned long vaddr;    //Start Virtual Address
    unsigned long offset;   //offset in the file
    size_t size;            //size of the segment
    int prot;               //Protection bits for the segment
};

struct map_contents {
    char* fileName;             //Saving the File name in order to be able to open the File on demand and load a page from it
    struct load_details *bss;
}map_contents;

static int padzero(unsigned long elf_bss, unsigned long nbyte){
	if (nbyte) {
		memset((void*)elf_bss, 0x0, nbyte);
	}
	return 0;
}

static int demand_paging(unsigned long fault_addr){
    //1. Check which region the address belongs to
    //2. Map the region
    if (((map_contents.bss)->vaddr <= fault_addr) && (fault_addr <= ((map_contents.bss)->vaddr + (map_contents.bss)->size ))){
        fprintf(stderr,"\nBSS Segment Page fault: fault address:%x, vaddr:%x, size:%x", fault_addr, (map_contents.bss)->vaddr ,(map_contents.bss)->size);
    	unsigned long dest_addr;
    	dest_addr = ELF_PAGESTART(fault_addr);
    	//the offset that needs to be added to be able to load the page from the file..
    	unsigned long page_offset = (map_contents.bss)->offset + dest_addr - (map_contents.bss)->vaddr ;
    	if( dest_addr < (map_contents.bss)->vaddr){
        	page_offset = (map_contents.bss)->offset - ELF_PAGEOFFSET((map_contents.bss)->vaddr);
    	}
    	fprintf(stderr,"\nAddr:%x, dest_addr:%x, prot:%d, offset:%x, page_offset:%x ", fault_addr, dest_addr, (map_contents.bss)->prot, (map_contents.bss)->offset, page_offset);
    	char* exev_mem ;
        //for bss segment, we do not need to load the page from the File but need to call memset(0);
        exev_mem = mmap(dest_addr, PAGE_LOAD_SIZE, (map_contents.bss)->prot, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
    	if(exev_mem == MAP_FAILED){
        	fprintf(stderr,"\nMapping failed:%s",strerror(errno));
        	printf("\nMapping failed:%s",strerror(errno));
        	return EXIT_FAILURE;
    	}
		if(dest_addr < (map_contents.bss)->vaddr)
            padzero((map_contents.bss)->vaddr, PAGE_LOAD_SIZE - ELF_PAGEOFFSET((map_contents.bss)->vaddr));
        else
            padzero(exev_mem, PAGE_LOAD_SIZE);
    	//fprintf(stderr,"\nSuccesful mapping 0x%x", exev_mem);
    	memory = memory + PAGE_LOAD_SIZE;
    	return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
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
			printf("\nload_image: p_filesz > p_memsz");
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
			memory = memory + pHdr.p_filesz;
		}
        if (pHdr.p_memsz > pHdr.p_filesz) {
          	// We have a .bss segment
            struct load_details *bss_segment = (struct load_details *)malloc(sizeof(struct load_details));
            bss_segment->vaddr = pHdr.p_vaddr + pHdr.p_filesz;
            bss_segment->size = pHdr.p_memsz - pHdr.p_filesz ; // pHdr.p_filesz + offsetadjustment;
            bss_segment->prot = pbits;
            bss_segment->offset = pHdr.p_offset + pHdr.p_filesz;
            map_contents.bss = bss_segment;
        }
	}
   //fprintf(stderr, "\nEntry Point address: %x", entry_addr );
   return entry_addr;
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

static void handler(int sig, siginfo_t *si, void *unused) {
    //printf("\nGot SIGSEGV at address: %lx", (unsigned long) si->si_addr);
    int ret = demand_paging(si->si_addr);
    printf("\nSeg fault at: %x, memory usage:%d",(unsigned long) si->si_addr, memory );
    if(ret == EXIT_FAILURE){
        printf("\nIllegal memory access\n", strerror(errno));
       	signal(sig, SIG_DFL);
		//exit(-1);
    }
    return;
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
	printf("Stack top : 0x%08x, tpop value in stack : %d\n", stack, *stack );
	unsigned long* stack_new;
	stack_new =  stack;

    void* ptr;
	ptr = load_image(argv[1]);
	//auxv_new(envp, argv[1]);
	//fprintf(stderr, "Stack top : 0x%08x\n", stack);
	unsigned long *stack_bottom = create_auxv_new(envp, stack, argv, argc);
	//print_stack(stack, argv);
    printf("\nENTRY ptr:0x%08x",ptr); 
    printf("\nSTACK ptr:%x pages :%d\n",stack, memory); 

    /* set up signal handler */
    struct sigaction sa;
    //To restart functions if interrupted by handler (as handlers called asynchronously)
    //sa.sa_flags = SA_RESTART;
    sa.sa_flags = SA_SIGINFO;
    //Set zero
    sigemptyset(&sa.sa_mask);
    //If want to block some signals while current one is executing.
    //sigaddset( &sa.sa_mask, SIGSEGV );
    sa.sa_sigaction = handler;
    //Register signals
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        handler_error("sigaction");

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
