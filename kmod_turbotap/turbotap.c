/*
 *  turbotap.c - The kernel module.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/if_tun.h>
#include <linux/net.h>
#include <linux/syscalls.h>

#include <net/sock.h>

// Module AUTHOR and DESCription
#define AUTHOR "Mohsin KAZMI"
#define DESC "Provide interfaces to userspace for turbo tap driver"

/*
 * TURBO TAP minor number
 * FIXME: we choose our own that number, though it should be standardized and
 * should available through linux kernel
 */
#define TURBOTAP_MINOR 254

/*
 * TURBO TAP IOCTL number
 * FIXME: we choose our own that number, though it should be standardized and
 * should available through linux kernel
 */
#define TUNGETSOCKFD _IOR('T', 224, int)

//max number of turbotap devices
#define MAX_TAP_INTERFACES 1024

struct turbotap_sock_fd {
	atomic_t refcount;
	struct socket *tun_sock;
	struct file *tun_file;
	struct socket *turbotap_sock;
	int tun_fd;
	int turbotap_fd;
};

static struct turbotap_interfaces {
	struct turbotap_sock_fd *tubotap_sf[MAX_TAP_INTERFACES];
	int interfaces;
} turbotap_interfaces;

static inline unsigned find_next_sock(int i, bool flag)
{
	static unsigned count;

	if (flag)
		count = 0;

	while (i < MAX_TAP_INTERFACES) {
		if (count < turbotap_interfaces.interfaces &&
			turbotap_interfaces.tubotap_sf[i] != NULL) {
			count++;
			break;
		}

		i++;
	}
	return i;
}

// Implement the iterator on all turbotap interfaces
#define for_each_turbo_sock(i) \
	for (i = find_next_sock(0, true); \
		i < MAX_TAP_INTERFACES; \
		i = find_next_sock(++i, false))

static inline bool test_max_interfaces_count(void)
{
	if (unlikely(turbotap_interfaces.interfaces >= MAX_TAP_INTERFACES))
		return false;

	return true;
}

static inline bool test_min_interfaces_count(void)
{
	if (unlikely(turbotap_interfaces.interfaces <= 0))
		return true;

	return false;
}

static inline bool interfaces_count_inc(void)
{
	if (test_max_interfaces_count()) {
		turbotap_interfaces.interfaces++;
		return true;
	}

	return false;
}

static inline bool interfaces_count_dec(void)
{
	if (!test_min_interfaces_count()) {
		turbotap_interfaces.interfaces--;
		return true;
	}

	return false;
}

/*
 * It finds first free index out of 1024 and it increments the interface count.
 * It returns the newly found index
 */
static inline int get_free_interface_index(void)
{
	int i = 0;

	while (i < MAX_TAP_INTERFACES) {
		if (turbotap_interfaces.tubotap_sf[i] == NULL) {
			interfaces_count_inc();
			break;
		}
		i++;
	}

	return i;
}

// Find interface index from interface itself
static inline int find_interface_index(struct turbotap_sock_fd *turbotap_sf)
{
	int i;

	for_each_turbo_sock(i) {
		if (turbotap_interfaces.tubotap_sf[i] == turbotap_sf) {
			break;
		}
	}

	return i;
}

// It finds the interface for given sock
static inline struct turbotap_sock_fd *find_interface_from_sock(struct socket *sock)
{
	int i;

	if (test_min_interfaces_count())
		return ERR_PTR(-EINVAL);

	/*
	 * check that tubotap_sf[at index i] must not be NULL and
	 * turbotap_sock element should be equal to sock.
	 */
	for_each_turbo_sock(i) {
		if (sock == turbotap_interfaces.tubotap_sf[i]->turbotap_sock) {
			return turbotap_interfaces.tubotap_sf[i];
		}
	}

	printk(KERN_ERR "Error: do not find an interface\n");
	return NULL;
}

static struct turbotap_sock_fd *interface_alloc(void)
{
	struct turbotap_sock_fd *turbotap_sf;

	if(!test_max_interfaces_count()) {
		printk(KERN_ERR "Error: MAX number of interfaces reached\n");
		return ERR_PTR(-EUSERS);
	}

	turbotap_sf = kmalloc(sizeof(*turbotap_sf), GFP_KERNEL);
        if (!turbotap_sf)
		goto err_mem_alloc;

	/*
	 * We have successfully allocated the memory for new interface.
	 * Set the newly created interface to turbotap_interfaces struct for
	 * future reference and use. First increment the interface reference
	 * count, so that it can be used as in-use interface.
	 *
	 * It gets the index using free interface index for new interface.
	 */
        atomic_set(&turbotap_sf->refcount, 1);

	turbotap_interfaces.tubotap_sf[get_free_interface_index()] = turbotap_sf;
	return turbotap_sf;

err_mem_alloc:
	interfaces_count_dec();
	return ERR_PTR(-ENOMEM);
}

static void interface_free(struct turbotap_sock_fd *turbotap_sf)
{
	int i;
	int r = atomic_sub_return(1, &turbotap_sf->refcount);

	if (unlikely(r < 0))
		printk(KERN_ERR "Error: in reference count\n");

	i = find_interface_index(turbotap_sf);

	if (likely(interfaces_count_dec())) {
		turbotap_interfaces.tubotap_sf[i] = NULL;
	}
	kfree(turbotap_sf);
}

static inline int turbotap_sock_map_fd(struct socket *sock, int flags)
{
         struct file *newfile;
         int fd = get_unused_fd_flags(flags);
         if (unlikely(fd < 0))
                 return fd;

         newfile = sock_alloc_file(sock, flags, NULL);
         if (likely(!IS_ERR(newfile))) {
                 fd_install(fd, newfile);
                 return fd;
         }

         put_unused_fd(fd);
         return PTR_ERR(newfile);
}

static int turbotap_socket_create(struct socket **turbo_sock)
{
	int flags;
	int type = SOCK_RAW;
	int protocol = ETH_P_ALL; // may be need to set to 0
	int family = PF_PACKET;
	int ret;
	struct socket *sock;

	flags = type & ~SOCK_TYPE_MASK;
        if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) {
		printk(KERN_ERR "Error: in flags\n");
		return -EINVAL;
        }
        type &= SOCK_TYPE_MASK;

        if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	ret = sock_create(family, type, protocol, &sock);
	if (ret < 0) {
		printk(KERN_ERR "Error: in sock create\n");
		return ret;
	}
	ret = turbotap_sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
	if (ret < 0) {
		printk(KERN_INFO "Error: in sock map fd\n");
		goto out_release;
	}
	*turbo_sock = sock;

	return ret;

out_release:
	sock_release(sock);
	return ret;
}

// Call the sendmsg and recvmsg
// TODO: check in msghdr that there should be no control data in msg m
static int turbotap_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct turbotap_sock_fd *turbotap_sf = find_interface_from_sock(sock);
	int len;

	if (unlikely(!turbotap_sf))
		return -1;

	//printk(KERN_DEBUG "total number of IOV %d\n",iov_iter_count(&m->msg_iter));
	len = turbotap_sf->tun_sock->ops->sendmsg(turbotap_sf->tun_sock, &(*m), total_len);
	//printk(KERN_DEBUG "Sent data length %d\n", len);

	return len;
}

static int turbotap_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len, int flags)
{
	struct turbotap_sock_fd *turbotap_sf = find_interface_from_sock(sock);
	int len;

	if (unlikely(!turbotap_sf))
		return -1;

	len = turbotap_sf->tun_sock->ops->recvmsg(turbotap_sf->tun_sock, &(*m), total_len, flags);
	//printk(KERN_DEBUG "Received data length %d\n", len);

	return len;
}

//Implement the code to release the tap devices here
static int turbotap_release(struct socket *sock)
{
	struct turbotap_sock_fd *turbotap_sf = find_interface_from_sock(sock); // need to decide which interface

	if (!turbotap_sf)
		return -1;

	printk(KERN_INFO "Release Socket %d\n", turbotap_sf->tun_fd);
	if(turbotap_sf->tun_file->f_op->release)
		turbotap_sf->tun_file->f_op->release(NULL,turbotap_sf->tun_file);

	interface_free(turbotap_sf);

	return 0;
}

static const struct proto_ops turbotap_socket_ops = {
	.owner	= THIS_MODULE,
	.release = turbotap_release,
        .sendmsg = turbotap_sendmsg,
        .recvmsg = turbotap_recvmsg,
};

/*
 * It is main IOCTL routine which handles all ioctl related to turbotap.
 * This function is registered to do all HACKs. It is the main culprit
 * as it oprhans the PF_PACKET socket and also set the pointers to call
 * the tun functions tun_sendmsg and tun_recvmsg for send and receive.
 */
static long turbotap_chr_ioctl(struct file *file,
                          unsigned int cmd, unsigned long arg)
{
	struct socket *tun_sock;
	struct turbotap_sock_fd *turbotap_sf;
	struct socket *turbotap_sock;
	struct file *tun_file;
	int ret;

	if (cmd == TUNGETSOCKFD) {
		void __user *argp = (void __user *)arg;
		int tun_fd = -1;

		if (copy_from_user(&tun_fd, argp, sizeof (int)))
			return -EFAULT;

		printk(KERN_DEBUG "tun fd value %d\n", tun_fd);

		/*
		 * Allocate the new interface
		 */
		turbotap_sf = interface_alloc();
		if (IS_ERR(turbotap_sf))
			return PTR_ERR(turbotap_sf);

		/*
		 * Get the tun sock using tun fd, user is responsible for
		 * providing it.
		 */
		tun_file = fget(tun_fd);
		if (!tun_file)
			return -EBADF;

		tun_sock = tun_get_socket(tun_file);
		if (IS_ERR(tun_sock)) {
			ret = -ENOTSOCK;
			goto err;
		}
		else {
			turbotap_sf->tun_sock = tun_sock;
			turbotap_sf->tun_file = tun_file;
			turbotap_sf->tun_fd = tun_fd;
			printk(KERN_DEBUG "Successfully get the tun socket\n");
		}

		/*
		 * Create a new socket and return the fd to that socket
		 */
		ret = turbotap_socket_create(&turbotap_sock);
		if (ret < 0)
			goto err;

		if (!turbotap_sock) {
			ret = -1;
			goto err;
		}

		turbotap_sf->turbotap_sock = turbotap_sock;
		turbotap_sf->turbotap_fd = ret;

		/*
		 * HACK:
		 * It is ugly but there is no choice to over power on PF_PACKETs.
		 * Here it kicks out the PF_PACKET's ops which becomes orphan
		 * and set pointer to new ops.
		 */
		if (turbotap_sf->tun_sock->ops->sendmsg &&
					turbotap_sf->tun_sock->ops->recvmsg) {
			/*
			 * put the module for PF_PACKET as we are hacking its
			 * ops to use them internally :-)
			 */
			module_put(turbotap_sf->turbotap_sock->ops->owner);

			turbotap_sf->turbotap_sock->ops = &turbotap_socket_ops;
			printk(KERN_DEBUG "set pointer to new ops\n");

			// get the module for new owner which is THIS_MODULE :D
			if (!try_module_get(turbotap_sf->turbotap_sock->ops->owner))
				printk(KERN_ERR "Error in getting module\n");

			printk(KERN_INFO "IOCTL Successful\n");
		}
		else {
			printk(KERN_ERR "Fail to set pointer to new ops\n");
			ret = -1;
			goto err;
		}
	}
	else {
		printk(KERN_ERR "IOCTL fail\n");
		return -1;
	}

	return ret;
err:
	interface_free(turbotap_sf);
	return ret;
}

static const struct file_operations turbotap_tun_fops = {
        .owner  = THIS_MODULE,
        .unlocked_ioctl = turbotap_chr_ioctl,
};

static struct miscdevice turbotap_tun_miscdev = {
        .minor = TURBOTAP_MINOR,
        .name = "turbotap",
        .nodename = "net/turbotap",
        .fops = &turbotap_tun_fops,
};

int __init turbotap_module_start(void)
{
	int ret = 0;

	ret = misc_register(&turbotap_tun_miscdev);
        if (ret) {
                printk(KERN_ERR "Can't register misc device %d\n", TURBOTAP_MINOR);
                goto err_misc;
        }

	printk(KERN_INFO "Turbotap module init\n");

	return 0;

err_misc:
	return -1;
}

void __exit turbotap_module_end(void)
{
	unsigned int i;

	for_each_turbo_sock(i) {
		if (turbotap_interfaces.tubotap_sf[i]->turbotap_sock)
			sock_release(turbotap_interfaces.tubotap_sf[i]->turbotap_sock);
	}

	misc_deregister(&turbotap_tun_miscdev);
	printk(KERN_INFO "turbotap module exit\n");
}

module_init(turbotap_module_start);
module_exit(turbotap_module_end);

/*
 * GPL aligned coding design.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_ALIAS_MISCDEV(TURBOTAP_MINOR);
MODULE_ALIAS("devname:turbotap");
