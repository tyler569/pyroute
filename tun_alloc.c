
#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc(char* tun_name) {
    printf("allocating '%s'\n", tun_name);

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("tun_alloc open");
        return -1;
    }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);

    int err = ioctl(fd, TUNSETIFF, (void*)&ifr);
    if (err < 0) {
        perror("tun_alloc ioctl");
        return -1;
    }

    return fd;
}

int set_netns(char* netns_name) {
    char netns_file[256];
    sprintf(netns_file, "/var/run/netns/%s", netns_name);
    printf("file: '%s'\n", netns_file);

    int nsfd = open(netns_file, O_RDONLY);
    if (nsfd < 0) {
        perror("set_netns open");
        return -1;
    }

    int err = setns(nsfd, CLONE_NEWNET);
    if (err != 0) {
        perror("set_netns setns");
        return -1;
    }

    return 0;
}

