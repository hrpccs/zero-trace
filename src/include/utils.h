#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long long get_cgroup_id(const char *path);
unsigned long long get_file_inode(const char *path);
unsigned long long get_device_id(const char *path);
unsigned long long get_timestamp();