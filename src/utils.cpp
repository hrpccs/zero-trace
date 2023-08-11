#include "utils.h"
#include <ctime>

unsigned long long get_cgroup_id(const char *path) {
  int dirfd, err, flags, mount_id, fhsize;
  union {
    unsigned long long cgid;
    unsigned char raw_bytes[8];
  } id;
  struct file_handle *fhp, *fhp2;
  unsigned long long ret = 0;
  dirfd = AT_FDCWD;
  flags = 0;
  fhsize = sizeof(*fhp);
  fhp = (struct file_handle *)calloc(1, fhsize);
  if (!fhp) {
    return 0;
  }
  err = name_to_handle_at(dirfd, path, fhp, &mount_id, flags);
  if (err >= 0 || fhp->handle_bytes != 8) {
    goto free_mem;
  }
  fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
  fhp2 = (struct file_handle *)realloc(fhp, fhsize);
  if (!fhp2) {
    goto free_mem;
  }
  err = name_to_handle_at(dirfd, path, fhp2, &mount_id, flags);
  fhp = fhp2;
  if (err < 0) {
    goto free_mem;
  }
  memcpy(id.raw_bytes, fhp->f_handle, 8);
  ret = id.cgid;
free_mem:
  free(fhp);
  return ret;
}

unsigned long long get_file_inode(const char* path){
  printf("file path: %s\n", path);
  struct stat buf;
  if (stat(path, &buf) < 0) {
    return 0;
  }
  return buf.st_ino;
}

unsigned long long get_device_id(const char* path){
  printf("device path: %s\n", path);
  struct stat buf;
  if (stat(path, &buf) < 0) {
    return 0;
  }
  return buf.st_rdev;
}

unsigned long long get_timestamp(){
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}