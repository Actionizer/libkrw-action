#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "libkrw.h"
#include "libkrw_plugin.h"

extern kern_return_t mach_vm_read_overwrite(task_t task, mach_vm_address_t addr, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(task_t task, mach_vm_address_t addr, mach_vm_address_t data, mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t addr, mach_vm_size_t size);

static task_t gKernelTask = MACH_PORT_NULL;

__attribute__((destructor)) static void unload(void) {
  if(gKernelTask != MACH_PORT_NULL) {
    (void)mach_port_deallocate(mach_task_self(), gKernelTask);
    gKernelTask = MACH_PORT_NULL;
  }
}

static int assure_ktask(void)
{
  if(gKernelTask != MACH_PORT_NULL) {
    return 0;
  }

  // hsp4
  task_t port = MACH_PORT_NULL;
  host_t host = mach_host_self();
  kern_return_t ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &port);
  if(ret == KERN_SUCCESS) {
    if(MACH_PORT_VALID(port)) {
      gKernelTask = port;
      return 0;
    }
  } else if(ret == KERN_INVALID_ARGUMENT) {
    libkrw_log(stderr, "[-]: %s: %s: host_get_special_port returned KERN_INVALID_ARGUMENT!\n", TARGET, __FUNCTION__);
    return EPERM;
  } else {
    libkrw_log(stderr, "[-]: %s: %s: host_get_special_port returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
    return EDEVERR;
  }

  // tfp0
  port = MACH_PORT_NULL;
  ret = task_for_pid(mach_task_self(), 0, &port);
  if(ret == KERN_SUCCESS) {
    if(MACH_PORT_VALID(port)) {
        gKernelTask = port;
        return 0;
    }
    libkrw_log(stderr, "[-]: %s: %s: task_for_pid 0 returned KERN_SUCCESS but port is invalid!\n", TARGET, __FUNCTION__);
    return EDEVERR;
  }
  // This is ugly, but task_for_pid really doesn't tell us what's wrong,
  // so the best we can do is guess? :/
  libkrw_log(stderr, "[-]: %s: %s: task_for_pid 0 returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
  return EPERM;
}

static int palera1n_get_kernel_info(uint64_t *kslide_out, uint64_t *kbase_out) {
  if(!kslide_out && !kbase_out) {
    return EINVAL;
  }
  int rmd0 = open("/dev/rmd0", O_RDONLY, 0);
  if (rmd0 < 0) {
    libkrw_log(stderr, "[-]: %s: %s: Could not get paleinfo!\n", TARGET, __FUNCTION__);
    return EDEVERR;
  }
  uint64_t off = lseek(rmd0, 0, SEEK_SET);
  if (off == -1) {
    libkrw_log(stderr, "[-]: %s: %s: Failed to lseek ramdisk to 0\n", TARGET, __FUNCTION__);
    close(rmd0);
    return EBUSY;
  }
  uint32_t pinfo_off;
  ssize_t didRead = read(rmd0, &pinfo_off, sizeof(uint32_t));
  if (didRead != (ssize_t)sizeof(uint32_t)) {
    libkrw_log(stderr,
            "[-]: %s: %s: Read %ld bytes does not match expected %lu bytes\n",
            TARGET, __FUNCTION__, didRead, sizeof(uint32_t));
    close(rmd0);
    return EBUSY;
  }
  off = lseek(rmd0, pinfo_off, SEEK_SET);
  if (off != pinfo_off) {
    libkrw_log(stderr, "[-]: %s: %s: Failed to lseek ramdisk to %u\n", TARGET, __FUNCTION__,
            pinfo_off);
    close(rmd0);
    return EBUSY;
  }
  struct paleinfo {
    uint32_t magic; /* 'PLSH' */
    uint32_t version; /* 2 */
    uint64_t kbase; /* kernel base */
    uint64_t kslide; /* kernel slide */
    uint64_t flags; /* unified palera1n flags */
    char rootdev[0x10]; /* ex. disk0s1s8 */
                        /* int8_t loglevel; */
  } __attribute__((packed));
  struct paleinfo_legacy {
    uint32_t magic;   // 'PLSH' / 0x504c5348
    uint32_t version; // 1
    uint32_t flags;
    char rootdev[0x10];
  };
  struct paleinfo *pinfo_p = malloc(sizeof(struct paleinfo));
  struct paleinfo_legacy *pinfo_legacy_p = NULL;
  didRead = read(rmd0, pinfo_p, sizeof(struct paleinfo));
  if (didRead != (ssize_t)sizeof(struct paleinfo)) {
    libkrw_log(stderr,
            "[-]: %s: %s: Read %ld bytes does not match expected %lu bytes\n",
            TARGET, __FUNCTION__, didRead, sizeof(struct paleinfo));
    close(rmd0);
    free(pinfo_p);
    return EBUSY;
  }
  if (pinfo_p->magic != 'PLSH') {
    close(rmd0);
    pinfo_off += 0x1000;
    pinfo_legacy_p = malloc(sizeof(struct paleinfo_legacy));
    didRead = read(rmd0, pinfo_legacy_p, sizeof(struct paleinfo_legacy));
    if (didRead != (ssize_t)sizeof(struct paleinfo_legacy)) {
      libkrw_log(stderr,
              "[-]: %s: %s: Read %ld bytes does not match expected %lu bytes\n",
              TARGET, __FUNCTION__, didRead, sizeof(struct paleinfo_legacy));
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return EBUSY;
    }
#ifdef DEBUG
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_legacy_p->magic: %s\n",
              TARGET, __FUNCTION__, (char *)&pinfo_legacy_p->magic);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_legacy_p->magic: 0x%X\n",
              TARGET, __FUNCTION__, pinfo_legacy_p->magic);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_legacy_p->version: 0x%Xd\n",
              TARGET, __FUNCTION__, pinfo_legacy_p->version);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_legacy_p->flags: 0x%X\n",
              TARGET, __FUNCTION__, pinfo_legacy_p->flags);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_legacy_p->rootdev: %s\n",
              TARGET, __FUNCTION__, pinfo_legacy_p->rootdev);
#endif
    if (pinfo_legacy_p->magic != 'PLSH') {
      libkrw_log(stderr, "[-]: %s: %s: Detected corrupted paleinfo!\n", TARGET, __FUNCTION__);
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return EFAULT;
    }
    if (pinfo_legacy_p->version != 1U) {
      libkrw_log(stderr, "[-]: %s: %s: Unexpected paleinfo version: %u, expected %u\n",
              TARGET, __FUNCTION__, pinfo_legacy_p->version, 1U);
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return EFAULT;
    }
    lseek(rmd0, pinfo_off - 0x1000, SEEK_SET);
    struct kerninfo {
      uint64_t size;
      uint64_t base;
      uint64_t slide;
      uint32_t flags;
    };
    struct kerninfo *kerninfo_p = malloc(sizeof(struct kerninfo));
    read(rmd0, kerninfo_p, sizeof(struct kerninfo));
    close(rmd0);
    if(kslide_out) {
      *kslide_out = kerninfo_p->slide;
    }
    if(kbase_out) {
      *kbase_out = kerninfo_p->base;
    }
    free(kerninfo_p);
  } else {
#ifdef DEBUG
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->magic: %s\n", TARGET,
            __FUNCTION__, (const char *)&pinfo_p->magic);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->magic: 0x%X\n", TARGET,
            __FUNCTION__, pinfo_p->magic);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->version: 0x%Xd\n", TARGET,
            __FUNCTION__, pinfo_p->version);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->kbase: 0x%llX\n", TARGET,
            __FUNCTION__, pinfo_p->kbase);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->kslide: 0x%llX\n", TARGET,
            __FUNCTION__, pinfo_p->kslide);
    libkrw_log(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->flags: 0x%llX\n", TARGET,
            __FUNCTION__, pinfo_p->flags);
    libkrw_logf(stdout, "[+]: [DEBUG]: %s: %s: pinfo_p->rootdev: %s\n", TARGET,
            __FUNCTION__, pinfo_p->rootdev);
#endif
    if(kslide_out) {
      *kslide_out = pinfo_p->kslide;
    }
    if(kbase_out) {
      *kbase_out = pinfo_p->kbase;
    }
  }
  return 0;
}

static int tfp0_kbase(uint64_t *addr) {
  if(!addr) {
    libkrw_log(stderr, "[-]: %s: %s: provided addr is NULL!\n", TARGET, __FUNCTION__);
    return EFAULT;
  }
  int r = assure_ktask();
  if(r != 0) {
    return r;
  }

  task_dyld_info_data_t info = {};
  uint32_t count = TASK_DYLD_INFO_COUNT;
  kern_return_t ret = task_info(gKernelTask, TASK_DYLD_INFO, (task_info_t)&info, &count);
  if(ret != KERN_SUCCESS) {
    if(!palera1n_get_kernel_info(NULL, addr)) {
      return 0;
    }
    libkrw_log(stderr, "[-]: %s: %s: task info returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
    libkrw_log(stderr, "[-]: %s: %s: failed to get palera1n kernel info!\n", TARGET, __FUNCTION__);
    return EDEVERR;
  }
  // Backwards-compat for jailbreaks that didn't set this
  if(info.all_image_info_addr == 0 && info.all_image_info_size == 0) {
    if(!palera1n_get_kernel_info(NULL, addr)) {
      return 0;
    }
    libkrw_log(stderr, "[-]: %s: %s: task info is NULL!\n", TARGET, __FUNCTION__);
    libkrw_log(stderr, "[-]: %s: %s: failed to get palera1n kernel info!\n", TARGET, __FUNCTION__);
    return ENOTSUP;
  }
  *addr = 0xfffffff007004000 + info.all_image_info_size; // very very legacy :)
  return 0;
}

static int tfp0_kread(uint64_t from, void *to, size_t len) {
  // Overflow
  if(from + len < from || (mach_vm_address_t)to + len < (mach_vm_address_t)to) {
    libkrw_log(stderr, "[-]: %s: %s: read overflow!\n", TARGET, __FUNCTION__);
    return EINVAL;
  }

  int r = assure_ktask();
  if(r != 0) {
    return r;
  }

  mach_vm_address_t dst = (mach_vm_address_t)to;
  for(mach_vm_size_t chunk = 0; len > 0; len -= chunk) {
    chunk = len > 0xff0 ? 0xff0 : len;
    kern_return_t ret = mach_vm_read_overwrite(gKernelTask, from, chunk, dst, &chunk);
    if(ret == KERN_INVALID_ARGUMENT || ret == KERN_INVALID_ADDRESS) {
      libkrw_log(stderr, "[-]: %s: %s: mach_vm_read_overwrite returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
      return EINVAL;
    }
    if(ret != KERN_SUCCESS || chunk == 0) {
      // Check whether we read any bytes at all
      int tmp = dst == (mach_vm_address_t)to ? EDEVERR : EIO;
      libkrw_log(stderr, "[-]: %s: %s: mach_vm_read_overwrite returned %s! 0x%llX bytes were read. (%s)\n", TARGET, __FUNCTION__, mach_error_string(ret), dst, strerror(tmp));
      return tmp;
    }
    from += chunk;
    dst  += chunk;
  }
  return 0;
}

static int tfp0_kwrite(void *from, uint64_t to, size_t len)
{
  // Overflow
  if((mach_vm_address_t)from + len < (mach_vm_address_t)from || to + len < to) {
    libkrw_log(stderr, "[-]: %s: %s: write overflow!\n", TARGET, __FUNCTION__);
    return EINVAL;
  }

  int r = assure_ktask();
  if(r != 0) {
    return r;
  }

  mach_vm_address_t src = (mach_vm_address_t)from;
  for(mach_vm_size_t chunk = 0; len > 0; len -= chunk) {
    chunk = len > 0xff0 ? 0xff0 : len;
    kern_return_t ret = mach_vm_write(gKernelTask, to, src, chunk);
    if(ret == KERN_INVALID_ARGUMENT || ret == KERN_INVALID_ADDRESS) {
      libkrw_log(stderr, "[-]: %s: %s: mach_vm_write returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
      return EINVAL;
    }
    if(ret != KERN_SUCCESS) {
      // Check whether we wrote any bytes at all
      int tmp = src == (mach_vm_address_t)from ? EDEVERR : EIO;
      libkrw_log(stderr, "[-]: %s: %s: mach_vm_write returned %s! 0x%llX bytes were read. (%s)\n", TARGET, __FUNCTION__, mach_error_string(ret), src, strerror(tmp));
      return tmp;
    }
    src += chunk;
    to  += chunk;
  }
  return 0;
}

static int tfp0_kmalloc(uint64_t *addr, size_t size)
{
  int r = assure_ktask();
  if(r != 0) {
    return r;
  }

  mach_vm_address_t va = 0;
  kern_return_t ret = mach_vm_allocate(gKernelTask, &va, size, VM_FLAGS_ANYWHERE);
  if(ret == KERN_SUCCESS) {
    *addr = va;
    return 0;
  }
  if(ret == KERN_INVALID_ARGUMENT) {
    libkrw_log(stderr, "[-]: %s: %s: mach_vm_allocate returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
    return EINVAL;
  }
  if(ret == KERN_NO_SPACE || ret == KERN_RESOURCE_SHORTAGE) {
    libkrw_log(stderr, "[-]: %s: %s: mach_vm_allocate returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
    return ENOMEM;
  }
  libkrw_log(stderr, "[-]: %s: %s: mach_vm_allocate returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
  return EDEVERR;
}

static int tfp0_kdealloc(uint64_t addr, size_t size)
{
  int r = assure_ktask();
  if(r != 0) {
    return r;
  }

  kern_return_t ret = mach_vm_deallocate(gKernelTask, addr, size);
  if(ret == KERN_SUCCESS) {
    return 0;
  }
  if(ret == KERN_INVALID_ARGUMENT) {
    libkrw_log(stderr, "[-]: %s: %s: mach_vm_deallocate returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
    return EINVAL;
  }
  libkrw_log(stderr, "[-]: %s: %s: mach_vm_deallocate returned %s!\n", TARGET, __FUNCTION__, mach_error_string(ret));
  return EDEVERR;
}

__attribute__((used))
int krw_initializer(krw_handlers_t handlers) {
  // Make sure structure version is not lower than what we compiled with
  if (handlers->version < LIBKRW_HANDLERS_VERSION) {
    return EPROTONOSUPPORT;
  }
  // Set the version in the struct that libkrw will read to the version we compled as
  // so that it can test if needed
  handlers->version = LIBKRW_HANDLERS_VERSION;
  int r = assure_ktask();
  if (r != 0) {
    return r;
  }
  handlers->kbase = &tfp0_kbase;
  handlers->kread = &tfp0_kread;
  handlers->kwrite = &tfp0_kwrite;
  handlers->kmalloc = &tfp0_kmalloc;
  handlers->kdealloc = &tfp0_kdealloc;
  return 0;
}
