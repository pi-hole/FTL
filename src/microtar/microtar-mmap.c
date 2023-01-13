/*
 * Copyright (c) 2017 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <string.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "microtar.h"
#include "microtar-mmap.h"

typedef struct {
  char name[100];
  char mode[8];
  char owner[8];
  char group[8];
  char size[12];
  char mtime[12];
  char checksum[8];
  char type;
  char linkname[100];
  char _padding[255];
} mtar_raw_header_t;

struct mmap_info {
  int fd;
  unsigned char *data;
  size_t size;
};

static int file_write(mtar_t *tar, const void *data, size_t size) {
  memcpy(((struct mmap_info*) tar->stream)->data + tar->pos, data, size);
  return MTAR_ESUCCESS;
}

static int file_read(mtar_t *tar, void *data, size_t size) {
  memcpy(data, ((struct mmap_info*) tar->stream)->data + tar->pos, size);
  return MTAR_ESUCCESS;
}

static int file_seek(mtar_t *tar, size_t offset) {
  tar->pos = offset;
  if (tar->pos > ((struct mmap_info*) tar->stream)->size) {
    return MTAR_ESEEKFAIL;
  }
  return MTAR_ESUCCESS;
}

static int file_close(mtar_t *tar) {
  munmap(
    ((struct mmap_info*) tar->stream)->data,
    ((struct mmap_info*) tar->stream)->size
  );
  close(((struct mmap_info*) tar->stream)->fd);
  return MTAR_ESUCCESS;
}


int mtar_open_mapped(mtar_t *tar, const char *filename) {
  int err;
  mtar_header_t h;
  struct stat st;
  struct mmap_info *info;

  /* Init tar struct and functions */
  memset(tar, 0, sizeof(*tar));
  tar->write = file_write;
  tar->read = file_read;
  tar->seek = file_seek;
  tar->close = file_close;

  /* Open file */
  info = malloc(sizeof(struct mmap_info));

  info->fd = open(filename, O_RDONLY);
  if (info->fd == -1) {
    mtar_close(tar);
    return MTAR_EOPENFAIL;
  }
  /* Get file info */
  fstat(info->fd, &st);
  /* Map file memory */
  info->data = mmap(
    NULL,
    st.st_size,
    PROT_READ,
    MAP_SHARED,
    info->fd,
    0
  );
  info->size = st.st_size;
  tar->stream = info;
  /* Read first header to check it is valid if mode is `r` */
  err = mtar_read_header(tar, &h);
  if (err != MTAR_ESUCCESS) {
    mtar_close(tar);
    return err;
  }
  mtar_rewind(tar);

  /* Return ok */
  return MTAR_ESUCCESS;
}


int mtar_get_mapped(mtar_t *tar, const char* filename, const void **ptr) {
  int err;
  mtar_header_t h;

  /* Rewind file */
  mtar_rewind(tar);
  /* Find file point */
  while ( (err = mtar_read_header(tar, &h)) == MTAR_ESUCCESS ) {
    if ( !strcmp(h.name, filename) ) {
      tar->pos += sizeof(mtar_raw_header_t);
      break;
    }
    mtar_next(tar);
  }
  /* Return mapped file pointer */
  *ptr = ((struct mmap_info*) tar->stream)->data + tar->pos;
  return MTAR_ESUCCESS;
}

int mtar_get_pointer(mtar_t *tar, const void **ptr) {
  tar->pos += sizeof(mtar_raw_header_t);
  /* Return pointer to data after header */
  *ptr = ((struct mmap_info*) tar->stream)->data + tar->pos;
  return MTAR_ESUCCESS;
}
