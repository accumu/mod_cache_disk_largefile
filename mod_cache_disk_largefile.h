/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOD_CACHE_DISK_LARGEFILE_H
#define MOD_CACHE_DISK_LARGEFILE_H

#include "mod_cache.h"
#include "apr_file_io.h"

#ifdef __linux
/* Linux fallocate() can preallocate a file without changing the visible
   filesize */
#include <linux/falloc.h>
#endif /* __linux */

#define S_MIN(a,b) (((a)<(b))?(a):(b))
#define S_MAX(a,b) (((a)>(b))?(a):(b))

/*
 * include for mod_cache_disk_largefile: Disk Based HTTP 1.1 Cache.
 */

#define VARY_FORMAT_VERSION 3
#define DISK_FORMAT_VERSION_OLD 4
#define DISK_FORMAT_VERSION_OLD2 5
#define DISK_FORMAT_VERSION_OLD3 7
#define DISK_FORMAT_VERSION_OLD4 8
#define DISK_FORMAT_VERSION 9

#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_BODY_SUFFIX   ".body"
#define CACHE_VDIR_SUFFIX   ".vary"

/* Size of buffer used when copying files, doesn't need to be too large as
   we leverage fadvise() for readahead (latency hiding) */
#define CACHE_BUF_SIZE 131072

/* How much the file on disk must have grown beyond the current offset
   before diskcache_bucket_read breaks out of the stat/sleep-loop */

/* The min size is used when called in blocking mode (ie. urgent read) */
#define CACHE_BUCKET_MINCHUNK (256)

/* Limit size returned when backing file not complete, we want to keep
   being called so we can convert to file-based buckets as soon as possible */
#define CACHE_BUCKET_MAXCHUNK (8388608)

/* The absolute maximum size of a bucket, strive to get as
   close to this as possible to reduce the number of buckets for large files.
   Yields 1GB on 32bit platforms, larger on 64bit */
#define CACHE_BUCKET_MAX ((APR_SIZE_MAX>>2)+1)

/* How long to wait for the preferred sized chunks (micro-seconds) */
#define CACHE_BUCKET_PREFERWAIT_BLOCK 10000

/* How long to sleep before retrying while looping (micro-seconds) */
#define CACHE_LOOP_MINSLEEP 4000
#define CACHE_LOOP_MAXSLEEP 100000

/* Size of fadvise (readahead) window */
#define CACHE_FADVISE_WINDOW 8388608

/* Size of window to flush when writing */
#define CACHE_WRITE_FLUSH_WINDOW 8388608

#define AP_TEMPFILE_PREFIX "/"
#define AP_TEMPFILE_BASE   "aptmp"
#define AP_TEMPFILE_SUFFIX "XXXXXX"
#define AP_TEMPFILE_BASELEN strlen(AP_TEMPFILE_BASE)
#define AP_TEMPFILE_NAMELEN strlen(AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX)
#define AP_TEMPFILE AP_TEMPFILE_PREFIX AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX

typedef apr_uint32_t disk_cache_format_t;

typedef struct {
    /* The HTTP status code returned for this response.  */
    apr_int32_t status;
    /* The number of times we've cached this entity. */
    apr_uint32_t entity_version;
    /* Miscellaneous time values. */
    apr_time_t date;
    apr_time_t expire;
    apr_time_t request_time;
    apr_time_t response_time;
    apr_time_t lastmod; /* Last-Modified (if present) */

    /* The body size forced to 64bit to not break when people go from non-LFS
     * to LFS builds */
    apr_int64_t file_size;

    /* body cache file inode forced to 64bit for portability */
    apr_uint64_t bodyinode;

    /* The parsed cache control header */
    cache_control_t control;

    /* The size of the entity name that follows. */
    apr_uint32_t name_len;
    /* The size of the body cache filename */
    apr_uint32_t bodyname_len;
    /* The size of the filename that follows, to fill in r->filename */
    apr_uint32_t filename_len;

    /* On disk:
       * name_len long string of entity name.
       * bodyname_len long string of body cache filename (without cacheroot).
       * filename_len long string of filename
     */
} disk_cache_info_t;


/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;        /* the location of the cache directory */
    apr_size_t root_len;

    /* Temporary file */
    apr_file_t *tfd;
    char *tempfile;

    /* Header cache file */
    apr_file_t *hfd;
    const char *hdrsfile;

    /* Body cache file */
    apr_file_t *bfd_write; /* When opened for writing (APR_EXCL) */
    apr_file_t *bfd_read; /* When opened read-only */
    const char *bodyfile;
    apr_ino_t bodyinode; /* inode of bodyfile, 0 if unknown */

    const char *name;           /* Requested URI without vary bits - 
                                   suitable for mortals. */
    const char *prefix;         /* Prefix to deal with Vary headers */
    char *filename;             /* Filename of requested URL (if present) */
    char **rfilename;           /* Pointer to r->filename */

    apr_off_t initial_size;     /* Size of body as reported upstreams */
    apr_off_t file_size;        /* File size of the cached body */

    apr_time_t lastmod;         /* Last-Modified (if present) */

    /* Flags */
    unsigned int skipstore:1;   /* Set if we should skip storing stuff */
    unsigned int body_done:1;   /* Set when we're done with the body */
    unsigned int can_copy_file:1; /* Set when we can do a simple file copy */
    unsigned int store_body_called:1; /* Set when store_body has been called */

    int header_only;            /* Copy of r->header_only */

    disk_cache_info_t disk_info; /* Disk header information. */

    apr_off_t bytes_sent; /* Copy of r->bytes_sent before calling recall_body */

    apr_pool_t *tpool;          /* Temporary pool, used while processing */
    char *tbuf;                 /* Temporary buffer */
    apr_size_t tbufsize;        /* Size of temp buffer */
} disk_cache_object_t;


/*
 * mod_cache_disk_largefile configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */

/* This gives us 4096 directories (64^2) */
#define DEFAULT_DIRLEVELS 2
#define DEFAULT_DIRLENGTH 1

#define DEFAULT_MIN_BACKGROUND_SIZE 1048576
#define DEFAULT_UPDATE_TIMEOUT apr_time_from_sec(10)

typedef struct {
    const char* cache_root;
    apr_size_t cache_root_len;
    apr_off_t minbgsize;         /* minimum file size to do bg caching */
    apr_interval_time_t updtimeout;   /* Cache update timeout */
} disk_cache_conf;

typedef struct diskcache_bucket_data diskcache_bucket_data;
struct diskcache_bucket_data {
    /** Number of buckets using this memory */
    apr_bucket_refcount  refcount;
    apr_file_t  *fd;
    /** The pool into which any needed structures should
     *  be created while reading from this file bucket */
    apr_pool_t *readpool;
    /* Cache update timeout */
    apr_interval_time_t updtimeout;
    /* The last time we returned data */
    apr_time_t lastdata;
};

/* Stuff needed by the background copy thread */
typedef struct copyinfo copyinfo;
struct copyinfo {
    apr_off_t len;
    /* Source info */
    const char *srcfile;
    apr_finfo_t srcinfo;
    apr_off_t srcoff;
    /* Destination info */
    const char *destfile;
    apr_finfo_t destinfo;
    apr_off_t destoff;

    /* Cache update timeout */
    apr_interval_time_t updtimeout;

    /* Our private pool */
    apr_pool_t *pool;

#if APR_HAS_THREADS
    /* Background process info */
    apr_thread_t *t;
#endif /* APR_HAS_THREADS */
#if APR_HAS_FORK
    apr_proc_t *proc;
#endif /* APR_HAS_FORK */

    /* For logging */
    const server_rec *s;
};

#define CACHE_ENODATA (APR_OS_START_USERERR+1)
#define CACHE_EDECLINED (APR_OS_START_USERERR+2)
#define CACHE_EEXIST (APR_OS_START_USERERR+3)

#endif /*MOD_CACHE_DISK_LARGEFILE_H*/
