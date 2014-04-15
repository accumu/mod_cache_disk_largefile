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

#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "mod_cache.h"
#include "mod_cache_disk_largefile.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "apr_portable.h"
#include "http_main.h"

/*
 * mod_cache_disk_largefile: Disk Based HTTP 1.1 Cache.
 *
 * Flow to Find the right cache file:
 *   Incoming client requests an URL
 *   Generate <hash>.header from URL
 *   Open <hash>.header
 *   Read in <hash>.header file format identifier, which might be:
 *      VARY_FORMAT_VERSION - Vary headers
 *      DISK_FORMAT_VERSION - Metadata and headers for a cached file
 *      Anything else       - Unknown header format, remove and return.
 *
 *   If VARY_FORMAT_VERSION (Contains a list of Vary Headers):
 *      Use each header name with our request values (headers_in) to
 *      regenerate <hash>.header using HeaderName+HeaderValue+URL,
 *      open it, read format (must be DISK_FORMAT_VERSION).
 *
 * VARY_FORMAT_VERSION:
 *   apr_uint32_t format;
 *   apr_time_t expire;
 *   apr_array_t vary_headers (delimited by CRLF)
 *
 * DISK_FORMAT_VERSION:
 *   disk_cache_info_t
 *   entity name (dobj->name) [length is in disk_cache_info_t->name_len]
 *   bodyfile (dobj->bodyfile) [length is in disk_cache_info_t->bodyname_len]
 *   optional filename (r->filename)
 *                      [length is in disk_cache_info_t->filename_len]
 *   r->headers_out (see on disk header format below)
 *   r->headers_in
 *
 * On disk headers are stored in the following format:
 *   apr_uint32_t totsize; - size of headers to follow
 *   totsize amount of headers, HeaderA\0ValueA\0...HeaderN\0ValueN\0
 */

module AP_MODULE_DECLARE_DATA cache_disk_largefile_module;

static const char rcsid[] = /* Add RCS version string to binary */
        "$Id: mod_cache_disk_largefile.c,v 1.33 2014/04/15 09:15:46 source Exp source $";

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *in,
                               apr_bucket_brigade *out);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);
static apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
                               apr_file_t *file);


#define CACHE_LOOP_INCTIME(x) x <<= 1
#define CACHE_LOOP_DECTIME(x) x >>= 1

static void cache_loop_sleep(apr_interval_time_t *t) {

    if(*t < CACHE_LOOP_MINSLEEP) {
        *t = CACHE_LOOP_MINSLEEP;
    }
    else if(*t > CACHE_LOOP_MAXSLEEP) {
        *t = CACHE_LOOP_MAXSLEEP;
    }

    apr_sleep(*t);
}


/*
 * Modified file bucket implementation to be able to deliver files
 * while caching.
 */

/* Derived from apr_buckets_file.c */

#define BUCKET_IS_DISKCACHE(e)        ((e)->type == &bucket_type_diskcache)
static const apr_bucket_type_t bucket_type_diskcache;

static void diskcache_bucket_destroy(void *data)
{
    diskcache_bucket_data *f = data;

    if (apr_bucket_shared_destroy(f)) {
        /* no need to close files here; it will get
         * done automatically when the pool gets cleaned up */
        apr_bucket_free(f);
    }
}


/* The idea here is to convert diskcache buckets to regular file buckets
   as data becomes available */
static apr_status_t diskcache_bucket_read(apr_bucket *e, const char **str,
                                          apr_size_t *len, 
                                          apr_read_type_e block)
{
    diskcache_bucket_data *a = e->data;
    apr_file_t *f = a->fd;
    apr_bucket *b = NULL;
    char *buf;
    apr_status_t rv;
    apr_finfo_t finfo;
    apr_size_t filelength = e->length; /* bytes remaining in file past offset */
    apr_off_t fileoffset = e->start;
    apr_size_t available;
    apr_time_t start = apr_time_now();
#if APR_HAS_THREADS && !APR_HAS_XTHREAD_FILES
    apr_int32_t flags;
#endif

#if APR_HAS_THREADS && !APR_HAS_XTHREAD_FILES
    if ((flags = apr_file_flags_get(f)) & APR_XTHREAD) {
        /* this file descriptor is shared across multiple threads and
         * this OS doesn't support that natively, so as a workaround
         * we must reopen the file into a->readpool */
        const char *fname;
        apr_file_name_get(&fname, f);

        rv = apr_file_open(&f, fname, (flags & ~APR_XTHREAD), 0, a->readpool);
        if (rv != APR_SUCCESS)
            return rv;

        a->fd = f;
    }
#endif

    /* in case we die prematurely */
    *str = NULL;
    *len = 0;

    /* DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
            "Called diskcache_bucket_read");
     */

    while(1) {
        /* Figure out how big the file is right now, sit here until
           it's grown enough or we get bored */
        rv = apr_file_info_get(&finfo, 
                        APR_FINFO_SIZE | APR_FINFO_MTIME | APR_FINFO_NLINK, f);
        if(rv != APR_SUCCESS) {
            return rv;
        }

        if(finfo.size >= fileoffset + S_MIN(filelength, CACHE_BUCKET_MINCHUNK)) {
            break;
        }

        /* No use to even wait for a deleted file */
        if(finfo.nlink == 0) {
            return APR_EGENERAL;
        }

        if(block == APR_NONBLOCK_READ) {
            return APR_EAGAIN;
        }

        /* Check for timeout */
        if(finfo.mtime < (apr_time_now() - a->updtimeout) ) {
            return APR_EGENERAL;
        }
        /* If we have progress within half the timeout period, return what
           we have so far */
        if(finfo.size > fileoffset &&
                start < (apr_time_now() - a->updtimeout/2) ) 
        {
            break;
        }

        /* Increase loop delay on each pass */
        cache_loop_sleep(&(a->polldelay));
        CACHE_LOOP_INCTIME(a->polldelay);
    }
    /* Decrease the loop delay a notch so the stored value is the actual
       delay needed */
    CACHE_LOOP_DECTIME(a->polldelay);

    /* Convert this bucket to a zero-length heap bucket so we won't be called
       again */
    buf = apr_bucket_alloc(0, e->list);
    apr_bucket_heap_make(e, buf, 0, apr_bucket_free);

    /* Wrap as much as possible into a regular file bucket */
    available = S_MIN(filelength, finfo.size-fileoffset);
    b = apr_bucket_file_create(f, fileoffset, available, a->readpool, e->list);
    APR_BUCKET_INSERT_AFTER(e, b);

    /* DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
            "diskcache_bucket_read: Converted to regular file"
            " off %" APR_OFF_T_FMT " len %" APR_SIZE_T_FMT,
            fileoffset, available);
     */


    /* Put any remains in yet another bucket */
    if(available < filelength) {
        e=b;
        /* for efficiency, we can just build a new apr_bucket struct
         * to wrap around the existing bucket */
        b = apr_bucket_alloc(sizeof(*b), e->list);
        b->start  = fileoffset + available;
        b->length = filelength - available;
        b->data   = a;
        b->type   = &bucket_type_diskcache;
        b->free   = apr_bucket_free;
        b->list   = e->list;
        APR_BUCKET_INSERT_AFTER(e, b);
    }
    else {
        diskcache_bucket_destroy(a);
    }

    *str = buf;
    return APR_SUCCESS;
}

static apr_bucket * diskcache_bucket_make(apr_bucket *b,
                                                apr_file_t *fd,
                                                apr_off_t offset,
                                                apr_size_t len, 
                                                apr_interval_time_t timeout,
                                                apr_pool_t *p)
{
    diskcache_bucket_data *f;

    f = apr_bucket_alloc(sizeof(*f), b->list);
    f->fd = fd;
    f->readpool = p;
    f->updtimeout = timeout;
    f->polldelay = 0;

    b = apr_bucket_shared_make(b, f, offset, len);
    b->type = &bucket_type_diskcache;

    return b;
}

static apr_bucket * diskcache_bucket_create(apr_file_t *fd,
                                                  apr_off_t offset,
                                                  apr_size_t len, 
                                                  apr_interval_time_t timeout,
                                                  apr_pool_t *p,
                                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return diskcache_bucket_make(b, fd, offset, len, timeout, p);
}


/* FIXME: This is probably only correct for the first case, that seems
   to be the one that occurs all the time... */
static apr_status_t diskcache_bucket_setaside(apr_bucket *data, 
                                              apr_pool_t *reqpool)
{
    diskcache_bucket_data *a = data->data;
    apr_file_t *fd = NULL;
    apr_file_t *f = a->fd;
    apr_pool_t *curpool = apr_file_pool_get(f);

    if (apr_pool_is_ancestor(curpool, reqpool)) {
        return APR_SUCCESS;
    }

    if (!apr_pool_is_ancestor(a->readpool, reqpool)) {
        /* FIXME: Figure out what needs to be done here */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                "diskcache_bucket_setaside: FIXME1");
        a->readpool = reqpool;
    }

    /* FIXME: Figure out what needs to be done here */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
            "diskcache_bucket_setaside: FIXME2");

    apr_file_setaside(&fd, f, reqpool);
    a->fd = fd;
    return APR_SUCCESS;
}

static const apr_bucket_type_t bucket_type_diskcache = {
    "DISKCACHE", 5, APR_BUCKET_DATA,
    diskcache_bucket_destroy,
    diskcache_bucket_read,
    diskcache_bucket_setaside,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

/* From apr_brigade.c */

/* A "safe" maximum bucket size, 1Gb */
#define MAX_BUCKET_SIZE (0x40000000)

static apr_bucket * diskcache_brigade_insert(apr_bucket_brigade *bb,
                                                   apr_file_t *f, apr_off_t
                                                   start, apr_off_t length,
                                                   apr_interval_time_t timeout,
                                                   apr_pool_t *p)
{
    apr_bucket *e;

    if (length < MAX_BUCKET_SIZE) {
        e = diskcache_bucket_create(f, start, (apr_size_t)length, timeout, p, 
                bb->bucket_alloc);
    }
    else {
        /* Several buckets are needed. */        
        e = diskcache_bucket_create(f, start, MAX_BUCKET_SIZE, timeout, p, 
                bb->bucket_alloc);

        while (length > MAX_BUCKET_SIZE) {
            apr_bucket *ce;
            apr_bucket_copy(e, &ce);
            APR_BRIGADE_INSERT_TAIL(bb, ce);
            e->start += MAX_BUCKET_SIZE;
            length -= MAX_BUCKET_SIZE;
        }
        e->length = (apr_size_t)length; /* Resize just the last bucket */
    }

    APR_BRIGADE_INSERT_TAIL(bb, e);
    return e;
}

/* --------------------------------------------------------------- */

/*
 * Local static functions
 */

static char *cache_file(apr_pool_t *p, disk_cache_conf *conf,
                        const char *prefix, const char *name, 
                        const char *suffix)
{

    char *hashfile;

    hashfile = ap_cache_generate_name(p, DEFAULT_DIRLEVELS, DEFAULT_DIRLENGTH, 
                                      name);

    /* This assumes that we always deal with Vary-stuff if there's a prefix */
    if (prefix) {
        return apr_pstrcat(p, prefix, CACHE_VDIR_SUFFIX, "/",
                hashfile, suffix, NULL);
    }
    else {
        return apr_pstrcat(p, conf->cache_root, "/", hashfile, suffix, NULL);
    }
}


static apr_status_t mkdir_structure(const char *file, apr_pool_t *pool)
{
    apr_status_t rv;
    char *p;
    int i;

    p = strrchr((char *)file, '/');
    if(!p) {
        return APR_EGENERAL;
    }

    *p = '\0';

    /* Be stubborn to overcome racyness when others deletes directories
       while we're trying to create them */
    for(i=0; i < 10; i++) {
        rv = apr_dir_make_recursive(file, 
                                    APR_UREAD|APR_UWRITE|APR_UEXECUTE, pool);
        if(rv == APR_SUCCESS) {
            break;
        }
    }
    *p = '/';

    return rv;
}

/* htcacheclean may remove directories underneath us.
 * So, we'll try renaming three times at a cost of 0.002 seconds.
 */
static apr_status_t safe_file_rename(const char *src, const char *dest,
                                     apr_pool_t *pool)
{
    apr_status_t rv;

    rv = apr_file_rename(src, dest, pool);

    if (rv != APR_SUCCESS) {
        int i;

        for (i = 0; i < 2 && rv != APR_SUCCESS; i++) {
            rv = mkdir_structure(dest, pool);
            if (rv != APR_SUCCESS)
                continue;

            rv = apr_file_rename(src, dest, pool);

            if(rv != APR_SUCCESS) {
                /* 1000 micro-seconds aka 0.001 seconds. */
                apr_sleep(1000);
            }
        }
    }

    return rv;
}

/* Close fd, remove file if it was opened for writing */
static void close_and_rm(apr_file_t *fd, const char *file, request_rec *r)
{
    apr_int32_t flags = apr_file_flags_get(fd);

    apr_file_close(fd);
    if(flags & APR_FOPEN_WRITE) {
        apr_file_remove(file, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "close_and_rm: Removed %s",
                     file);
    }
}


static apr_status_t file_cache_errorcleanup(disk_cache_object_t *dobj, 
                                            request_rec *r)
{
    /* Only remove files that are opened for write when called, files
       opened only for reading must be explicitly removed */
    if(dobj->hfd) {
        close_and_rm(dobj->hfd, dobj->hdrsfile, r);
        dobj->hfd = NULL;
    }
    if(dobj->bfd_read) {
        apr_file_close(dobj->bfd_read);
        dobj->bfd_read = NULL;
    }
    if(dobj->bfd_write) {
        close_and_rm(dobj->bfd_write, dobj->bodyfile, r);
        dobj->bfd_write = NULL;
    }
    if (dobj->tfd) {
        close_and_rm(dobj->tfd, dobj->tempfile, r);
        dobj->tfd = NULL;
    }

    return APR_SUCCESS;
}


static const char* regen_key(apr_pool_t *p, apr_table_t *headers,
                             apr_array_header_t *varray, const char *oldkey)
{
    struct iovec *iov;
    int i, k;
    int nvec;
    const char *header;
    const char **elts;

    nvec = (varray->nelts * 2) + 1;
    iov = apr_palloc(p, sizeof(struct iovec) * nvec);
    elts = (const char **) varray->elts;

    /* TODO:
     *    - Handle multiple-value headers better. (sort them?)
     *    - Handle Case in-sensitive Values better.
     *        This isn't the end of the world, since it just lowers the cache
     *        hit rate, but it would be nice to fix.
     *
     * The majority are case insenstive if they are values (encoding etc).
     * Most of rfc2616 is case insensitive on header contents.
     *
     * So the better solution may be to identify headers which should be
     * treated case-sensitive?
     *  HTTP URI's (3.2.3) [host and scheme are insensitive]
     *  HTTP method (5.1.1)
     *  HTTP-date values (3.3.1)
     *  3.7 Media Types [exerpt]
     *     The type, subtype, and parameter attribute names are case-
     *     insensitive. Parameter values might or might not be case-sensitive,
     *     depending on the semantics of the parameter name.
     *  4.20 Except [exerpt]
     *     Comparison of expectation values is case-insensitive for unquoted
     *     tokens (including the 100-continue token), and is case-sensitive for
     *     quoted-string expectation-extensions.
     */

    for(i=0, k=0; i < varray->nelts; i++) {
        header = apr_table_get(headers, elts[i]);
        if (!header) {
            header = "";
        }
        iov[k].iov_base = (char*) elts[i];
        iov[k].iov_len = strlen(elts[i]);
        k++;
        iov[k].iov_base = (char*) header;
        iov[k].iov_len = strlen(header);
        k++;
    }
    iov[k].iov_base = (char*) oldkey;
    iov[k].iov_len = strlen(oldkey);
    k++;

    return apr_pstrcatv(p, iov, k, NULL);
}

static int array_alphasort(const void *fn1, const void *fn2)
{
    return strcmp(*(char**)fn1, *(char**)fn2);
}

static void tokens_to_array(apr_pool_t *p, const char *data,
                            apr_array_header_t *arr)
{
    char *token;

    while ((token = ap_get_list_item(p, &data)) != NULL) {
        *((const char **) apr_array_push(arr)) = token;
    }

    /* Sort it so that "Vary: A, B" and "Vary: B, A" are stored the same. */
    qsort((void *) arr->elts, arr->nelts,
         sizeof(char *), array_alphasort);
}

/*
 * Hook and mod_cache callback functions
 */
static int create_entity(cache_handle_t *h, request_rec *r, const char *key, 
                         apr_off_t len, apr_bucket_brigade *bb)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);
    cache_object_t *obj;
    disk_cache_object_t *dobj;

    if (conf->cache_root == NULL) {
        return DECLINED;
    }

    /* we don't support caching of range requests (yet) */
    if (r->status == HTTP_PARTIAL_CONTENT) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "URL %s partial content response not cached",
                     key);
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pstrdup(r->pool, key);

    dobj->name = obj->key;
    /* Save the cache root */
    dobj->root = apr_pstrndup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;
    dobj->hdrsfile = cache_file(r->pool, conf, NULL, key, CACHE_HEADER_SUFFIX);
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);
    dobj->initial_size = len;
    dobj->file_size = -1;
    dobj->lastmod = APR_DATE_BAD;
    dobj->header_only = r->header_only;
    dobj->bytes_sent = 0;

    if(r->filename != NULL && strlen(r->filename) > 0) {
        char buf[34];
        char *str;

        /* When possible, hash the body on dev:inode to minimize file
           duplication. */
        if( (r->finfo.valid & APR_FINFO_IDENT) == APR_FINFO_IDENT) {
            apr_uint64_t device = r->finfo.device; /* Avoid ifdef ... */
            apr_uint64_t inode  = r->finfo.inode;  /* ... type-mess */

            apr_snprintf(buf, sizeof(buf), "%016" APR_UINT64_T_HEX_FMT ":%016" 
                         APR_UINT64_T_HEX_FMT, device, inode);
            str = buf;
        }
        else {
            str = r->filename;
        }
        dobj->bodyfile = cache_file(r->pool, conf, NULL, str, 
                                    CACHE_BODY_SUFFIX);
        dobj->filename = r->filename;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "File %s was hashed using %s into %s",
                     r->filename, str, dobj->bodyfile);
    }
    else {
        dobj->bodyfile = cache_file(r->pool, conf, NULL, key, 
                                    CACHE_BODY_SUFFIX);
    }

    return OK;
}


static apr_status_t file_read_timeout(apr_file_t *file, char * buf,
                                      apr_size_t len, apr_time_t timeout)
{
    apr_size_t left, done;
    apr_finfo_t finfo;
    apr_status_t rc;
    apr_interval_time_t delay=0;

    done = 0;
    left = len;

    while(1) {
        rc = apr_file_read_full(file, buf+done, left, &len);
        if (rc == APR_SUCCESS) {
           break;
        }
        done += len;
        left -= len;

        if(!APR_STATUS_IS_EOF(rc)) {
            return rc;
        }
        rc = apr_file_info_get(&finfo, APR_FINFO_MTIME, file);
        if(rc != APR_SUCCESS) {
           return rc;
        }
        if(finfo.mtime < (apr_time_now() - timeout) ) {
            return APR_ETIMEDOUT;
        }
        cache_loop_sleep(&delay);
        CACHE_LOOP_INCTIME(delay);
    }

    return APR_SUCCESS;
}


static apr_status_t open_header(cache_object_t *obj, disk_cache_object_t *dobj,
                                request_rec *r, const char *key, 
                                disk_cache_conf *conf)
{
    int flags = APR_READ | APR_WRITE | APR_BINARY;
    disk_cache_format_t format;
    apr_status_t rc;
    const char *nkey = key;
    disk_cache_info_t disk_info;

    /* Open header read/write so it's easy to rewrite it when needed */
    rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        return CACHE_EDECLINED;
    }

    /* read the format from the cache file */
    rc = apr_file_read_full(dobj->hfd, &format, sizeof(format), NULL);
    if(APR_STATUS_IS_EOF(rc)) {
        return CACHE_ENODATA;
    }
    else if(rc != APR_SUCCESS) {
        return rc;
    }

    /* Vary-files are being written to tmpfile and moved in place, so
       the should always be complete */
    if (format == VARY_FORMAT_VERSION) {
        apr_array_header_t* varray;
        apr_time_t expire;
        char *p;

        rc = apr_file_read_full(dobj->hfd, &expire, sizeof(expire), NULL);
        if(rc != APR_SUCCESS) {
            return rc;
        }

        varray = apr_array_make(r->pool, 5, sizeof(char*));
        rc = read_array(r, varray, dobj->hfd);
        if (rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                         "Cannot parse vary header file: %s",
                         dobj->hdrsfile);
            return CACHE_EDECLINED;
        }
        apr_file_close(dobj->hfd);

        nkey = regen_key(r->pool, r->headers_in, varray, key);

        dobj->prefix = dobj->hdrsfile;
        p = strrchr((char *)dobj->prefix, '.');
        if(p) {
            /* Cut away the suffix */
            *p = '\0';
        }
        dobj->hdrsfile = cache_file(r->pool, conf, dobj->prefix, nkey,
                                    CACHE_HEADER_SUFFIX);

        rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
        if (rc != APR_SUCCESS) {
            dobj->hfd = NULL;
            return CACHE_EDECLINED;
        }
        rc = apr_file_read_full(dobj->hfd, &format, sizeof(format), NULL);
        if(APR_STATUS_IS_EOF(rc)) {
            return CACHE_ENODATA;
        }
        else if(rc != APR_SUCCESS) {
            return rc;
        }
    }

    if(format != DISK_FORMAT_VERSION) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                     "File '%s' had a version mismatch. File had "
                     "version: %d (current is %d). Deleted.", dobj->hdrsfile,
                     format, DISK_FORMAT_VERSION);
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->hdrsfile, r->pool);
        return CACHE_EDECLINED;
    }

    obj->key = nkey;
    dobj->name = key;

    /* read the data from the header file */
    rc = apr_file_read_full(dobj->hfd, &disk_info, sizeof(disk_info), NULL);
    if(APR_STATUS_IS_EOF(rc)) {
        return CACHE_ENODATA;
    }
    else if(rc != APR_SUCCESS) {
        return rc;
    }

    /* Store it away so we can get it later. */
    dobj->disk_info = disk_info;

    return APR_SUCCESS;
}


static apr_status_t open_header_timeout(cache_object_t *obj, 
                                        disk_cache_object_t *dobj, 
                                        request_rec *r, 
                                        const char *key, disk_cache_conf *conf)
{
    apr_status_t rc;
    apr_finfo_t finfo;
    apr_interval_time_t delay = 0;

    while(1) {
        if(dobj->hfd) {
            apr_file_close(dobj->hfd);
            dobj->hfd = NULL;
        }
        rc = open_header(obj, dobj, r, key, conf);
        if(rc != APR_SUCCESS && rc != CACHE_ENODATA) {
            if(rc != CACHE_EDECLINED) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                             "Cannot load header file: %s",
                             dobj->hdrsfile);
            }
            return rc;
        }

        /* Objects with unknown body size will have file_size == -1 until the
           entire body is written and the header updated with the actual size.
           And since we depend on knowing the body size we wait until the size
           is written */
        if(rc == APR_SUCCESS && dobj->disk_info.file_size >= 0) {
            break;
        }
        rc = apr_file_info_get(&finfo, APR_FINFO_MTIME, dobj->hfd);
        if(rc != APR_SUCCESS) {
            return rc;
        }
        if(finfo.mtime < (apr_time_now() - conf->updtimeout)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "Timed out waiting for header file %s for "
                         "URL %s - caching the body failed?", 
                         dobj->hdrsfile, key);
            return CACHE_EDECLINED;
        }
        cache_loop_sleep(&delay);
        CACHE_LOOP_INCTIME(delay);
    }

    return APR_SUCCESS;
}


static apr_status_t load_header_strings(request_rec *r,
                                        disk_cache_object_t *dobj)
{
    apr_size_t len;
    apr_status_t rc;
    char *urlbuff;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);


    if(dobj->disk_info.name_len > MAX_STRING_LEN ||
            dobj->disk_info.bodyname_len > MAX_STRING_LEN ||
            dobj->disk_info.filename_len > MAX_STRING_LEN) 
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Corrupt cache header for URL %s, deleting: %s",
                dobj->name, dobj->hdrsfile);
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->hdrsfile, r->pool);
        return CACHE_EDECLINED;
    }

    /* FIXME: Enforce that url and bodyname is present */


    len = dobj->disk_info.name_len;
    urlbuff = apr_palloc(r->pool, len+1);
    if(urlbuff == NULL) {
        return APR_ENOMEM;
    }

    rc = file_read_timeout(dobj->hfd, urlbuff, len, conf->updtimeout);
    if (rc == APR_ETIMEDOUT) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                     "Timed out waiting for urlbuff for "
                     "URL %s - caching failed?",  dobj->name);
        return CACHE_EDECLINED;
    }
    else if(rc != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                     "Error reading urlbuff for URL %s",
                     dobj->name);
        return CACHE_EDECLINED;
    }
    urlbuff[len] = '\0';

    /* check that we have the same URL */
    if (strcmp(urlbuff, dobj->name) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "Cached URL %s didn't match requested "
                     "URL %s", urlbuff, dobj->name);
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->hdrsfile, r->pool);
        apr_file_remove(dobj->bodyfile, r->pool);
        return CACHE_EDECLINED;
    }

    /* Read in the file the body is stored in */
    len = dobj->disk_info.bodyname_len;
    if(len > 0) {
        char *bodyfile = apr_palloc(r->pool, len+1);

        if(bodyfile == NULL) {
            return APR_ENOMEM;
        }

        rc = file_read_timeout(dobj->hfd, bodyfile, len, conf->updtimeout);
        if (rc == APR_ETIMEDOUT) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Timed out waiting for body cache "
                         "filename for URL %s - caching failed?", dobj->name);
            return CACHE_EDECLINED;
        }
        else if(rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Error reading body cache filename for "
                         "URL %s", dobj->name);
            return CACHE_EDECLINED;
        }
        bodyfile[len] = '\0';
        dobj->bodyfile = apr_pstrcat(r->pool, dobj->root, "/", bodyfile, NULL);
    }

    /* Read in the filename */
    len = dobj->disk_info.filename_len;
    if(len > 0) {
        char *fnamebuf = apr_palloc(r->pool, len+1);

        if(fnamebuf == NULL) {
            return APR_ENOMEM;
        }

        rc = file_read_timeout(dobj->hfd, fnamebuf, len, conf->updtimeout);
        if (rc == APR_ETIMEDOUT) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Timed out waiting for filename for "
                         "URL %s - caching failed?", dobj->name);
            return CACHE_EDECLINED;
        }
        else if(rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Error reading filename for URL %s",
                         dobj->name);
            return CACHE_EDECLINED;
        }
        fnamebuf[len] = '\0';

        dobj->filename = fnamebuf;
        /* We can't set r->filename here because for example mod_rewrite
           will exhibit different behaviour compared to a completely
           uncached entity (will happen if entity is revalidated for 
           example). */
        /* Save a pointer to r->filename so we can set it later on in
           recall_body which doesn't get r as an argument */
        dobj->rfilename = &(r->filename);
    }

    return APR_SUCCESS;
}


static apr_status_t open_body_timeout(request_rec *r, cache_object_t *cache_obj,
                                      disk_cache_object_t *dobj)
{
    apr_status_t rc;
    apr_finfo_t finfo;
    int flags = APR_READ|APR_BINARY;
    apr_interval_time_t delay = 0;
    cache_info *info = &(cache_obj->info);
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);

    
#if APR_HAS_SENDFILE
    core_dir_config *pdconf = ap_get_core_module_config(r->per_dir_config);
    /* When we are in the quick handler we don't have the per-directory
     * configuration, so this check only takes the global setting of
     * the EnableSendFile directive into account.  */
    flags |= AP_SENDFILE_ENABLED(pdconf->enable_sendfile);
#endif  

    if(dobj->bodyfile == NULL || strlen(dobj->bodyfile) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "open_body_timeout called with NULL "
                     "bodyfile for URL %s",
                     dobj->name);
        return APR_EGENERAL;
    }

    /* Wait here until we get a body cachefile, data in it, and do quick sanity
     * check */

    while(1) {
        if(dobj->bfd_read == NULL) {
            rc = apr_file_open(&dobj->bfd_read, dobj->bodyfile, flags, 0, r->pool);
            if(rc != APR_SUCCESS) {
                if(info->response_time < (apr_time_now() - conf->updtimeout) ) {
                    /* This usually means that the body simply wasn't cached,
                       due to HEAD requests for example */
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                                 "Timed out waiting for bodyfile "
                                 "%s for URL %s - caching failed?", 
                                 dobj->bodyfile, dobj->name);
                    return CACHE_EDECLINED;
                }
                cache_loop_sleep(&delay);
                CACHE_LOOP_INCTIME(delay);
                continue;
            }
        }


        /* FIXME: When we have bfd_write, verify that the bfd_read opened
                  is the same file */
        rc = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_CSIZE | 
                                       APR_FINFO_MTIME | APR_FINFO_CTIME |
                                       APR_FINFO_NLINK, 
                               dobj->bfd_read);
        if(rc != APR_SUCCESS && !APR_STATUS_IS_INCOMPLETE(rc)) {
            return rc;
        }
        if(finfo.valid & APR_FINFO_NLINK && finfo.nlink == 0) {
            /* This file has been deleted, close it and try again */
            apr_file_close(dobj->bfd_read);
            dobj->bfd_read = NULL;
            continue;
        }

        /* XFS on Linux can leave corrupted files behind after a system crash,
           these are usually detectable by the fact that csize is smaller than
           the actual filesize. The occurances we've seen has had csize=0.

           Note that we can't simply check for csize<size, due to file systems
           with compression and/or delayed allocation like SUN ZFS.
         */

        /* Check for non-zero sized files with zero consumed size only
           when ctime is older than our update timeout. We use ctime here
           because some filesystems (ZFS) has delayed allocation which means
           we can't rely on csize immediately after file close */
        if(finfo.valid & APR_FINFO_CSIZE && dobj->initial_size > 0 &&
                finfo.csize == 0 &&
                finfo.ctime < (apr_time_now() - conf->updtimeout))
        {
            dobj->file_size = 0;
        }
        else {
            dobj->file_size = finfo.size;
        }

        /* Note that the body might have been updated by another entity
           that uses the same body, which usually means that we should
           revalidate too. Don't freak out completely when this happens.
           We might have:
           - Body in sync with this header.
           - Body being cached.
           - Body that failed caching.
           - Body newer than this header. 
         */

        /* FIXME: Should we tag the header with the device/inode of the
                  corresponding body as well? */

        if(dobj->initial_size < dobj->file_size) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                         "Cached body for too large for URL %s"
                         " - revalidating.", dobj->name);
            apr_file_remove(dobj->hdrsfile, r->pool);
            return CACHE_EDECLINED;
        }
        else if(dobj->initial_size > dobj->file_size) {
            /* Still caching or failed? */
            if(finfo.mtime < (apr_time_now() - conf->updtimeout) ) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, rc, r,
                             "Cached body too small for URL %s"
                             " - revalidating.", dobj->name);
                apr_file_remove(dobj->hdrsfile, r->pool);
                return CACHE_EDECLINED;
            }
        }
        else {
            /* If right size, file has either the correct mtime or 
               mtime == ctime which means the mtime isn't set. The latter
               either means there was no Last-Modified available or
               that we're in the window between finished copying and setting
               mtime.
             */
            if(dobj->lastmod != APR_DATE_BAD &&
                    apr_time_sec(finfo.mtime) != apr_time_sec(dobj->lastmod) &&
                    (finfo.mtime != finfo.ctime || 
                     finfo.mtime < (apr_time_now() - conf->updtimeout)) ) 
            {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, rc, r,
                             "Cached body Last-Modified mismatch "
                             "for URL %s - revalidating.", dobj->name);
                apr_file_remove(dobj->hdrsfile, r->pool);
                return CACHE_EDECLINED;
            }
        }

        if(dobj->file_size > 0) {
            break;
        }
        cache_loop_sleep(&delay);
        CACHE_LOOP_INCTIME(delay);
    }

    return APR_SUCCESS;
}


static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    apr_status_t rc;
    cache_object_t *obj;
    disk_cache_object_t *dobj;
    cache_info *info;
    static int error_logged = 0;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);

    h->cache_obj = NULL;

    /* Look up entity keyed to 'url' */
    if (conf->cache_root == NULL) {
        if (!error_logged) {
            error_logged = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                         "Cannot cache files to disk without a "
                         "CacheRoot specified.");
        }
        return DECLINED;
    }

    /* Create and init the cache object */
    obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));
    info = &(obj->info);

    /* Save the cache root */
    dobj->root = apr_pstrndup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;

    dobj->hdrsfile = cache_file(r->pool, conf, NULL, key, CACHE_HEADER_SUFFIX);

    dobj->header_only = r->header_only;

    /* Open header and read basic info, wait until header contains
       valid size information for the body */
    rc = open_header_timeout(obj, dobj, r, key, conf);
    if(rc != APR_SUCCESS) {
        if(dobj->hfd != NULL) {
            apr_file_close(dobj->hfd);
            dobj->hfd = NULL;
        }
        return DECLINED;
    }

    info->status = dobj->disk_info.status;
    info->date = dobj->disk_info.date;
    info->expire = dobj->disk_info.expire;
    info->request_time = dobj->disk_info.request_time;
    info->response_time = dobj->disk_info.response_time;

    memcpy(&info->control, &dobj->disk_info.control, sizeof(cache_control_t));

    dobj->lastmod = dobj->disk_info.lastmod;
    dobj->initial_size = (apr_off_t) dobj->disk_info.file_size;
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    /* Load and check strings (URL, bodyfile, filename) */
    rc = load_header_strings(r, dobj);
    if(rc != APR_SUCCESS) {
        if(dobj->hfd != NULL) {
            apr_file_close(dobj->hfd);
            dobj->hfd = NULL;
        }
        return DECLINED;
    }

    /* Only need body cachefile if we have a body and this isn't a HEAD
       request */
    if(dobj->initial_size > 0 && !dobj->header_only) {
        rc = open_body_timeout(r, obj, dobj);
        if(rc != APR_SUCCESS) {
            if(dobj->hfd != NULL) {
                apr_file_close(dobj->hfd);
                dobj->hfd = NULL;
            }
            if(dobj->bfd_read != NULL) {
                apr_file_close(dobj->bfd_read);
                dobj->bfd_read = NULL;
            }
            return DECLINED;
        }
    }
    else {
        dobj->file_size = 0;
    }

    /* make the configuration stick */
    h->cache_obj = obj;
    h->cache_obj->vobj = dobj;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Recalled status for cached URL %s from file %s",
                 dobj->name, dobj->hdrsfile);
    return OK;
}


/* Called to abort processing using this entity */
static int remove_entity(cache_handle_t *h)
{
    disk_cache_object_t *dobj;
    apr_finfo_t finfo;
    apr_status_t rv;

    /* Get disk cache object from cache handle */
    dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    /* Null out the cache object pointer so next time we start from scratch */
    h->cache_obj = NULL;

    if(!dobj) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
            "remove_entity: %s", dobj->name);

    /* FIXME: Should we use file_cache_errorcleanup() instead? */

    if(dobj->hfd != NULL) {
        apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
    }
    if(dobj->bfd_read != NULL) {
        apr_file_close(dobj->bfd_read);
        dobj->bfd_read = NULL;
    }

    return OK;
}


/* FIXME: It would make sense to have the errorcleanup and this function
   to be the same */
static int remove_url(cache_handle_t *h, request_rec *r)
{
    apr_status_t rc;
    disk_cache_object_t *dobj;

    /* Get disk cache object from cache handle */
    dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    if (!dobj) {
        return DECLINED;
    }

    /* Delete headers file */
    if (dobj->hdrsfile) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Deleting %s from cache.", dobj->hdrsfile);

        rc = apr_file_remove(dobj->hdrsfile, r->pool);
        if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
            /* Will only result in an output if httpd is started with -e debug.
             * For reason see log_error_core for the case s == NULL.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                         "Failed to delete headers file %s "
                         "from cache.", dobj->hdrsfile);
            return DECLINED;
        }
    }

    /* Only delete body cache file if it isn't backed by a real file */
    if(!dobj->filename && dobj->bodyfile) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Deleting %s from cache.", dobj->bodyfile);

        rc = apr_file_remove(dobj->bodyfile, r->pool);
        if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                         "Failed to delete body file %s "
                         "from cache.", dobj->bodyfile);
            return DECLINED;
        }
    }

    return OK;
}

static apr_status_t commit_entity(cache_handle_t *h, request_rec *r)
{
    /* FIXME: Do we have anything that needs to be done here? */
    return APR_SUCCESS;
}

static apr_status_t invalidate_entity(cache_handle_t *h, request_rec *r)
{
    return APR_ENOTIMPL;
}

static apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
                               apr_file_t *file)
{
    char w[MAX_STRING_LEN];
    int p;
    apr_status_t rv;

    while (1) {
        rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Premature end of vary array.");
            return rv;
        }

        p = strlen(w);
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        /* If we've finished reading the array, break out of the loop. */
        if (w[0] == '\0') {
            break;
        }

       *((const char **) apr_array_push(arr)) = apr_pstrdup(r->pool, w);
    }

    return APR_SUCCESS;
}

static apr_status_t store_array(apr_file_t *fd, apr_array_header_t* arr)
{
    int i;
    apr_status_t rv;
    struct iovec iov[2];
    apr_size_t amt;
    const char **elts;

    elts = (const char **) arr->elts;

    for (i = 0; i < arr->nelts; i++) {
        iov[0].iov_base = (char*) elts[i];
        iov[0].iov_len = strlen(elts[i]);
        iov[1].iov_base = CRLF;
        iov[1].iov_len = sizeof(CRLF) - 1;

        rv = apr_file_writev_full(fd, (const struct iovec *) &iov, 2, &amt);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    iov[0].iov_base = CRLF;
    iov[0].iov_len = sizeof(CRLF) - 1;

    return apr_file_writev_full(fd, (const struct iovec *) &iov, 1,
                         &amt);
}

/* Load table stored by store_table */
static apr_status_t read_table(request_rec *r,
                               apr_table_t *table, apr_file_t *file)
{
    char *s, *k, *v;
    apr_uint32_t totsize = 0;
    apr_status_t rv;

    rv = apr_file_read_full(file, &totsize, sizeof(totsize), NULL);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    s = apr_palloc(r->pool, totsize);
    if(s == NULL) {
        return APR_ENOMEM;
    }

    rv = apr_file_read_full(file, s, totsize, NULL);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    k=s;
    while(k < s + totsize) {
        /* FIXME: Do a pointer-loop instead of strlen to make sure we don't
                  walk outside of allocated memory if on-disk data has been
                  corrupted
         */
        v = k + strlen(k) + 1;
        apr_table_addn(table, k, v);
        k = v + strlen(v) + 1;
    }

    return APR_SUCCESS;
}


/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged.
 * Is that okay, or should they be collapsed where possible?
 */
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r)
{
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);
    apr_status_t rv;
    apr_off_t off;
    apr_finfo_t finfo;
    apr_interval_time_t delay = 0;

    /* This case should not happen... */
    if (!dobj->hfd) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "recall_headers called without fd for URL %s",
                     dobj->name);
        return APR_NOTFOUND;
    }

    off = 0;
    rv = apr_file_seek(dobj->hfd, APR_CUR, &off);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    h->resp_hdrs = apr_table_make(r->pool, 20);
    h->req_hdrs = apr_table_make(r->pool, 20);

    while(1) {
        rv = read_table(r, h->resp_hdrs, dobj->hfd);
        if(rv != APR_SUCCESS) {
            apr_table_clear(h->resp_hdrs);
        }
        else {
            rv = read_table(r, h->req_hdrs, dobj->hfd);
            if(rv != APR_SUCCESS) {
                apr_table_clear(h->req_hdrs);
            }
        }
        if(rv == APR_SUCCESS) {
            break;
        }
        if(!APR_STATUS_IS_EOF(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Error reading cache headers "
                          "URL %s", dobj->name);
            if(dobj->hfd != NULL) {
                apr_file_close(dobj->hfd);
                dobj->hfd = NULL;
            }
            if(dobj->bfd_read != NULL) {
                apr_file_close(dobj->bfd_read);
                dobj->bfd_read = NULL;
            }
            return rv;
        }

        /* FIXME: Check if header file deleted (nlinks==0) and reopen it if
         * that's the case */
        rv = apr_file_info_get(&finfo, APR_FINFO_MTIME, dobj->hfd);
        if(rv != APR_SUCCESS ||
                finfo.mtime < (apr_time_now() - conf->updtimeout) ) 
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Timed out waiting for cache headers "
                          "URL %s", dobj->name);
            if(dobj->hfd != NULL) {
                apr_file_close(dobj->hfd);
                dobj->hfd = NULL;
            }
            if(dobj->bfd_read != NULL) {
                apr_file_close(dobj->bfd_read);
                dobj->bfd_read = NULL;
            }
            return APR_EGENERAL;
        }
        rv = apr_file_seek(dobj->hfd, APR_SET, &off);
        if(rv != APR_SUCCESS) {
            return rv;
        }
        cache_loop_sleep(&delay);
        CACHE_LOOP_INCTIME(delay);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Recalled headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;
    apr_off_t bytes_already_done;
    disk_cache_conf *conf = ap_get_module_config(ap_server_conf->module_config,
                                                 &cache_disk_largefile_module);

    if(dobj->hfd != NULL) {
        /* Close header cache file, it won't be needed anymore */
        apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
    }

    if(dobj->initial_size > 0 && !dobj->header_only && dobj->bfd_read == NULL) {
        /* This should never happen, really... */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "recall_body: Called but no fd open, URL %s "
                     "from file %s", dobj->name, dobj->bodyfile);
        return APR_EGENERAL;
    }

    /* Restore r->filename if not present */
    if(dobj->filename != NULL && dobj->rfilename != NULL && 
            *(dobj->rfilename) == NULL) 
    {
        *(dobj->rfilename) = dobj->filename;
    }

    /* Insert as much as possible as regular file (ie. sendfile():able) */
    /* We need to make sure to skip the beginning of the file if we've
       already sent some bytes, e.g., due to mod_proxy */
    if(dobj->file_size > dobj->bytes_sent) {
        if(apr_brigade_insert_file(bb, dobj->bfd_read, dobj->bytes_sent, 
                                   dobj->file_size - dobj->bytes_sent, p) == NULL) 
        {
            return APR_ENOMEM;
        }
        bytes_already_done = dobj->file_size;
    } else {
        bytes_already_done = dobj->bytes_sent;
    }

    /* Insert any remainder as read-while-caching bucket */
    if(bytes_already_done < dobj->initial_size) {
        if(diskcache_brigade_insert(bb, dobj->bfd_read, bytes_already_done, 
                                    dobj->initial_size - bytes_already_done,
                                    conf->updtimeout, p
                    ) == NULL) 
        {
            return APR_ENOMEM;
        }
    }

    e = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "recall_body: Succeeded for URL %s from file %s",
                 dobj->name, dobj->bodyfile);

    return APR_SUCCESS;
}

/* Store table on disk.
 * Format on disk: apr_uint32_t totsize - total size of data following totsize
 *                 totsize of data, consisting of key\0value\0...key\0value\0
 */
static apr_status_t store_table(apr_file_t *fd, apr_table_t *table,
                                request_rec *r)
{
    int i, nelts, niov;
    apr_status_t rv = APR_SUCCESS;
    apr_uint32_t totsize = 0;
    apr_table_entry_t *elts;
    struct iovec *iov;

    nelts = apr_table_elts(table)->nelts;

    /* Allocate space for the size-header plus two elements per table entry */

    iov = apr_palloc(r->pool, (1+nelts*2) * sizeof(struct iovec));
    if(iov == NULL) {
        return APR_ENOMEM;
    }

    elts = (apr_table_entry_t *) apr_table_elts(table)->elts;
    niov = 1;
    for (i = 0; i < nelts; ++i) {
        if (elts[i].key != NULL) {
            iov[niov].iov_base = elts[i].key;
            iov[niov].iov_len = strlen(elts[i].key)+1;
            totsize += iov[niov++].iov_len;
            iov[niov].iov_base = elts[i].val;
            iov[niov].iov_len = strlen(elts[i].val)+1;
            totsize += iov[niov++].iov_len;
        }
    }
    iov[0].iov_base = (void *) &totsize;
    iov[0].iov_len = sizeof(totsize);
    i=0;
    while(niov > 0) {
        /* Need to write this in chunks, APR_MAX_IOVEC_SIZE is really small
           on some OS's */
        int chunk = S_MIN(niov, APR_MAX_IOVEC_SIZE);
        apr_size_t amt;

        rv = apr_file_writev_full(fd, (const struct iovec *) &iov[i], chunk,
                                  &amt);
        if(rv != APR_SUCCESS) {
            return rv;
        }
        niov -= chunk;
        i += chunk;
    }
    return rv;
}


static apr_status_t open_new_file(request_rec *r, const char *filename,
                                  apr_file_t **fd, disk_cache_conf *conf)
{
    int flags = APR_CREATE | APR_WRITE | APR_BINARY | APR_EXCL;
    apr_status_t rv;

    while(1) {
        rv = apr_file_open(fd, filename, flags, 
                           APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                     "open_new_file: Opening %s", filename);

        if(APR_STATUS_IS_EEXIST(rv)) {
            apr_finfo_t finfo;

            rv = apr_stat(&finfo, filename, APR_FINFO_MTIME, r->pool);
            if(APR_STATUS_IS_ENOENT(rv)) {
                /* Someone else has already removed it, try again */
                continue;
            }
            else if(rv != APR_SUCCESS) {
                return rv;
            }

            /* FIXME: We should really check for size and mtime that matches
               the source file too if available */
            if(finfo.mtime < (apr_time_now() - conf->updtimeout) ) {
                /* Something stale that's left around */

                rv = apr_file_remove(filename, r->pool);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                             "open_new_file: removing old %s", filename);
                if(rv != APR_SUCCESS && !APR_STATUS_IS_ENOENT(rv)) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                 "open_new_file: Failed to "
                                 "remove old %s", filename);
                    return rv;
                }
                continue;
            }
            else {
                /* Someone else has just created the file, return identifiable
                   status so calling function can do the right thing */

                return CACHE_EEXIST;
            }
        }
        else if(APR_STATUS_IS_ENOENT(rv)) {
            /* The directory for the file didn't exist */

            rv = mkdir_structure(filename, r->pool);
            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "open_new_file: Failed to make "
                             "directory for %s", filename);
                return rv;
            }
            continue;
        }
        else if(rv == APR_SUCCESS) {
            return APR_SUCCESS;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "open_new_file: Failed to open %s",
                         filename);
            return rv;
        }
    }

    /* We should never get here, so */
    return APR_EGENERAL;
}


static apr_status_t store_vary_header(cache_handle_t *h, disk_cache_conf *conf,
                                       request_rec *r, cache_info *info,
                                       const char *varyhdr)
{
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;
    apr_array_header_t* varray;
    const char *vfile;
    apr_status_t rv;
    int flags;
    disk_cache_format_t format = VARY_FORMAT_VERSION;
    struct iovec iov[2];
    apr_size_t amt;

    /* We should always write the vary format hints to the original header
     * path, otherwise they will never be refreshed.  */

    vfile = dobj->hdrsfile;

    flags = APR_CREATE | APR_WRITE | APR_BINARY | APR_EXCL | APR_BUFFERED;
    rv = apr_file_mktemp(&dobj->tfd, dobj->tempfile, flags, r->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    iov[0].iov_base = (void*)&format;
    iov[0].iov_len = sizeof(format);

    iov[1].iov_base = (void*)&info->expire;
    iov[1].iov_len = sizeof(info->expire);

    rv = apr_file_writev_full(dobj->tfd, (const struct iovec *) &iov, 2, &amt);
    if (rv != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);
        return rv;
    }

    varray = apr_array_make(r->pool, 6, sizeof(char*));
    tokens_to_array(r->pool, varyhdr, varray);

    rv = store_array(dobj->tfd, varray);
    if (rv != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);
        return rv;
    }

    rv = apr_file_close(dobj->tfd);
    dobj->tfd = NULL;
    if (rv != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->tempfile, r->pool);
        return rv;
    }

    rv = safe_file_rename(dobj->tempfile, vfile, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "rename tempfile to varyfile failed: "
                     "%s -> %s", dobj->tempfile, vfile);
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->tempfile, r->pool);
        return rv;
    }

    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    if(dobj->prefix == NULL) {
        const char *tmp = regen_key(r->pool, r->headers_in, varray, dobj->name);
        char *p;

        dobj->prefix = dobj->hdrsfile;
        p = strrchr((char *)dobj->prefix, '.');
        if(p) {
            /* Cut away the suffix */
            *p = '\0';
        }
        dobj->hdrsfile = cache_file(r->pool, conf, dobj->prefix, tmp, 
                                    CACHE_HEADER_SUFFIX);
        dobj->bodyfile = cache_file(r->pool, conf, dobj->prefix, tmp, 
                                    CACHE_BODY_SUFFIX);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Stored vary header for URL %s", dobj->name);

    return APR_SUCCESS;
}


static apr_status_t store_disk_header(cache_handle_t *h, request_rec *r, 
                                      cache_info *info)
{
    disk_cache_format_t format = DISK_FORMAT_VERSION;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;
    struct iovec iov[5];
    int niov;
    disk_cache_info_t disk_info;
    apr_size_t amt;
    apr_status_t rv;

    disk_info.date = info->date;
    disk_info.expire = info->expire;
    disk_info.entity_version = dobj->disk_info.entity_version++;
    disk_info.request_time = info->request_time;
    disk_info.response_time = info->response_time;
    disk_info.status = info->status;
    disk_info.file_size = dobj->initial_size;
    disk_info.lastmod = dobj->lastmod;

    memcpy(&disk_info.control, &h->cache_obj->info.control, sizeof(cache_control_t));

    niov = 0;
    iov[niov].iov_base = (void*)&format;
    iov[niov++].iov_len = sizeof(format);
    iov[niov].iov_base = (void*)&disk_info;
    iov[niov++].iov_len = sizeof(disk_cache_info_t);

    disk_info.name_len = strlen(dobj->name);
    iov[niov].iov_base = (void*)dobj->name;
    iov[niov++].iov_len = disk_info.name_len;

    if(dobj->initial_size > 0) {
        /* We know the bodyfile is root/bodyname ... */
        char *bodyname = (char *) dobj->bodyfile + dobj->root_len + 1;
        disk_info.bodyname_len = strlen(bodyname);
        iov[niov].iov_base = (void*)bodyname;
        iov[niov++].iov_len = disk_info.bodyname_len;
    }
    else {
        disk_info.bodyname_len = 0;
    }

    if(r->filename != NULL && strlen(r->filename) > 0) {
        disk_info.filename_len = strlen(r->filename);
        iov[niov].iov_base = (void*)r->filename;
        iov[niov++].iov_len = disk_info.filename_len;
    }
    else {
        disk_info.filename_len = 0;
    }

    rv = apr_file_writev_full(dobj->hfd, (const struct iovec *) &iov, niov, 
                              &amt);
    if (rv != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);
        return rv;
    }

    if (r->headers_out) {
        apr_table_t *headers_out;

        headers_out = ap_cache_cacheable_headers_out(r);

        rv = store_table(dobj->hfd, headers_out, r);
        if (rv != APR_SUCCESS) {
            file_cache_errorcleanup(dobj, r);
            return rv;
        }
    }

    /* Parse the vary header and dump those fields from the headers_in. */
    /* FIXME: Make call to the same thing cache_select calls to crack Vary. */
    if (r->headers_in) {
        apr_table_t *headers_in;

        headers_in = ap_cache_cacheable_headers_in(r);

        rv = store_table(dobj->hfd, headers_in, r);
        if (rv != APR_SUCCESS) {
            file_cache_errorcleanup(dobj, r);
            return rv;
        }
    }

    /* Store it away so we can get it later. */
    dobj->disk_info = disk_info;

    return APR_SUCCESS;
}


static apr_status_t store_headers(cache_handle_t *h, request_rec *r, 
                                  cache_info *info)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);
    apr_status_t rv;
    int rewriting;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;
    const char *lastmods;


    /* This is flaky... we need to manage the cache_info differently */
    h->cache_obj->info = *info;

    /* Get last-modified timestamp */
    lastmods = apr_table_get(r->err_headers_out, "Last-Modified");
    if (lastmods == NULL) {
        lastmods = apr_table_get(r->headers_out, "Last-Modified");
    }
    if (lastmods != NULL) {
        dobj->lastmod = apr_date_parse_http(lastmods);
    }

    if(dobj->hfd) {
        rewriting = TRUE;

        /* Don't update header on disk if the following is met:
           - The body size is known.
           - If Last-Modified is known, it has to be identical.
           - It's not expired.
           - Date in cached header isn't older than updtimeout.
         */
        if( dobj->disk_info.file_size >= 0 && (dobj->lastmod == APR_DATE_BAD || 
                dobj->lastmod == dobj->disk_info.lastmod) &&
                dobj->disk_info.expire > r->request_time &&
                dobj->disk_info.date > info->date - conf->updtimeout) 
        {
            dobj->skipstore = TRUE;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                         "store_headers: Headers current for URL "
                         "%s", dobj->name);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                         "Rewriting headers for URL %s", 
                         dobj->name);
        }
    }
    else {
        rewriting = FALSE;

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                     "Storing new headers for URL %s", dobj->name);
    }

    if (r->headers_out) {
        const char *tmp;

        tmp = apr_table_get(r->headers_out, "Vary");

        if (tmp) {
            rv = store_vary_header(h, conf, r, info, tmp);
            if(rv != APR_SUCCESS) {
                return rv;
            }
        }
    } 

    if(dobj->skipstore) {
        apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
        return APR_SUCCESS;
    }

    if(rewriting) {
        apr_finfo_t     finfo;

        rv = apr_file_info_get(&finfo, APR_FINFO_MTIME, dobj->hfd);
        if(rv != APR_SUCCESS) {
            return rv;
        }

        /* FIXME: Isn't this a bit redundant? It probably causes more
           trouble than it's fixing, especially since we handle it above
           except for looking at mtime */
        /* Don't store disk headers more often than updtimeout */
        if(dobj->disk_info.file_size >= 0 &&
                dobj->disk_info.expire > r->request_time &&
                r->request_time < finfo.mtime + conf->updtimeout) 
        {
            dobj->skipstore = TRUE;
        }
        else {
            /* This triggers bugs in APR when using APR_BUFFERED */
            apr_off_t off=0;
            rv = apr_file_seek(dobj->hfd, APR_SET, &off);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            rv = apr_file_trunc(dobj->hfd, 0);
            if(rv != APR_SUCCESS) {
                return rv;
            }
        }

    }
    else {
        rv = open_new_file(r, dobj->hdrsfile, &(dobj->hfd), conf);
        if(rv == CACHE_EEXIST) {
            dobj->skipstore = TRUE;
        }
        else if(rv != APR_SUCCESS) {
            return rv;
        }
    }

    if(dobj->skipstore) {
        if(dobj->hfd) {
            apr_file_close(dobj->hfd);
            dobj->hfd = NULL;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Skipping store for URL %s: Someone else "
                     "beat us to it",  dobj->name);
        return APR_SUCCESS;
    }

    rv = store_disk_header(h, r, info);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    /* If the body size is unknown, the header file will be rewritten later
       so we can't close it */
    if(dobj->initial_size >= 0) {
        rv = apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
        if(rv != APR_SUCCESS) {
            apr_file_remove(dobj->hdrsfile, r->pool);
            return rv;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Stored headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}


static apr_status_t check_destfd_timeout(apr_file_t *fd, apr_time_t now,
                                         apr_time_t updtimeout) 
{
    apr_status_t rc;
    apr_finfo_t finfo;

    /* Get mtime and nlink for our opened destfile */
    rc = apr_file_info_get(&finfo, APR_FINFO_MTIME | APR_FINFO_NLINK, fd);
    if(rc != APR_SUCCESS) {
        return rc;
    }

    /* If link count is zero, file is deleted */
    if(finfo.nlink == 0) {
        return APR_ETIMEDOUT;
    }

    /* Check if mtime on destfile shows us having timed out */
    if(now - finfo.mtime > updtimeout) {
        return APR_ETIMEDOUT;
    }

    return APR_SUCCESS;
}


static apr_status_t copy_body(apr_pool_t *p,
                              apr_file_t *srcfd, apr_off_t srcoff, 
                              apr_file_t *destfd, apr_off_t destoff, 
                              apr_off_t len, apr_interval_time_t updtimeout)
{
    apr_status_t rc;
    apr_size_t size;
    apr_finfo_t finfo;
    apr_time_t starttime = apr_time_now();
    apr_time_t last = starttime;
    apr_time_t lastcheck = 0;
    unsigned int i=0, freq=1;
    apr_interval_time_t minintvl = updtimeout/10;
    apr_interval_time_t maxintvl = minintvl*3;
    int srcfd_os, destfd_os;
    off64_t srcoff_os, destoff_os, flushoff;
    int err;

    char *buf = apr_palloc(p, S_MIN(len, CACHE_BUF_SIZE));
    if (!buf) {
        return APR_ENOMEM;
    }

    if(srcoff != 0) {
        rc = apr_file_seek(srcfd, APR_SET, &srcoff);
        if(rc != APR_SUCCESS) {
            return rc;
        }
    }

    if(destoff != 0) {
        rc = apr_file_seek(destfd, APR_SET, &destoff);
        if(rc != APR_SUCCESS) {
            return rc;
        }
    }

    rc = apr_os_file_get(&srcfd_os, srcfd);
    if(rc != APR_SUCCESS) {
        return rc;
    }

    rc = apr_os_file_get(&destfd_os, destfd);
    if(rc != APR_SUCCESS) {
        return rc;
    }

#ifdef POSIX_FADV_SEQUENTIAL
    /* We expect sequential IO */
    err=posix_fadvise(srcfd_os, 0, 0, POSIX_FADV_SEQUENTIAL);
    if(err) {
        rc = APR_FROM_OS_ERROR(err);
        ap_log_perror(APLOG_MARK, APLOG_WARNING, rc, p,
                     "copy_body: posix_fadvise");
    }
#endif /* POSIX_FADV_SEQUENTIAL */

    srcoff_os = 0;
    destoff_os = 0;
    flushoff = 0;
    while(len > 0) {
        size=S_MIN(len, CACHE_BUF_SIZE);

        rc = apr_file_read_full (srcfd, buf, size, NULL);
        if(rc != APR_SUCCESS) {
            return rc;
        }

#ifdef POSIX_FADV_DONTNEED
        /* We will never need this segment again */
        err=posix_fadvise(srcfd_os, srcoff_os, size, POSIX_FADV_DONTNEED);
        if(err) {
            rc = APR_FROM_OS_ERROR(err);
            ap_log_perror(APLOG_MARK, APLOG_WARNING, rc, p,
                         "copy_body: posix_fadvise");
        }
#endif /* POSIX_FADV_DONTNEED */

        srcoff_os += size;

#ifdef POSIX_FADV_WILLNEED
        if(len-size > 0) {
            /* Tell kernel that we'll need more segments soon */
            err=posix_fadvise(srcfd_os, srcoff_os, 2*CACHE_BUF_SIZE,
                              POSIX_FADV_WILLNEED);
            if(err) {
                rc = APR_FROM_OS_ERROR(err);
                ap_log_perror(APLOG_MARK, APLOG_WARNING, rc, p,
                             "copy_body: posix_fadvise");
            }
        }
#endif /* POSIX_FADV_WILLNEED */

        /* Do timeout checks before we do the write, this is what other clients
           will see. Don't waste resources by calling apr_time_now() on each
           iteration. */
        if(i++ % freq == 0) {
            apr_time_t now = apr_time_now();
            apr_time_t elapsed = now-last;

            /* Do closer inspection at updtimeout intervals */
            if(now-lastcheck > updtimeout) {
                rc = check_destfd_timeout(destfd, now, updtimeout);
                if(rc != APR_SUCCESS) {
                    return rc;
                }
                lastcheck = now;
            }

            if(elapsed > updtimeout) {
                if(freq > 1) {
                    /* The close inspection above will catch a timeout. 
                       If we get here, make sure we recalibrate at which
                       frequency we should check stuff */
                    freq = 1;
                }
            }
            else if(elapsed < minintvl) {
                freq <<= 1;
                freq |= 1;
            }
            else if(elapsed > maxintvl && freq > 1) {
                freq >>= 1;
            }
            last = now;
        }

        rc = apr_file_write_full(destfd, buf, size, NULL);
        if(rc != APR_SUCCESS) {
            return rc;
        }
        len -= size;
        destoff_os += size;

#ifdef SYNC_FILE_RANGE_WRITE
        if(destoff_os - flushoff >= CACHE_WRITE_FLUSH_WINDOW) {
            /* Start flushing the current write window */
            if(sync_file_range(destfd_os, flushoff, destoff_os - flushoff,
                            SYNC_FILE_RANGE_WRITE) != 0)
            {
                return(APR_FROM_OS_ERROR(errno));
            }
            /* Wait for the previous window to be written to disk before
               continuing. This is to prevent the disk write queues to be
               chock full if incoming data rate is higher than the disks can
               handle, which will cause horrible read latencies for other
               requests while handling writes for this one */
            if(flushoff >= CACHE_WRITE_FLUSH_WINDOW) {
                if(sync_file_range(destfd_os, flushoff-CACHE_WRITE_FLUSH_WINDOW,
                                   CACHE_WRITE_FLUSH_WINDOW,
                                   SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER) 
                                   != 0)
                {
                    return(APR_FROM_OS_ERROR(errno));
                }
            }

            flushoff = destoff_os;
        }
#endif /* SYNC_FILE_RANGE_WRITE */
    }

    /* Make sure we are the one having cached the destfile */
    rc = check_destfd_timeout(destfd, apr_time_now(), updtimeout);
    if(rc != APR_SUCCESS) {
        return rc;
    }

    /* Check if file has changed during copying. This is not 100% foolproof
       due to NFS attribute caching when on NFS etc. */
    /* FIXME: Can we assume that we're always copying an entire file? In that
              case we can check if the current filesize matches the length
              we think it is */
    rc = apr_file_info_get(&finfo, APR_FINFO_MTIME, srcfd);
    if(rc != APR_SUCCESS) {
        return rc;
    }
    if(starttime < finfo.mtime) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}


/* Provide srcfile and srcinfo containing APR_FINFO_IDENT|APR_FINFO_MTIME
   and destfile and destinfo containing APR_FINFO_IDENT 
   to make sure we have opened the right files
   (someone might have just replaced them which messes up things).
*/
static apr_status_t copy_body_nofd(apr_pool_t *p, const char *srcfile, 
                                   apr_off_t srcoff, apr_finfo_t *srcinfo,
                                   const char *destfile, apr_off_t destoff, 
                                   apr_finfo_t *destinfo, apr_off_t len, 
                                   apr_interval_time_t updtimeout)
{
    apr_status_t rc;
    apr_file_t *srcfd, *destfd;
    apr_finfo_t srcfinfo, destfinfo;

    rc = apr_file_open(&srcfd, srcfile, APR_READ | APR_BINARY, 0, p);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: apr_file_open srcfd");
        return rc;
    }
    rc = apr_file_info_get(&srcfinfo, APR_FINFO_IDENT | APR_FINFO_MTIME, srcfd);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: apr_file_info_get srcfd");
        return rc;
    }
    if(srcinfo->inode != srcfinfo.inode || srcinfo->device != srcfinfo.device 
            || srcinfo->mtime < srcfinfo.mtime) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: src: inode/device/mtime mismatch");
        return APR_EGENERAL;
    }

    rc = apr_file_open(&destfd, destfile, APR_WRITE | APR_BINARY, 0, p);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: apr_file_open destfd");
        return rc;
    }
    rc = apr_file_info_get(&destfinfo, APR_FINFO_IDENT, destfd);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: apr_file_info_get destfd");
        return rc;
    }
    if(destinfo->inode != destfinfo.inode 
            || destinfo->device != destfinfo.device) 
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: dest: inode/device mismatch");
        return APR_EGENERAL;
    }

    rc = copy_body(p, srcfd, srcoff, destfd, destoff, len, updtimeout);
    apr_file_close(srcfd);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_body_nofd: copy_body");
        apr_file_close(destfd);
        return rc;
    }

    rc = apr_file_close(destfd);

    /* Set mtime on dest file to the one of the source file */
    apr_file_mtime_set(destfile, srcfinfo.mtime, p);

    return rc;
}


#if APR_HAS_THREADS
static apr_status_t bgcopy_thread_cleanup(void *data)
{
    copyinfo *ci = data;
    apr_status_t rc, ret;
    apr_pool_t *p;

    /* FIXME: Debug */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ci->s,
                 "bgcopy_thread_cleanup: %s -> %s",
                 ci->srcfile, ci->destfile);

    rc = apr_thread_join(&ret, ci->t);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ci->s,
                     "bgcopy_thread_cleanup: apr_thread_join "
                     "failed %s -> %s", ci->srcfile, ci->destfile);
        return rc;
    }
    if(ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, ret, ci->s,
                     "Background caching body %s -> %s failed",
                     ci->srcfile, ci->destfile);
    }

    /* FIXME: Debug */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ci->s,
                 "bgcopy_thread_cleanup: SUCCESS %s -> %s",
                 ci->srcfile, ci->destfile);

    /* Destroy our private pool */
    p = ci->pool;
    apr_pool_destroy(p);

    return APR_SUCCESS;
}


static void *bgcopy_thread(apr_thread_t *t, void *data)
{
    copyinfo *ci = data;
    apr_pool_t *p;
    apr_status_t rc;

    p = apr_thread_pool_get(t);

    /* FIXME: Debug */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ci->s,
                 "bgcopy_thread: start %s -> %s",
                 ci->srcfile, ci->destfile);

    rc = copy_body_nofd(p, ci->srcfile, ci->srcoff, &(ci->srcinfo), 
                        ci->destfile, ci->destoff, &(ci->destinfo),
                        ci->len, ci->updtimeout);

    if(rc != APR_ETIMEDOUT && rc != APR_SUCCESS) {
        apr_file_remove(ci->destfile, p);
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ci->s,
                     "bgcopy_thread: failed %s -> %s",
                     ci->srcfile, ci->destfile);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ci->s,
                     "bgcopy_thread: done %s -> %s",
                     ci->srcfile, ci->destfile);
    }

    apr_thread_exit(t, rc);
    return NULL;
}
#endif /* APR_HAS_THREADS */


#if APR_HAS_FORK
static apr_status_t bgcopy_child_cleanup(void *data) {
    copyinfo *ci = data;
    int status;
    apr_exit_why_e why;
    apr_pool_t *p;

    apr_proc_wait(ci->proc, &status, &why, APR_WAIT);
    if(why == APR_PROC_EXIT) {
        if(status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, ci->s,
                         "Background caching body %s -> %s failed",
                         ci->srcfile, ci->destfile);
            return APR_SUCCESS;
        }
    }
    else if(status & (APR_PROC_SIGNAL | APR_PROC_SIGNAL_CORE) ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ci->s,
                     "Background caching body %s -> %s failed, "
                     "caught signal %d", ci->srcfile, ci->destfile, status);
        return APR_SUCCESS;
    }

    /* Destroy our private pool */
    p = ci->pool;
    apr_pool_destroy(p);

    return APR_SUCCESS;
}
#endif /* APR_HAS_FORK */


static apr_status_t do_bgcopy(apr_file_t *srcfd, apr_off_t srcoff, 
                              apr_file_t *destfd, apr_off_t destoff, 
                              apr_off_t len, apr_interval_time_t updtimeout,
                              conn_rec *c)
{
    copyinfo *ci;
    apr_status_t rv;
    apr_pool_t *newpool;
    const char *srcfile, *destfile;
    int mpm_query_info;

    /* It seems pool gets destroyed (ie. fd's closed) before our cleanup 
       function is called when an error occurs (a dropped connection, for
       example), so we need a pool of our own.
     */
    rv = apr_pool_create(&newpool, NULL);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    ci = apr_palloc(newpool, sizeof(*ci));
    if(ci == NULL) {
        apr_pool_destroy(newpool);
        return APR_ENOMEM;
    }

    rv = apr_file_name_get(&srcfile, srcfd);
    if(rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_file_info_get(&(ci->srcinfo), APR_FINFO_IDENT|APR_FINFO_MTIME,
                           srcfd);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_file_name_get(&destfile, destfd);
    if(rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_file_info_get(&(ci->destinfo), APR_FINFO_IDENT, destfd);
    if(rv != APR_SUCCESS) {
        return rv;
    }


    ci->pool = newpool;
    ci->srcfile = apr_pstrdup(newpool, srcfile);
    ci->srcoff = srcoff;
    ci->destfile = apr_pstrdup(newpool, destfile);
    ci->destoff = destoff;
    ci->len = len;
    ci->updtimeout = updtimeout;
    ci->s = c->base_server;

#if APR_HAS_THREADS
    if(ap_mpm_query(AP_MPMQ_IS_THREADED, &mpm_query_info) == APR_SUCCESS) {
        apr_threadattr_t *ta;
        apr_thread_t *t;
        rv = apr_threadattr_create(&ta, newpool);
        if(rv != APR_SUCCESS) {
            apr_pool_destroy(newpool);
            return rv;
        }

        apr_threadattr_detach_set(ta, FALSE);

        /* FIXME: This makes module unloadable on AIX */
#if 0
#ifdef AP_MPM_WANT_SET_STACKSIZE
        if (ap_thread_stacksize != 0) {
            apr_threadattr_stacksize_set(ta, ap_thread_stacksize);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
                    "BG thread stacksize set to %"
                    APR_SIZE_T_FMT, ap_thread_stacksize);
        }
#endif /* AP_MPM_WANT_SET_STACKSIZE */
#endif /* 0 */

        if (rv != APR_SUCCESS) {
            apr_pool_destroy(newpool);
            return rv;
        }
        rv = apr_thread_create (&t, ta, bgcopy_thread, ci, newpool);
        if (rv != APR_SUCCESS) {
            apr_pool_destroy(newpool);
            return rv;
        }
        ci->t = t;

        apr_pool_cleanup_register(c->pool, ci, 
                                  bgcopy_thread_cleanup, apr_pool_cleanup_null);
    }
    else
#endif /* APR_HAS_THREADS */
#if APR_HAS_FORK
    if(ap_mpm_query(AP_MPMQ_IS_FORKED, &mpm_query_info) == APR_SUCCESS) {
        ci->proc = apr_palloc(newpool, sizeof(apr_proc_t));
        if(ci->proc == NULL) {
            apr_pool_destroy(newpool);
            return APR_ENOMEM;
        }
        if (rv != APR_SUCCESS) {
            apr_pool_destroy(newpool);
            return rv;
        }
        rv = apr_proc_fork(ci->proc, newpool);
        if(rv == APR_INCHILD) {
            /* Child */
            rv = copy_body_nofd(ci->pool, ci->srcfile, ci->srcoff, 
                                &(ci->srcinfo), ci->destfile, ci->destoff, 
                                &(ci->destinfo), ci->len, ci->updtimeout);
            if(rv != APR_ETIMEDOUT && rv != APR_SUCCESS) {
                apr_file_remove(ci->destfile, ci->pool);
            }
            exit(rv);
        }
        else if(rv == APR_INPARENT) {
            apr_pool_cleanup_register(c->pool, ci, 
                                      bgcopy_child_cleanup, 
                                      apr_pool_cleanup_null);
        }
        else {
            return rv;
        }
    }
    else 
#endif /* APR_HAS_FORK */
    if(1)
    {
        rv = copy_body(newpool, srcfd, ci->srcoff, destfd, ci->destoff,
                       ci->len, ci->updtimeout);
        apr_pool_destroy(newpool);
    }

    return rv;
}


static apr_status_t replace_brigade_with_cache(cache_handle_t *h,
                                               request_rec *r,
                                               apr_bucket_brigade *bb)
{
    apr_status_t rv;
    apr_bucket *e;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    /* FIXME: Close elsewhere now that we don't share read/write fd:s? */
    if(dobj->bfd_write) {
        apr_file_close(dobj->bfd_write);
        dobj->bfd_write = NULL;
    }

    rv = open_body_timeout(r, h->cache_obj, dobj);
    if(rv == CACHE_EDECLINED) {
        return APR_ETIMEDOUT;
    }
    else if(rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "Error opening bodyfile %s for URL %s",
                     dobj->bodyfile, dobj->name);
        return rv;
    }

    /* First, empty the brigade */
    e  = APR_BRIGADE_FIRST(bb);
    while (e != APR_BRIGADE_SENTINEL(bb)) {
        apr_bucket *d;
        d = e;
        e = APR_BUCKET_NEXT(e);
        apr_bucket_delete(d);
    }

    /* Then, populate it with our cached instance */

    /* in case we've already sent part, e.g. via mod_proxy */
    dobj->bytes_sent = r->bytes_sent;

    rv = recall_body(h, r->pool, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "Error serving URL %s from cache", dobj->name);
        return rv;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Serving cached body for URL %s", dobj->name);

    return APR_SUCCESS;
}

static apr_status_t fileident_compare(apr_file_t *a, apr_file_t *b)
{
    apr_finfo_t ainfo, binfo;
    apr_status_t rv;

    rv = apr_file_info_get(&ainfo, APR_FINFO_IDENT, a);
    if(rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_file_info_get(&binfo, APR_FINFO_IDENT, b);
    if(rv != APR_SUCCESS) {
        return(rv);
    }
    if(ainfo.device != binfo.device || ainfo.inode != binfo.inode) {
        rv = APR_EBADF;
    }

    return rv;
}


static apr_status_t store_body(cache_handle_t *h, request_rec *r,
                               apr_bucket_brigade *in, apr_bucket_brigade *out)
{
    apr_bucket *e, *fbout=NULL;
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *pool = NULL;
    char *buf=NULL;
    int first_call = FALSE, did_bgcopy = FALSE;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);

    if(r->no_cache) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "store_body called for URL %s even though"
                     "no_cache is set", dobj->name);
        file_cache_errorcleanup(dobj, r);
        return APR_EGENERAL;
    }

    if(dobj->initial_size == 0) {
        /* Don't waste a body cachefile on a 0 length body */
        APR_BRIGADE_CONCAT(out, in);
        return APR_SUCCESS;
    }

    /* Only perform these actions when called the first time */
    if(dobj->bfd_write == NULL) {
        first_call = TRUE;

        if(dobj->lastmod != APR_DATE_BAD) {
            apr_finfo_t finfo;
            rv = apr_stat(&finfo, dobj->bodyfile, 
                          APR_FINFO_MTIME | APR_FINFO_SIZE | APR_FINFO_CSIZE, 
                          r->pool);
            if(rv == APR_SUCCESS || APR_STATUS_IS_INCOMPLETE(rv)) {
                /* Dest-file will have same mtime as source if it's
                   current */
                /* FIXME: This code and the one used in open_body should
                   probably be identical... */
                if(dobj->lastmod <= finfo.mtime && 
                        dobj->initial_size == finfo.size &&
                        !(finfo.valid & APR_FINFO_CSIZE && finfo.csize < finfo.size))
                {
                    /* Assume it's a valid cached body there already */
                    dobj->skipstore = TRUE;
                }
            }
        }

        if(!dobj->skipstore) {
            /* FIXME: We should pass the source file's size and mtime so
               open_new_file() can more reliably determine if the target
               file is current or stale. */
            rv = open_new_file(r, dobj->bodyfile, &(dobj->bfd_write), conf);
#ifdef __linux
            /* Use Linux fallocate() to preallocate the file to avoid
               fragmentation and ENOSPC surprises */
            if(rv == APR_SUCCESS) {
                int bfd_os;
                rv = apr_os_file_get(&bfd_os, dobj->bfd_write);
                if(rv == APR_SUCCESS) {
                    if(fallocate(bfd_os, FALLOC_FL_KEEP_SIZE, 0, 
                                 dobj->initial_size) != 0) 
                    {
                        /* Only choke on relevant errors */
                        if(errno == EBADF || errno == ENOSPC || errno == EIO) {
                            rv = APR_FROM_OS_ERROR(errno);
                        }
                    }
                }
            }
#endif /* __linux */
            if(rv == CACHE_EEXIST) {
                /* Someone else beat us to storing this */
                dobj->skipstore = TRUE;
            }
            else if(rv != APR_SUCCESS) {
                file_cache_errorcleanup(dobj, r);
                apr_file_remove(dobj->hdrsfile, r->pool);
                return rv;
            }
            else {
                dobj->file_size = 0;
            }
        }

        if(dobj->skipstore) {
            /* Someone else beat us to storing this object */

            /* FIXME: Perhaps do something more elegant using the new
                      in/out brigades, this emulates old behaviour */
            APR_BRIGADE_CONCAT(out, in);

            if( dobj->initial_size > 0 &&
                    APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(out)) )
            {
                /* Yay, we can replace the body with the cached instance */
                return replace_brigade_with_cache(h, r, out);
            }

            return APR_SUCCESS;
        }

        if(dobj->initial_size > conf->minbgsize &&
                APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(in)) )
        {
            apr_off_t begin = -1;
            apr_off_t pos = -1;
            apr_file_t *fd = NULL;
            apr_bucket_file *a;

            dobj->can_copy_file = TRUE;

            for (e = APR_BRIGADE_FIRST(in);
                    e != APR_BRIGADE_SENTINEL(in);
                    e = APR_BUCKET_NEXT(e))
            {
                if(APR_BUCKET_IS_EOS(e)) {
                    break;
                }
                if(!APR_BUCKET_IS_FILE(e)) {
                    dobj->can_copy_file = FALSE;
                    break;
                }

                a = e->data;

                if(begin < 0) {
                    begin = pos = e->start;
                    fd = a->fd;
                }

                if(fd != a->fd || pos != e->start) {
                    dobj->can_copy_file = FALSE;
                    break;
                }

                pos += e->length;
            }
            if(dobj->initial_size != pos) {
                /* This should never happen, really */
                dobj->can_copy_file = FALSE;
            }
        }
    }

    if(first_call) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                     "Caching body for URL %s, len %"
                     APR_OFF_T_FMT, dobj->name, dobj->initial_size);
    }

    /* Get the last out bucket and check if it's a file bucket pointing at
       our cachefile */
    if(!fbout && dobj->bfd_read) {
        fbout = APR_BRIGADE_LAST(out);
        if(APR_BUCKET_IS_FILE(fbout)) {
            apr_bucket_file *a = fbout->data;
            rv = fileident_compare(a->fd, dobj->bfd_read);
            if(rv != APR_SUCCESS) {
                fbout = NULL;
                rv = APR_SUCCESS;
            }
        }
        else {
            fbout = NULL;
        }
    }

    while (!APR_BRIGADE_EMPTY(in))
    {
        const char *str;
        apr_size_t length, written=0;

        e = APR_BRIGADE_FIRST(in);

        if(dobj->body_done) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        /* End Of Stream? */
        if (APR_BUCKET_IS_EOS(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            dobj->body_done = TRUE;
            continue;
        }

        /* honour flush buckets, we'll get called again */
        if (APR_BUCKET_IS_FLUSH(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            return APR_SUCCESS;
        }

        /* Ignore the non-data-buckets */
        if(APR_BUCKET_IS_METADATA(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        if(dobj->can_copy_file && dobj->file_size >= conf->minbgsize 
                && APR_BUCKET_IS_FILE(e))
        {
            apr_bucket_file *a = e->data;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "Doing background copy of body for URL %s, offset %"
                    APR_OFF_T_FMT " len %" APR_OFF_T_FMT, 
                    dobj->name, dobj->file_size, dobj->initial_size);

            /* FIXME: Maybe check that e->start and dobj->file_size are
                      identical, because they really should be */
            rv = do_bgcopy(a->fd, e->start, 
                           dobj->bfd_write, dobj->file_size, 
                           dobj->initial_size-dobj->file_size, 
                           conf->updtimeout, r->connection);
            did_bgcopy = TRUE;
            break;
        }

        /* FIXME: We should probably break this into reasonably sized chunks
                  (say 1MB) that we can do fadvise(WILLNEED) on, the smaller
                  CACHE_BUF_SIZE in the copy loop is in reality handled by the
                  OS readahead */

        if(e->length > conf->minbgsize) {
            /* Try to split the bucket into our chunk size */
            rv = apr_bucket_split(e, conf->minbgsize);
            if(rv != APR_SUCCESS && !APR_STATUS_IS_ENOTIMPL(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "apr_bucket_split()");
                break;
            }
        }

        if(APR_BUCKET_IS_FILE(e)) {
            apr_bucket_file *a = e->data;
            apr_size_t len = e->length;
            int fd_os, err;
            apr_off_t off;

            rv = apr_os_file_get(&fd_os, a->fd);
            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "apr_os_file_get()");
                break;
            }

            off = e->start;
            rv = apr_file_seek(a->fd, APR_SET, &off);
            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "apr_file_seek()");
                break;
            }

#ifdef POSIX_FADV_SEQUENTIAL
            /* We expect sequential IO */
            err=posix_fadvise(fd_os, e->start, e->length, 
                              POSIX_FADV_SEQUENTIAL);
            if(err) {
                rv = APR_FROM_OS_ERROR(err);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "posix_fadvise(POSIX_FADV_SEQUENTIAL)");
                break;
            }
#endif /* POSIX_FADV_SEQUENTIAL */

            /* *sigh* All this just because there is no free() ... */
            if(!pool) {
                rv = apr_pool_create(&pool, r->pool);
                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "apr_pool_create()");
                    break;
                }
            }
            if(!buf) {
                buf = apr_pcalloc(pool, CACHE_BUF_SIZE);
                if(!buf && rv == APR_SUCCESS) {
                    rv = APR_ENOMEM;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "apr_palloc()");
                    break;
                }
            }

            while(len > 0) {
                apr_size_t size = S_MIN(len, CACHE_BUF_SIZE);
                rv = apr_file_read_full(a->fd, buf, size, NULL);
                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "apr_file_read_full()");
                    break;
                }

#ifdef POSIX_FADV_DONTNEED
                /* We will never need this segment again */
                err=posix_fadvise(fd_os, off, size, 
                                  POSIX_FADV_DONTNEED);
                if(err) {
                    rv = APR_FROM_OS_ERROR(err);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "posix_fadvise(POSIX_FADV_DONTNEED)");
                    break;
                }
#endif /* POSIX_FADV_DONTNEED */

                off += size;

#ifdef POSIX_FADV_WILLNEED
                if(len-size > 0) {
                    err=posix_fadvise(fd_os, off, CACHE_BUF_SIZE, 
                                      POSIX_FADV_WILLNEED);
                    if(err) {
                        rv = APR_FROM_OS_ERROR(err);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                      "posix_fadvise(POSIX_FADV_WILLNEED)");
                        break;
                    }
                }
#endif /* POSIX_FADV_WILLNEED */

                rv = apr_file_write_full(dobj->bfd_write, buf, size, NULL);
                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "apr_file_write_full()");
                    break;
                }
                written += size;
                len -= size;
            }
            if(rv != APR_SUCCESS) {
                break;
            }
        }
        else { /* Not FILE bucket */
            rv = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "apr_bucket_read()");
                break;
            }
            /* don't write empty buckets to the cache */
            if (!length) {
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(out, e);
                continue;
            }

            rv = apr_file_write_full(dobj->bfd_write, str, length, &written);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "apr_file_write_full()");
                break;
            }
        }
        if(written > 0) {
            if(!dobj->bfd_read) {
                int flags = APR_READ|APR_BINARY;

                /* We know the body file is OK, because we just wrote to it,
                   so just open the file. Verify device/inode so we're sure
                   we opened the file we wrote to though */

                /* Weird, we need to allocate this file on the connection pool
                   or we get a bad filedescriptor failure when the event MPM
                   wants to write the reply. Shouldn't bucket brigade
                   filedescriptors be setaside automatically? */
                /* And, why does this seem to work for the
                   replace_brigade_with_cache() case in this function, or
                   doesn't it ??? */
                rv = apr_file_open(&dobj->bfd_read, dobj->bodyfile, flags, 
                                   0, r->connection->pool);

                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "apr_file_open()");
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(out, e);
                    break;
                }
                rv = fileident_compare(dobj->bfd_write, dobj->bfd_read);
                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                                  "bfd_write and bfd_read mismatch");
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(out, e);
                    rv = APR_EBADF;
                    break;
                }
            }
            apr_bucket_delete(e);
            if(fbout) {
                /* Just extend the existing file cache bucket */
                /* FIXME: This isn't large-file safe on 32bit platforms, do
                          we really care? */
                fbout->length += written;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                             "URL %s extended out brigade to len %" 
                             APR_OFF_T_FMT " off %" APR_OFF_T_FMT,
                             dobj->name, fbout->length, fbout->start);
            }
            else {
                fbout = apr_brigade_insert_file(out, dobj->bfd_read, 
                                            dobj->file_size, written, r->pool);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                             "URL %s added out brigade len %" APR_OFF_T_FMT
                             " off %" APR_OFF_T_FMT,
                             dobj->name, written, dobj->file_size);

            }
            if(!fbout) {
                rv = APR_ENOMEM;
                break;
            }

            dobj->file_size += written;
        }
        else {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
        }
        /* FIXME: Add handling of max time/bytes to handle in each call
           similar to upstream mod_cache_disk ? */
    }

    if(pool) {
        apr_pool_destroy(pool);
        pool = NULL;
        buf = NULL;
    }

    if(did_bgcopy) {
        dobj->bytes_sent = dobj->file_size; /* FIXME: Name is a misnomer now */
        rv = recall_body(h, r->pool, out);
        if(rv == APR_SUCCESS) {
            /* Empty the in brigade */
            apr_bucket *e  = APR_BRIGADE_FIRST(in);
            while (e != APR_BRIGADE_SENTINEL(in)) {
                apr_bucket *d;
                d = e;
                e = APR_BUCKET_NEXT(e);
                apr_bucket_delete(d);
            }
            return rv;
        }
    }

    if(rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "Error during store_body for URL %s", dobj->name);
        file_cache_errorcleanup(dobj, r);
        apr_file_remove(dobj->hdrsfile, r->pool);
        apr_file_remove(dobj->bodyfile, r->pool);
        return rv;
    }

    /* Drop out here if this wasn't the end */
    if (!dobj->body_done) {
        return APR_SUCCESS;
    }

    if(dobj->bfd_write) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Done caching URL %s, len %" APR_OFF_T_FMT,
                     dobj->name, dobj->file_size);

        /* FIXME: Do we really need to check r->no_cache here since we
           checked it in the beginning? */
        /* Assume that if we've got an initial size then bucket brigade
           was complete and there's no danger in keeping it even if the
           connection was aborted */
        if (r->no_cache || (r->connection->aborted && dobj->initial_size < 0)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                         "Discarding body for URL %s "
                         "because connection has been aborted.",
                         dobj->name);
            /* Remove the intermediate cache file and 
               return non-APR_SUCCESS */
            file_cache_errorcleanup(dobj, r);
            apr_file_remove(dobj->hdrsfile, r->pool);
            apr_file_remove(dobj->bodyfile, r->pool);
            return APR_EGENERAL;
        }

        if(dobj->initial_size < 0) {
            /* Update header information now that we know the size */
            dobj->initial_size = dobj->file_size;
            rv = store_headers(h, r, &(h->cache_obj->info));
            if(rv != APR_SUCCESS) {
                file_cache_errorcleanup(dobj, r);
                apr_file_remove(dobj->hdrsfile, r->pool);
                apr_file_remove(dobj->bodyfile, r->pool);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "Discarded body for URL %s "
                             "because store_headers failed",
                             dobj->name);
                return rv;
            }
        }
        else if(dobj->initial_size != dobj->file_size) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                         "URL %s - body size mismatch: suggested %"
                         APR_OFF_T_FMT "  file_size %" APR_OFF_T_FMT ")",
                         dobj->name, dobj->initial_size, dobj->file_size);
            file_cache_errorcleanup(dobj, r);
            apr_file_remove(dobj->hdrsfile, r->pool);
            apr_file_remove(dobj->bodyfile, r->pool);
            return APR_EGENERAL;
        }

        /* All checks were fine, close output file */
        rv = apr_file_close(dobj->bfd_write);
        dobj->bfd_write = NULL;
        if(rv != APR_SUCCESS) {
            apr_file_remove(dobj->bodyfile, r->pool);
            file_cache_errorcleanup(dobj, r);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "Discarded body for URL %s "
                         "because close failed",
                         dobj->name);
            return rv;
        }

        /* Set mtime on body file */
        if(dobj->lastmod != APR_DATE_BAD) {
            apr_file_mtime_set(dobj->bodyfile, dobj->lastmod, r->pool);
        }
    }

    return APR_SUCCESS;
}

static void *create_config(apr_pool_t *p, server_rec *s)
{
    disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

    conf->updtimeout = DEFAULT_UPDATE_TIMEOUT;
    conf->minbgsize = DEFAULT_MIN_BACKGROUND_SIZE;

    conf->cache_root = NULL;
    conf->cache_root_len = 0;

    return conf;
}

/*
 * mod_cache_disk_largefile configuration directives handlers.
 */
static const char
*set_cache_root(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_largefile_module);
    conf->cache_root = arg;
    conf->cache_root_len = strlen(arg);
    /* TODO: canonicalize cache_root and strip off any trailing slashes */

    return NULL;
}


static const char
*set_cache_updtimeout(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_int64_t val;
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_largefile_module);

    if (apr_strtoff(&val, arg, NULL, 10) != APR_SUCCESS || val < 0) 
    {
        return "CacheUpdateTimeout argument must be a non-negative integer representing the timeout in milliseconds for cache update operations";
    }

    conf->updtimeout = val * 1000;

    return NULL;
}


static const char
*set_cache_minbgsize(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_largefile_module);

    if (apr_strtoff(&conf->minbgsize, arg, NULL, 10) != APR_SUCCESS ||
            conf->minbgsize < 0) 
    {
        return "CacheMinBGSize argument must be a non-negative integer representing the min size in bytes for a file to be eligable for background caching";
    }

    return NULL;
}


static const command_rec disk_cache_cmds[] =
{
    AP_INIT_TAKE1("CacheRoot", set_cache_root, NULL, RSRC_CONF,
                 "The directory to store cache files"),
    AP_INIT_TAKE1("CacheUpdateTimeout", set_cache_updtimeout, NULL, RSRC_CONF,
                  "Timeout in ms for cache updates"),
    AP_INIT_TAKE1("CacheMinBGSize", set_cache_minbgsize, NULL, RSRC_CONF,
                  "The minimum file size for background caching"),
    {NULL}
};

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                       server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s started.", rcsid);

    return OK;
}

static const cache_provider cache_disk_provider =
{
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_entity,
    &open_entity,
    &remove_url,
    &commit_entity,
    &invalidate_entity
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* cache initializer */
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "disk_largefile", "0",
                         &cache_disk_provider);
}

AP_DECLARE_MODULE(cache_disk_largefile) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_config,              /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    disk_cache_cmds,            /* command apr_table_t */
    register_hooks              /* register hooks */
};

/*
vim:sw=4:sts=4:et:ai
*/
