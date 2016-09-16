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
#include "http_request.h"

#if !APR_HAS_THREADS
#error This module requires thread support
#endif /* !APR_HAS_THREADS */

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
        "$Id: mod_cache_disk_largefile.c,v 2.25 2016/09/16 14:23:13 source Exp source $";

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *in,
                               apr_bucket_brigade *out);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);
static apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
                               apr_file_t *file);


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
   as data becomes available. We want to keep being called if the backing
   file isn't complete, so don't return too large chunks or we won't be
   called for a long time when slow connections are involved. This would
   in turn prevent us from returning the entire file as a file bucket,
   which is the requirement for event mpm async write completion to kick in.
 */
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
    apr_interval_time_t loopdelay = CACHE_LOOP_MINSLEEP;
#if APR_HAS_THREADS && !APR_HAS_XTHREAD_FILES
    apr_int32_t flags;
#endif

#if APR_HAS_THREADS && !APR_HAS_XTHREAD_FILES
    if ((flags = apr_file_flags_get(f)) & APR_FOPEN_XTHREAD) {
        /* this file descriptor is shared across multiple threads and
         * this OS doesn't support that natively, so as a workaround
         * we must reopen the file into a->readpool */
        const char *fname;
        apr_file_name_get(&fname, f);

        rv = apr_file_open(&f, fname, (flags & ~APR_FOPEN_XTHREAD), 0, 
                           a->readpool);
        if (rv != APR_SUCCESS)
            return rv;

        a->fd = f;
    }
#endif

    /* in case we die prematurely */
    *str = NULL;
    *len = 0;

    if (APLOGtrace4(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                "Called diskcache_bucket_read.  block: %d  fd: %pp  "
                "fd pool: %pp  readpool: %pp  "
                "lastdata: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT, 
                block, f, apr_file_pool_get(f), a->readpool, 
                apr_time_sec(a->lastdata), apr_time_usec(a->lastdata));
    }

    while(1) {
        /* Figure out how big the file is right now, sit here until
           it's grown enough or we get bored */
        rv = apr_file_info_get(&finfo, 
                        APR_FINFO_SIZE | APR_FINFO_MTIME | APR_FINFO_NLINK, f);
        if(rv != APR_SUCCESS) {
            return rv;
        }

        /* The filesize has to be beyond our current offset or we'll end
           up with fun negative numbers in the wrong place ;) */
        if(finfo.size > fileoffset) {
            available = S_MIN(filelength, finfo.size-fileoffset);
        }
        else {
            available = 0;
        }

        /* Always be content if we have the complete backing file */
        if(available >= filelength) {
            break;
        }

        /* No use to even wait for a deleted file */
        if(finfo.nlink == 0) {
            return APR_EGENERAL;
        }

        /* Non-blocking reads can retry */
        if(block == APR_NONBLOCK_READ) {
            return APR_EAGAIN;
        }

        /* Blocking, ie. urgent, reads gets the MAXCHUNK if available */
        if(available >= CACHE_BUCKET_MAXCHUNK) {
            available = CACHE_BUCKET_MAXCHUNK;
            break;
        }

        /* Otherwise deliver what's there if larger than MINCHUNK after
           PREFERWAIT microseconds since the last time we returned data */
        if(available >= CACHE_BUCKET_MINCHUNK
                &&
                a->lastdata + CACHE_BUCKET_PREFERWAIT_BLOCK < apr_time_now()) 
        {
            break;
        }

        /* Check for timeout */
        if(finfo.mtime < (apr_time_now() - a->updtimeout) ) {
            return APR_EGENERAL;
        }
        /* If we have progress within half the timeout period, return what
           we have so far */
        if(available > 0 &&
                start < (apr_time_now() - a->updtimeout/2) ) 
        {
            break;
        }

        apr_sleep(loopdelay);
        loopdelay <<= 1;
        if(loopdelay > CACHE_LOOP_MAXSLEEP) {
            loopdelay = CACHE_LOOP_MAXSLEEP;
        }
    }

    /* Convert this bucket to a zero-length heap bucket so we won't be called
       again */
    buf = apr_bucket_alloc(0, e->list);
    apr_bucket_heap_make(e, buf, 0, apr_bucket_free);

    /* Wrap available data into a regular file bucket */
    /* FIXME: This doesn't cater for CACHE_MAX_BUCKET, ie 32bit platforms,
              which might need splitting into multiple buckets. */
    b = apr_bucket_file_create(f, fileoffset, available, a->readpool, e->list);
    APR_BUCKET_INSERT_AFTER(e, b);

    /* Record that we returned data */
    a->lastdata = apr_time_now();

    if (APLOGtrace4(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                "diskcache_bucket_read: Converted to regular file"
                " off %" APR_OFF_T_FMT " len %" APR_SIZE_T_FMT,
                fileoffset, available);
    }

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
        if (APLOGtrace4(ap_server_conf)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                    "diskcache_bucket_read: done with this bucket.");
        }
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
    f->lastdata = 0;

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

static apr_bucket * diskcache_brigade_insert(apr_bucket_brigade *bb,
                                                   apr_file_t *f, apr_off_t
                                                   start, apr_off_t length,
                                                   apr_interval_time_t timeout,
                                                   apr_pool_t *p)
{
    apr_bucket *e;

    if (length < CACHE_BUCKET_MAX) {
        e = diskcache_bucket_create(f, start, (apr_size_t)length, timeout, p, 
                bb->bucket_alloc);
    }
    else {
        /* Several buckets are needed. */        
        e = diskcache_bucket_create(f, start, CACHE_BUCKET_MAX, timeout, p, 
                bb->bucket_alloc);

        while (length > CACHE_BUCKET_MAX) {
            apr_bucket *ce;
            apr_bucket_copy(e, &ce);
            APR_BRIGADE_INSERT_TAIL(bb, ce);
            e->start += CACHE_BUCKET_MAX;
            length -= CACHE_BUCKET_MAX;
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

/* dobj->errcleanflags determines if non-temporary files gets deleted */
static apr_status_t file_cache_errorcleanup(disk_cache_object_t *dobj, 
                                            request_rec *r)
{
    apr_status_t rc;

    if(dobj->hfd) {
        apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
    }
    if( (dobj->errcleanflags & ERRCLEAN_HEADER && dobj->hdrsfile) ) {
        rc = apr_file_remove(dobj->hdrsfile, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                "file_cache_errorcleanup: Removed %s", dobj->hdrsfile);

        /* Clear flag so we don't try again if called twice */
        dobj->errcleanflags &= ~ERRCLEAN_HEADER;
    }

    if(dobj->bfd_read) {
        apr_file_close(dobj->bfd_read);
        dobj->bfd_read = NULL;
    }
    if(dobj->bfd_write) {
        apr_file_close(dobj->bfd_write);
        dobj->bfd_write = NULL;
    }
    if( (dobj->errcleanflags & ERRCLEAN_BODY && dobj->bodyfile) ) {
        rc = apr_file_remove(dobj->bodyfile, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                "file_cache_errorcleanup: Removed %s", dobj->bodyfile);

        /* Clear flag so we don't try again if called twice */
        dobj->errcleanflags &= ~ERRCLEAN_BODY;
    }

    if (dobj->tfd) {
        apr_file_close(dobj->tfd);
        dobj->tfd = NULL;
        rc = apr_file_remove(dobj->tempfile, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                "file_cache_errorcleanup: Removed %s", dobj->tempfile);
    }

    return APR_SUCCESS;
}


static void debug_rlog_brigade(const char *file, int line, int module_index,
                               int level, apr_status_t status,
                               const request_rec *r, apr_bucket_brigade *bb,
                               const char *bbname)
{
    apr_bucket *db;
    char *btype;
    apr_file_t *fd;
    int i = 0;

    for (db = APR_BRIGADE_FIRST(bb);
            db != APR_BRIGADE_SENTINEL(bb);
            db = APR_BUCKET_NEXT(db), i++)
    {
        btype = "UNKNOWN";
        fd = NULL;

        if(BUCKET_IS_DISKCACHE(db)) {
            diskcache_bucket_data *a = db->data;
            fd = a->fd;
            btype = "DISKCACHE";
        }
        else if(APR_BUCKET_IS_FILE(db)) {
            apr_bucket_file *a = db->data;
            fd = a->fd;
            btype = "FILE";
        }
        else if(APR_BUCKET_IS_HEAP(db)) {
            btype = "HEAP";
        }
        else if(APR_BUCKET_IS_EOS(db)) {
            btype = "EOS";
        }
        else if(APR_BUCKET_IS_FLUSH(db)) {
            btype = "FLUSH";
        }
        else if(APR_BUCKET_IS_METADATA(db)) {
            btype = "METADATA";
        }
        else if(AP_BUCKET_IS_EOR(db)) {
            btype = "EOR";
        }
        else if(APR_BUCKET_IS_MMAP(db)) {
            btype = "MMAP";
        }
        else if(APR_BUCKET_IS_PIPE(db)) {
            btype = "PIPE";
        }
        else if(APR_BUCKET_IS_SOCKET(db)) {
            btype = "SOCKET";
        }
        else if(APR_BUCKET_IS_TRANSIENT(db)) {
            btype = "TRANSIENT";
        }
        else if(APR_BUCKET_IS_IMMORTAL(db)) {
            btype = "IMMORTAL";
        }
        else if(APR_BUCKET_IS_POOL(db)) {
            btype = "POOL";
        }

        if(fd) {
            const char *fname=NULL;
            apr_file_name_get(&fname, fd);

            ap_log_rerror(file, line, module_index, level, status, r,
                         "%s bucket %d: type %s  length %" APR_OFF_T_FMT "  "
                         "offset %" APR_OFF_T_FMT "  "
                         "fd %pp  fdpool %pp  fdname %s",
                         bbname, i, btype, db->length, db->start,
                         fd, apr_file_pool_get(fd), fname);
        }
        else {
            ap_log_rerror(file, line, module_index, level, status, r,
                         "%s bucket %d: type %s length %" APR_OFF_T_FMT "  "
                         "offset %" APR_OFF_T_FMT "  ",
                         bbname, i, btype, db->length, db->start);
        }

    }
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
    apr_status_t rv;

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

    /* Don't allow HEAD requests to trigger any caching operations. The
       reason for this is the large-file nature of this caching module,
       triggering the caching of a huge file just to satisfy a HEAD request
       is potentially resource-intensive.
       We could compromise and just cache a header, but then we get into
       trouble if we want to revalidate it into a complete cached item within
       the update timeout. */
    /* FIXME: Make this configureable? */
    if(r->header_only) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "URL %s not cached, header_only request", key);

        return DECLINED;
    }

    if (APLOGrtrace1(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "create_entity called. r->filename: %s "
                      "finfo.filetype: %d "
                      "finfo.valid: %x "
                      "finfo.protection: %x "
                      "finfo.fname: %s "
                      "len: %" APR_OFF_T_FMT,
                      r->filename, r->finfo.filetype, r->finfo.valid, 
                      r->finfo.protection, 
                      r->finfo.fname?r->finfo.fname:"NULL", len);
        if (APLOGrtrace2(r)) {
            debug_rlog_brigade(APLOG_MARK, APLOG_TRACE2, 0, r, bb, 
                               "create_entity bb");
        }
    }

    /* Would really like to avoid caching of objects without
       last-modified, but that doesn't seem to be available until
       store_headers, from which we can't return DECLINED ...
       So let's settle for only handling objects that stems from
       files/directories for now.
     */
    /* FIXME: It would make sense to make this configureable */
    if(r->finfo.filetype != APR_REG && r->finfo.filetype != APR_DIR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "URL %s not cached, not file/directory (filetype: %d)",
                     key, r->finfo.filetype);
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pstrdup(r->pool, key);

    rv = apr_pool_create(&(dobj->tpool), r->pool);
    if(rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                     "Unable to create temporary pool");
        return DECLINED;
    }
    apr_pool_tag(dobj->tpool, "mod_cache_disk_largefile (create_entity)");
    dobj->tbuf = NULL;

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


    /* As of httpd 2.4 r->filename and r->finfo always seem to be set,
       faked together from URL and document-root if there is no backing file!

       r->finfo.filetype seems to be correct when it's a real file though...
     */

    if(r->filename != NULL && strlen(r->filename) > 0) {
        dobj->filename = r->filename;
    }

    if(r->finfo.filetype == APR_REG) {
        char buf[34];
        char *str;
        int usedevino = TRUE;

        /* finfo.protection (st_mode) set to zero if no such file */
        if(r->finfo.protection == 0) {
            usedevino = FALSE;
        }
        /* Is the device/inode in r->finfo valid? */
        if(!(r->finfo.valid & APR_FINFO_IDENT)) {
            usedevino = FALSE;
        }

        /* When possible, hash the body on dev:inode to minimize file
           duplication. */
        if(usedevino) {
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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "File %s was hashed using %s into %s",
                     r->filename, str, dobj->bodyfile);
    }
    else {
        dobj->bodyfile = cache_file(r->pool, conf, NULL, key, 
                                    CACHE_BODY_SUFFIX);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Body of URL %s was hashed into %s",
                     key, dobj->bodyfile);
    }

    return OK;
}


static apr_status_t file_read_timeout(apr_file_t *file, char * buf,
                                      apr_size_t len, apr_time_t timeout)
{
    apr_size_t left, done;
    apr_finfo_t finfo;
    apr_status_t rc;
    apr_interval_time_t loopdelay=CACHE_LOOP_MINSLEEP;

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
        apr_sleep(loopdelay);
        loopdelay <<= 1;
        if(loopdelay > CACHE_LOOP_MAXSLEEP) {
            loopdelay = CACHE_LOOP_MAXSLEEP;
        }
    }

    return APR_SUCCESS;
}


static apr_status_t open_header(cache_object_t *obj, disk_cache_object_t *dobj,
                                request_rec *r, const char *key, 
                                disk_cache_conf *conf)
{
    int flags = APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_BINARY;
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

        dobj->errcleanflags |= ERRCLEAN_HEADER;
        file_cache_errorcleanup(dobj, r);

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
    apr_interval_time_t loopdelay=CACHE_LOOP_MINSLEEP;

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
        apr_sleep(loopdelay);
        loopdelay <<= 1;
        if(loopdelay > CACHE_LOOP_MAXSLEEP) {
            loopdelay = CACHE_LOOP_MAXSLEEP;
        }
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
       dobj->disk_info.name_len == 0 ||
       dobj->disk_info.bodyname_len > MAX_STRING_LEN ||
       dobj->disk_info.bodyname_len == 0 ||
       dobj->disk_info.filename_len > MAX_STRING_LEN) 
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Corrupt cache header for URL %s, deleting: %s",
                dobj->name, dobj->hdrsfile);
        dobj->errcleanflags |= ERRCLEAN_HEADER;
        file_cache_errorcleanup(dobj, r);

        return CACHE_EDECLINED;
    }

    len = dobj->disk_info.name_len;
    urlbuff = apr_palloc(dobj->tpool, len+1);
    if(urlbuff == NULL) {
        return APR_ENOMEM;
    }

    rc = file_read_timeout(dobj->hfd, urlbuff, len, conf->updtimeout);
    if (rc == APR_ETIMEDOUT) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                     "Timed out waiting for urlbuff for "
                     "URL %s - caching failed?",  dobj->name);
        dobj->errcleanflags |= ERRCLEAN_HEADER;
        file_cache_errorcleanup(dobj, r);

        return CACHE_EDECLINED;
    }
    else if(rc != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                     "Error reading urlbuff for URL %s",
                     dobj->name);
        dobj->errcleanflags |= ERRCLEAN_HEADER;
        file_cache_errorcleanup(dobj, r);

        return CACHE_EDECLINED;
    }
    urlbuff[len] = '\0';

    /* check that we have the same URL */
    if (strcmp(urlbuff, dobj->name) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "Cached URL %s didn't match requested "
                     "URL %s", urlbuff, dobj->name);
        dobj->errcleanflags |= ERRCLEAN_HEADER;
        file_cache_errorcleanup(dobj, r);

        return CACHE_EDECLINED;
    }

    /* Read in the file the body is stored in */
    len = dobj->disk_info.bodyname_len;
    if(len > 0) {
        char *bodyfile = apr_palloc(dobj->tpool, len+1);

        if(bodyfile == NULL) {
            return APR_ENOMEM;
        }

        rc = file_read_timeout(dobj->hfd, bodyfile, len, conf->updtimeout);
        if (rc == APR_ETIMEDOUT) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Timed out waiting for body cache "
                         "filename for URL %s - caching failed?", dobj->name);
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            file_cache_errorcleanup(dobj, r);

            return CACHE_EDECLINED;
        }
        else if(rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Error reading body cache filename for "
                         "URL %s", dobj->name);
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            file_cache_errorcleanup(dobj, r);

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
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            file_cache_errorcleanup(dobj, r);

            return CACHE_EDECLINED;
        }
        else if(rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rc, r,
                         "Error reading filename for URL %s",
                         dobj->name);
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            file_cache_errorcleanup(dobj, r);

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


/* FIXME: Use our own set of status code so callers can do the appropriate? */
static apr_status_t check_dest_invalid(apr_file_t *fd, apr_finfo_t *finfo,
                                         apr_time_t now, apr_time_t updtimeout,
                                         apr_off_t finalsize, 
                                         apr_ino_t inode, apr_time_t lastmod) 
{
    apr_status_t rc;
    apr_finfo_t localfinfo;

    if (APLOGtrace2(ap_server_conf)) {
        apr_uint64_t uinode = inode;

        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                "Called check_dest_invalid.  fd: %pp  "
                "finfo: %pp  "
                "now: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT "  "
                "updtimeout: %" APR_TIME_T_FMT "  "
                "finalsize: %" APR_OFF_T_FMT "  "
                "inode: %" APR_UINT64_T_HEX_FMT "  "
                "lastmod: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT,
                fd, finfo, apr_time_sec(now), apr_time_usec(now), updtimeout,
                finalsize, uinode, 
                apr_time_sec(lastmod), apr_time_usec(lastmod));
    }

    if(updtimeout == APR_DATE_BAD) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "check_dest_invalid called without valid updtimeout");
    }

    if(fd == NULL && finfo == NULL) {
        rc = APR_EINVAL;
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ap_server_conf,
                "check_dest_invalid: Must pass either fd or finfo");
        return rc;
    }

    if(finfo == NULL) {
        finfo = &localfinfo;
    }

    if(fd != NULL) {
        /* Get mtime and nlink for our opened destfile */
        rc = apr_file_info_get(finfo, APR_FINFO_NORM, fd);
        if(rc != APR_SUCCESS && !APR_STATUS_IS_INCOMPLETE(rc)) {
            if (APLOGtrace2(ap_server_conf)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE2, rc, ap_server_conf,
                        "check_dest_invalid: fd: %pp  "
                        "apr_file_info_get() failed", fd);
            }
            return rc;
        }
    }

    /* If link count is zero, file is deleted */
    if(finfo->valid & APR_FINFO_NLINK && finfo->nlink == 0) {
        if (APLOGtrace2(ap_server_conf)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                             "check_dest_invalid: fd: %pp  "
                             "deleted (nlinks==0)", fd);
        }
        return APR_ENOENT;
    }

    /* Check if correct inode if provided */
    if(inode && finfo->valid & APR_FINFO_IDENT && finfo->inode != inode) {
        if (APLOGtrace2(ap_server_conf)) {
                apr_uint64_t fuinode=finfo->inode, uinode = inode;

                ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                             "check_dest_invalid: "
                             "finfo->inode %" APR_UINT64_T_HEX_FMT " != "
                             "inode %" APR_UINT64_T_HEX_FMT,
                             fuinode, uinode);
        }
        return APR_EBADF;
    }

    if(finalsize < 0 || finfo->size != finalsize) {
        /* Only mtime on destfile shows us having timed out, but for
           files with unknown final size we accept files with matching
           last-modified. */
        if(now - finfo->mtime > updtimeout
                && 
                (
                 finalsize >= 0
                 ||
                 apr_time_sec(finfo->mtime) != apr_time_sec(lastmod)
                ) 
          )
        {
            if (APLOGtrace2(ap_server_conf)) {
                    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, 
                                 ap_server_conf,
                                 "check_dest_invalid: fd: %pp  "
                                 "stale (lastmod "
                                 "%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT
                                 " age %" APR_TIME_T_FMT 
                                 " > updtimeout %" APR_TIME_T_FMT ")",
                                 fd, 
                                 apr_time_sec(lastmod),
                                 apr_time_usec(lastmod),
                                 now-finfo->mtime, updtimeout);
            }
            return APR_ETIMEDOUT;
        }
    }
    else {
        /* If right size, file has either the correct mtime or
           mtime == ctime which means the mtime isn't set. The latter
           either means there was no Last-Modified available or
           that we're in the window between finished copying and setting
           mtime.
         */
        if(lastmod != APR_DATE_BAD &&
                apr_time_sec(finfo->mtime) != apr_time_sec(lastmod) &&
                (finfo->mtime != finfo->ctime ||
                 finfo->mtime < (now - updtimeout)) )
        {
            if (APLOGtrace2(ap_server_conf)) {
                    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, 
                                 ap_server_conf,
                                 "check_dest_invalid: fd: %pp  "
                                 "stale (size OK, mtime "
                                 "%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT
                                 " ctime "
                                 "%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT
                                 " <->lastmod "
                                 "%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT
                                 " mismatch)", fd,
                                 apr_time_sec(finfo->mtime),
                                 apr_time_usec(finfo->mtime),
                                 apr_time_sec(finfo->ctime),
                                 apr_time_usec(finfo->ctime),
                                 apr_time_sec(lastmod),
                                 apr_time_usec(lastmod));
            }
            return APR_ETIMEDOUT;
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
        if(finfo->valid & APR_FINFO_CSIZE && finalsize > 0 &&
                finfo->csize == 0 && finfo->ctime < (now - updtimeout))
        {
            if (APLOGtrace2(ap_server_conf)) {
                    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, 
                                 ap_server_conf,
                                 "check_dest_invalid: fd: %pp  "
                                 "csize == 0", fd);
            }
            return APR_EINCOMPLETE;
        }
    }

    if (APLOGtrace2(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                "check_dest_invalid:  fd: %pp  "
                "returning SUCCESS", fd);
    }

    return APR_SUCCESS;
}


static apr_status_t open_body_timeout(request_rec *r, cache_object_t *cache_obj,
                                      disk_cache_object_t *dobj)
{
    apr_status_t rc;
    apr_finfo_t finfo;
    int flags = APR_FOPEN_READ | APR_FOPEN_BINARY;
    unsigned int passes = 0;
    apr_interval_time_t loopdelay=CACHE_LOOP_MINSLEEP;
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

    if (APLOGrtrace2(r)) {
        apr_time_t now = apr_time_now();

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                "Called open_body_timeout.  URL: %s  "
                "bfd_read: %pp  "
                "response_time: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT "  "
                "now: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT "  "
                "updtimeout: %" APR_TIME_T_FMT,
                dobj->name, dobj->bfd_read,
                apr_time_sec(info->response_time),
                apr_time_usec(info->response_time),
                apr_time_sec(now), apr_time_usec(now),
                conf->updtimeout);
    }

    /* Wait here until we get a body cachefile, data in it, and do quick sanity
     * check */

    while(1) {
        passes++;

        if(dobj->bfd_read == NULL) {
            rc = apr_file_open(&dobj->bfd_read, dobj->bodyfile, flags, 0, r->pool);
            if(rc != APR_SUCCESS) {
                if(info->response_time < (apr_time_now() - conf->updtimeout) ) {
                    if(passes <= 1) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                                     "No bodyfile %s for URL %s - "
                                     "likely not cached due to "
                                     "HEAD request",
                                     dobj->bodyfile, dobj->name);
                    }
                    else {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r,
                                     "Timed out waiting for bodyfile "
                                     "%s for URL %s - caching failed?", 
                                     dobj->bodyfile, dobj->name);
                    }

                    return CACHE_EDECLINED;
                }

                apr_sleep(loopdelay);
                loopdelay <<= 1;
                if(loopdelay > CACHE_LOOP_MAXSLEEP) {
                    loopdelay = CACHE_LOOP_MAXSLEEP;
                }

                continue;
            }
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

        rc = check_dest_invalid(dobj->bfd_read, &finfo, apr_time_now(),
                                  conf->updtimeout, dobj->initial_size,
                                  dobj->bodyinode, dobj->lastmod);
        if(rc == APR_ENOENT) {
            /* This file has been deleted, close it and try again */
            apr_file_close(dobj->bfd_read);
            dobj->bfd_read = NULL;
            continue;
        }
        else if(rc != APR_SUCCESS) {
            /* Force revalidation for all other discrepancies */
            apr_file_remove(dobj->hdrsfile, r->pool);
            return CACHE_EDECLINED;
        }

        if(finfo.valid & APR_FINFO_SIZE) {
            dobj->file_size = finfo.size;
        }

        /* We don't even create/write 0-sized body files, so we know the
           size must be greater than 0 bytes */
        if(dobj->file_size > 0) {
            break;
        }

        apr_sleep(loopdelay);
        loopdelay <<= 1;
        if(loopdelay > CACHE_LOOP_MAXSLEEP) {
            loopdelay = CACHE_LOOP_MAXSLEEP;
        }

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

    if(APLOGrtrace3(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Called open_entity.  "
                      "URL: %s", key);
    }


    /* Create and init the cache object */
    obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));
    info = &(obj->info);

    rc = apr_pool_create(&(dobj->tpool), r->pool);
    if(rc != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                     "open_entity: URL: %s - Unable to create temporary pool",
                     key);

        return DECLINED;
    }
    apr_pool_tag(dobj->tpool, "mod_cache_disk_largefile (open_entity)");
    dobj->tbuf = NULL;

    /* Save the cache root */
    dobj->root = apr_pstrndup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;

    dobj->hdrsfile = cache_file(r->pool, conf, NULL, key, CACHE_HEADER_SUFFIX);

    dobj->header_only = r->header_only;

    /* Open header and read basic info, wait until header contains
       valid size information for the body */
    rc = open_header_timeout(obj, dobj, r, key, conf);
    if(rc != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);

        if(APLOGrtrace3(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, rc, r, "open_entity: "
                          "URL: %s - open_header_timeout failed, "
                          "returning DECLINED", key);
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
    dobj->bodyinode = (apr_ino_t) dobj->disk_info.bodyinode;
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    /* Load and check strings (URL, bodyfile, filename) */
    rc = load_header_strings(r, dobj);
    if(rc != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);

        if(APLOGrtrace3(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, rc, r, "open_entity: "
                          "URL: %s - load_header_strings failed, "
                          "returning DECLINED", key);
        }
        return DECLINED;
    }

    /* Directory listings and other dynamic content might change due to
       reloads (upgrades, config changes, ...). In order to promote those
       changes we resort to cleaning out non-file objects older than
       restart time to force re-caching them. */
    if(dobj->disk_info.filetype != APR_REG 
            && info->response_time < ap_scoreboard_image->global->restart_time)
    {
        dobj->errcleanflags |= ERRCLEAN_HEADER | ERRCLEAN_BODY;
        file_cache_errorcleanup(dobj, r);

        if(APLOGrtrace3(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, rc, r, "open_entity: "
                          "URL: %s - filetype %d "
                          "response_time %" APR_TIME_T_FMT " "
                          "older than restart_time %" APR_TIME_T_FMT " "
                          ", removed old object and returning DECLINED", 
                          key, dobj->disk_info.filetype,
                          info->response_time,
                          ap_scoreboard_image->global->restart_time);
        }
        return DECLINED;
    }

    /* Only need body cachefile if we have a body and this isn't a HEAD
       request */
    if(dobj->initial_size > 0 && !dobj->header_only) {
        if(dobj->bodyfile == NULL) {
            /* Force revalidation if body file name not present - this means
               that only the headers were cached due to a HEAD request */

            file_cache_errorcleanup(dobj, r);

            if(APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "open_entity: "
                              "URL: %s - no bodyfile, "
                              "returning DECLINED", key);
            }
               
            return DECLINED;
        }
        rc = open_body_timeout(r, obj, dobj);
        if(rc != APR_SUCCESS) {
            file_cache_errorcleanup(dobj, r);

            if(APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, rc, r, "open_entity: "
                              "URL: %s - open_body_timeout failed, "
                              "returning DECLINED", key);
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
                 "open_entity: Recalled status for cached URL %s from file %s",
                 dobj->name, dobj->hdrsfile);

    return OK;
}


/* Called to abort processing using this entity */
static int remove_entity(cache_handle_t *h)
{
    disk_cache_object_t *dobj;

    /* Get disk cache object from cache handle */
    dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    /* Null out the cache object pointer so next time we start from scratch */
    h->cache_obj = NULL;

    if(!dobj) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
            "remove_entity: %s", dobj->name);

    if(dobj->hfd != NULL) {
        apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
    }
    if(dobj->bfd_read != NULL) {
        apr_file_close(dobj->bfd_read);
        dobj->bfd_read = NULL;
    }
    if(dobj->bfd_write != NULL) {
        apr_file_close(dobj->bfd_write);
        dobj->bfd_write = NULL;
    }

    /* Destroy temporary pool and buffer */
    if(dobj->tpool != NULL) {
        dobj->tbuf = NULL;
        apr_pool_destroy(dobj->tpool);
        dobj->tpool = NULL;
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
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;


    if (APLOGrtrace3(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Called commit_entity.  "
                      "URL: %s", dobj->name);
    }

    /* Destroy temporary pool and buffer */
    if(dobj->tpool != NULL) {
        if (APLOGrtrace4(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "commit_entity: tpool cleanup");
        }
        dobj->tbuf = NULL;
        apr_pool_destroy(dobj->tpool);
        dobj->tpool = NULL;
    }

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
    apr_interval_time_t loopdelay=CACHE_LOOP_MINSLEEP;

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

        rv = apr_file_info_get(&finfo, APR_FINFO_MTIME | APR_FINFO_NLINK,
                               dobj->hfd);
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
        if(finfo.nlink == 0) {
            /* Header file deleted, might mean that ongoing store failed so
               play it safe and trigger rewrite */
            file_cache_errorcleanup(dobj, r);
            return APR_ENOENT;
        }
        rv = apr_file_seek(dobj->hfd, APR_SET, &off);
        if(rv != APR_SUCCESS) {
            return rv;
        }

        apr_sleep(loopdelay);
        loopdelay <<= 1;
        if(loopdelay > CACHE_LOOP_MAXSLEEP) {
            loopdelay = CACHE_LOOP_MAXSLEEP;
        }

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

    if(dobj->initial_size < 0) {
        /* This should also never happen... */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "recall_body: Called but initial_size < 0, URL %s",
                     dobj->name);
        return APR_EGENERAL;
    }

    /* Restore r->filename if not present */
    if(dobj->filename != NULL && dobj->rfilename != NULL && 
            *(dobj->rfilename) == NULL) 
    {
        *(dobj->rfilename) = dobj->filename;
    }

    if(!dobj->header_only) {
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

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "recall_body: Succeeded for URL %s from file %s",
                     dobj->name, dobj->bodyfile);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "recall_body: No data inserted, header_only. URL %s",
                     dobj->name);
    }

    e = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    /* Destroy temporary pool and buffer */
    if(dobj->tpool != NULL) {
        dobj->tbuf = NULL;
        apr_pool_destroy(dobj->tpool);
        dobj->tpool = NULL;
    }

    return APR_SUCCESS;
}

/* Store table on disk.
 * Format on disk: apr_uint32_t totsize - total size of data following totsize
 *                 totsize of data, consisting of key\0value\0...key\0value\0
 */
static apr_status_t store_table(apr_file_t *fd, apr_table_t *table,
                                apr_pool_t *pool)
{
    int i, nelts, niov;
    apr_status_t rv = APR_SUCCESS;
    apr_uint32_t totsize = 0;
    apr_table_entry_t *elts;
    struct iovec *iov;

    nelts = apr_table_elts(table)->nelts;

    /* Allocate space for the size-header plus two elements per table entry */

    iov = apr_palloc(pool, (1+nelts*2) * sizeof(struct iovec));
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


static apr_status_t open_new_file(request_rec *r, apr_pool_t *pool,
                                  const char *filename, apr_file_t **fd, 
                                  apr_time_t srcmtime, apr_off_t srcsize,
                                  apr_interval_time_t updtimeout)
{
    int flags = APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_BINARY 
                | APR_FOPEN_EXCL;
    apr_status_t rv;

    if (APLOGrtrace3(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                "Called open_new_file.  pool: %pp  "
                "filename: %s  "
                "srcmtime: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT "  "
                "srcsize: %" APR_OFF_T_FMT "  ",
                pool, filename, apr_time_sec(srcmtime), apr_time_usec(srcmtime),
                srcsize);
    }

    while(1) {
        rv = apr_file_open(fd, filename, flags, 
                           APR_FPROT_UREAD | APR_FPROT_UWRITE, pool);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                     "open_new_file: Opening %s", filename);

        if(APR_STATUS_IS_EEXIST(rv)) {
            apr_finfo_t finfo;

            rv = apr_stat(&finfo, filename, APR_FINFO_NORM, pool);
            if(APR_STATUS_IS_ENOENT(rv)) {
                /* Someone else has already removed it, try again */
                continue;
            }
            else if(rv != APR_SUCCESS) {
                return rv;
            }

            rv = check_dest_invalid(NULL, &finfo, apr_time_now(),
                                    updtimeout, srcsize, 0, srcmtime);

            if(rv == APR_SUCCESS) {
                return CACHE_EEXIST;
            }
            else {
                /* Something stale that's left around */

                rv = apr_file_remove(filename, pool);
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
        }
        else if(APR_STATUS_IS_ENOENT(rv)) {
            /* The directory for the file didn't exist */

            rv = mkdir_structure(filename, pool);
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

    flags = APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_BINARY 
            | APR_FOPEN_EXCL | APR_FOPEN_BUFFERED;
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
        return rv;
    }

    rv = safe_file_rename(dobj->tempfile, vfile, dobj->tpool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "rename tempfile to varyfile failed: "
                     "%s -> %s", dobj->tempfile, vfile);
        file_cache_errorcleanup(dobj, r);
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
    disk_info.bodyinode = dobj->bodyinode;
    disk_info.lastmod = dobj->lastmod;
    disk_info.filetype = APR_NOFILE;

    if(r->finfo.valid & APR_FINFO_TYPE) {
        disk_info.filetype = r->finfo.filetype;
    }

    memcpy(&disk_info.control, &h->cache_obj->info.control, sizeof(cache_control_t));

    niov = 0;
    iov[niov].iov_base = (void*)&format;
    iov[niov++].iov_len = sizeof(format);
    iov[niov].iov_base = (void*)&disk_info;
    iov[niov++].iov_len = sizeof(disk_cache_info_t);

    disk_info.name_len = strlen(dobj->name);
    iov[niov].iov_base = (void*)dobj->name;
    iov[niov++].iov_len = disk_info.name_len;

    /* We know the bodyfile is root/bodyname ... */
    char *bodyname = (char *) dobj->bodyfile + dobj->root_len + 1;
    disk_info.bodyname_len = strlen(bodyname);
    iov[niov].iov_base = (void*)bodyname;
    iov[niov++].iov_len = disk_info.bodyname_len;

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
        return rv;
    }

    if (r->headers_out) {
        apr_table_t *headers_out;

        headers_out = ap_cache_cacheable_headers_out(r);

        rv = store_table(dobj->hfd, headers_out, dobj->tpool);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    /* Parse the vary header and dump those fields from the headers_in. */
    /* FIXME: Make call to the same thing cache_select calls to crack Vary. */
    if (r->headers_in) {
        apr_table_t *headers_in;

        headers_in = ap_cache_cacheable_headers_in(r);

        rv = store_table(dobj->hfd, headers_in, dobj->tpool);
        if (rv != APR_SUCCESS) {
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

    if (APLOGrtrace1(r)) {
        apr_uint64_t dobj_bodyinode=dobj->bodyinode;
        apr_uint64_t diskinfo_bodyinode=dobj->disk_info.bodyinode;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Called store_headers.  "
                      "URL: %s  "
                      "dobj->skipstore: %d  "
                      "dobj->lastmod: %" APR_TIME_T_FMT "  "
                      "disk_info.lastmod: %" APR_TIME_T_FMT "  "
                      "dobj->initial_size: %" APR_OFF_T_FMT "  "
                      "disk_info.file_size: %" APR_OFF_T_FMT "  "
                      "request_time: %" APR_OFF_T_FMT "  "
                      "disk_info.expire: %" APR_OFF_T_FMT "  "
                      "info->date: %" APR_OFF_T_FMT "  "
                      "disk_info.date: %" APR_OFF_T_FMT "  "
                      "dobj->bodyinode: %" APR_UINT64_T_FMT "  "
                      "disk_info.bodyinode: %" APR_UINT64_T_FMT
                      , dobj->name, dobj->skipstore, 
                      dobj->lastmod, dobj->disk_info.lastmod,
                      dobj->initial_size, dobj->disk_info.file_size,
                      r->request_time, dobj->disk_info.expire,
                      info->date, dobj->disk_info.date, dobj_bodyinode,
                      diskinfo_bodyinode);
    }

    if(dobj->hfd) {
        rewriting = TRUE;
        int hdrcurrent = TRUE;

        if(dobj->disk_info.file_size < 0) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "Header on disk indicating unknown size "
                              "being cached" , dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->initial_size < 0) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "Unknown size, shouldn't really happen when"
                              "rewriting...", dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->initial_size != dobj->disk_info.file_size) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "This object and on-disk object size doesn't "
                              "match", dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->bodyinode != dobj->disk_info.bodyinode) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "Body inode doesn't match on-disk header",
                              dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->lastmod != APR_DATE_BAD && 
                dobj->lastmod != dobj->disk_info.lastmod)
        {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                               "Last-Modified does not match", dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->disk_info.expire <= r->request_time) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "On-disk headers expired", dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->disk_info.date <= info->date - conf->updtimeout) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "On-disk headers older than updtimeout",
                              dobj->name);
            }
            hdrcurrent = FALSE;
        }
        else if(dobj->disk_info.bodyname_len == 0 && dobj->bodyfile != NULL) {
            if (APLOGrtrace3(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "store_headers: URL: %s  not current: "
                              "On-disk headers missing bodyfile",
                              dobj->name);
            }
            hdrcurrent = FALSE;
        }

        if(hdrcurrent) {
            dobj->skipstore = TRUE;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                         "store_headers: Headers current for URL %s", 
                         dobj->name);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                         "Rewriting headers for URL %s", dobj->name);
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

    if(!dobj->skipstore) {
        if(rewriting) {
            apr_off_t off=0;
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            rv = apr_file_seek(dobj->hfd, APR_SET, &off);
            if (rv != APR_SUCCESS) {
                file_cache_errorcleanup(dobj, r);
                return rv;
            }
            rv = apr_file_trunc(dobj->hfd, 0);
            if(rv != APR_SUCCESS) {
                file_cache_errorcleanup(dobj, r);
                return rv;
            }
        }
        else {
            rv = open_new_file(r, dobj->tpool, dobj->hdrsfile, &(dobj->hfd), 
                               APR_DATE_BAD, -1, conf->updtimeout);
            if(rv == CACHE_EEXIST) {
                dobj->skipstore = TRUE;
            }
            else if(rv != APR_SUCCESS) {
                return rv;
            }
        }
    }

    if(r->header_only && (dobj->initial_size < 0 || dobj->bodyinode == 0)) {
        if (APLOGrtrace3(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "store_headers: URL: %s  header_only rewrite but "
                          "missing body size/inode",
                          dobj->name);
        }
        dobj->skipstore = TRUE;
    }

    if(dobj->skipstore) {
        if(dobj->hfd) {
            apr_file_close(dobj->hfd);
            dobj->hfd = NULL;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "store_headers: Skipping store for URL %s", dobj->name);
        return APR_SUCCESS;
    }

    dobj->errcleanflags |= ERRCLEAN_HEADER;

    rv = store_disk_header(h, r, info);
    if(rv != APR_SUCCESS) {
        file_cache_errorcleanup(dobj, r);
        return rv;
    }

    /* If the body size or inode is unknown, the header file will be rewritten
       later so we can't close it */
    if(dobj->initial_size >= 0 && dobj->bodyinode != 0) {
        rv = apr_file_close(dobj->hfd);
        dobj->hfd = NULL;
        if(rv != APR_SUCCESS) {
            file_cache_errorcleanup(dobj, r);
            return rv;
        }
    }

    if (APLOGrtrace1(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                "store_headers done.  URL: %s  "
                "initial_size: %" APR_OFF_T_FMT "  "
                "lastmod: %" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT,
                dobj->name, dobj->initial_size,
                apr_time_sec(dobj->lastmod), apr_time_usec(dobj->lastmod));
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Stored headers for URL %s",  dobj->name);
    }

    dobj->errcleanflags &= ~ERRCLEAN_HEADER;

    return APR_SUCCESS;
}


static apr_status_t copy_file_region(char *buf, const apr_size_t bufsize,
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
    off64_t srcoff_os, destoff_os, fadvoff, flushoff;
    apr_off_t destfinalsize = destoff+len;
    int err;

    if (APLOGtrace2(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                "Called copy_file_region.  bufsize: %" APR_SIZE_T_FMT "  "
                "srcfd: %pp  destfd: %pp  srcoff: %" APR_OFF_T_FMT "  "
                "destoff: %" APR_OFF_T_FMT "  len: %" APR_OFF_T_FMT,
                bufsize, srcfd, destfd, srcoff, destoff, len);
    }

    if(srcoff >= 0) {
        rc = apr_file_seek(srcfd, APR_SET, &srcoff);
    }
    else {
        srcoff = 0;
        rc = apr_file_seek(srcfd, APR_CUR, &srcoff);
        if (APLOGtrace4(ap_server_conf)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                    "copy_file_region: srcoff: %" APR_OFF_T_FMT,
                    srcoff);
        }
    }
    if(rc != APR_SUCCESS) {
        return rc;
    }
    srcoff_os = srcoff;
    fadvoff = srcoff;

    if(destoff >= 0) {
        rc = apr_file_seek(destfd, APR_SET, &destoff);
    }
    else {
        destoff = 0;
        rc = apr_file_seek(srcfd, APR_CUR, &destoff);
        if (APLOGtrace4(ap_server_conf)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                    "copy_file_region: destoff: %" APR_OFF_T_FMT,
                    destoff);
        }
    }
    if(rc != APR_SUCCESS) {
        return rc;
    }
    destoff_os = destoff;
    flushoff = destoff;

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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                     "copy_file_region: posix_fadvise");
    }
#endif /* POSIX_FADV_SEQUENTIAL */

    while(len > 0) {
#ifdef POSIX_FADV_WILLNEED
        if(len > 0 && fadvoff < srcoff_os + S_MIN(2*bufsize, len)) 
        {
            size_t fadvamount = S_MIN(len, CACHE_FADVISE_WINDOW);
            /* Tell kernel that we'll need more segments soon */
            err=posix_fadvise(srcfd_os, srcoff_os, fadvamount,
                              POSIX_FADV_WILLNEED);
            if(err) {
                rc = APR_FROM_OS_ERROR(err);
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                             "copy_file_region: posix_fadvise");
            }
            if (APLOGtrace5(ap_server_conf)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                        "copy_file_region: fadvise WILLNEED off: %"
                        APR_OFF_T_FMT "  amount: %" APR_OFF_T_FMT,
                        srcoff_os, fadvamount);
            }
            fadvoff += fadvamount;
        }
#endif /* POSIX_FADV_WILLNEED */

        size=S_MIN(len, bufsize);

        rc = apr_file_read_full (srcfd, buf, size, NULL);
        if(rc != APR_SUCCESS) {
            return rc;
        }

#ifdef POSIX_FADV_DONTNEED
        /* We will never need this segment again */
        err=posix_fadvise(srcfd_os, srcoff_os, size, POSIX_FADV_DONTNEED);
        if(err) {
            rc = APR_FROM_OS_ERROR(err);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                         "copy_file_region: posix_fadvise");
        }
#endif /* POSIX_FADV_DONTNEED */

        srcoff_os += size;


        /* Do timeout checks before we do the write, this is what other clients
           will see. Don't waste resources by calling apr_time_now() on each
           iteration. */
        if(i++ % freq == 0) {
            apr_time_t now = apr_time_now();
            apr_time_t elapsed = now-last;

            /* Do closer inspection at updtimeout intervals */
            if(now-lastcheck > updtimeout) {
                /* FIXME: Would it make sense to also check if our header
                          file is still there? If it has been deleted during
                          copy it makes little sense to keep going... */
                /* FIXME: Should be possible to get last-modified and bodyinode
                          in here as well */
                rc = check_dest_invalid(destfd, NULL, now, updtimeout,
                                          destfinalsize, 0, APR_DATE_BAD);
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
        if(destoff_os - flushoff >= CACHE_WRITE_FLUSH_WINDOW) 
        {
            /* Start flushing the current write window */
            if(sync_file_range(destfd_os, flushoff, destoff_os - flushoff,
                            SYNC_FILE_RANGE_WRITE) != 0)
            {
                return(APR_FROM_OS_ERROR(errno));
            }
            if (APLOGtrace4(ap_server_conf)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                        "copy_file_region: sync_file_range WRITE off: %"
                        APR_OFF_T_FMT "  amount: %" APR_OFF_T_FMT,
                        flushoff, destoff_os - flushoff);
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
                if (APLOGtrace4(ap_server_conf)) {
                    ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                            "copy_file_region: sync_file_range WAIT off: %"
                            APR_OFF_T_FMT "  amount: %" APR_OFF_T_FMT,
                            flushoff-CACHE_WRITE_FLUSH_WINDOW,
                            (apr_off_t)CACHE_WRITE_FLUSH_WINDOW);
                }
            }

            flushoff = destoff_os;
        }
#endif /* SYNC_FILE_RANGE_WRITE */
    }

    /* Make sure we are the one having cached the destfile */
    /* FIXME: provide last-modified and bodyinode */
    rc = check_dest_invalid(destfd, NULL, apr_time_now(), updtimeout,
                              destfinalsize, 0, APR_DATE_BAD);
    if(rc != APR_SUCCESS) {
        return rc;
    }

    /* Check if file has changed during copying. This is not 100% foolproof
       due to NFS attribute caching when on NFS etc. */
    /* FIXME: Can we assume that we're always copying an entire file? In that
              case we can check if the current filesize matches the length
              we think it is */
    rc = apr_file_info_get(&finfo, APR_FINFO_MTIME, srcfd);
    if(rc == APR_SUCCESS) {
        if(starttime < finfo.mtime) {
            rc = APR_EGENERAL;
        }
    }

    if (APLOGtrace2(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rc, ap_server_conf,
                "copy_file_region: Done.");
    }

    return rc;
}


static apr_status_t bgcopy_thread_cleanup(void *data)
{
    copyinfo *ci = data;
    apr_status_t rc, ret;
    apr_pool_t *p;

    if (APLOGtrace2(ci->s)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ci->s,
                     "bgcopy_thread_cleanup: called for %s -> %s",
                     ci->srcname, ci->destname);
    }

    rc = apr_thread_join(&ret, ci->t);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ci->s,
                     "bgcopy_thread_cleanup: apr_thread_join "
                     "failed %s -> %s", ci->srcname, ci->destname);
        return rc;
    }
    if(ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, ret, ci->s,
                     "Background caching body %s -> %s failed",
                     ci->srcname, ci->destname);
    }

    if (APLOGtrace1(ci->s)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ci->s,
                "bgcopy_thread_cleanup: SUCCESS %s -> %s",
                ci->srcname, ci->destname);
    }

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
    char *buf;
    apr_size_t bufsize;

    p = apr_thread_pool_get(t);

    if (APLOGtrace1(ci->s)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ci->s,
                     "bgcopy_thread: start %s -> %s",
                     ci->srcname, ci->destname);
    }


    bufsize = S_MIN(ci->len, CACHE_BUF_SIZE);
    buf = apr_palloc(p, bufsize);
    if (!buf) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_ENOMEM, ci->s,
                     "bgcopy_thread: palloc buf");
        apr_thread_exit(t, APR_ENOMEM);
        return NULL;
    }

    rc = copy_file_region(buf, bufsize, ci->srcfd, ci->srcoff,
                          ci->destfd, ci->destoff, ci->len, ci->updtimeout);

    apr_file_close(ci->srcfd);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ci->s,
                     "bgcopy_thread: copy_file_region");
        apr_file_close(ci->destfd);
        apr_thread_exit(t, rc);
        return NULL;
    }

    rc = apr_file_close(ci->destfd);

    /* Set mtime on dest file to the one of the source file */
    apr_file_mtime_set(ci->destname, ci->srcmtime, p);

    if(rc != APR_ETIMEDOUT && rc != APR_SUCCESS) {
        apr_file_remove(ci->destname, p);
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ci->s,
                     "bgcopy_thread: failed %s -> %s",
                     ci->srcname, ci->destname);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ci->s,
                     "bgcopy_thread: done %s -> %s",
                     ci->srcname, ci->destname);
    }

    apr_thread_exit(t, rc);
    return NULL;
}


static apr_status_t do_bgcopy(apr_file_t *srcfd, apr_off_t srcoff, 
                              apr_time_t srcmtime,
                              apr_file_t *destfd, apr_off_t destoff, 
                              apr_off_t len, apr_interval_time_t updtimeout,
                              conn_rec *c)
{
    copyinfo *ci;
    apr_status_t rv;
    apr_pool_t *newpool;

    /* It seems pool gets destroyed (ie. fd's closed) before our cleanup 
       function is called when an error occurs (a dropped connection, for
       example), so we need a pool of our own.
     */
    rv = apr_pool_create(&newpool, NULL);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    apr_pool_tag(newpool, "mod_cache_disk_largefile (do_bgcopy)");

    ci = apr_palloc(newpool, sizeof(*ci));
    if(ci == NULL) {
        apr_pool_destroy(newpool);
        return APR_ENOMEM;
    }

    rv = apr_file_setaside(&(ci->srcfd), srcfd, newpool);
    if(rv != APR_SUCCESS) {
        apr_pool_destroy(newpool);
        return rv;
    }
    rv = apr_file_name_get(&(ci->srcname), ci->srcfd);
    if(rv != APR_SUCCESS) {
        apr_pool_destroy(newpool);
        return rv;
    }

    rv = apr_file_setaside(&(ci->destfd), destfd, newpool);
    if(rv != APR_SUCCESS) {
        apr_pool_destroy(newpool);
        return rv;
    }
    rv = apr_file_name_get(&(ci->destname), ci->destfd);
    if(rv != APR_SUCCESS) {
        apr_pool_destroy(newpool);
        return rv;
    }

    ci->pool = newpool;
    ci->srcoff = srcoff;
    ci->srcmtime = srcmtime;
    ci->destoff = destoff;
    ci->len = len;
    ci->updtimeout = updtimeout;
    ci->s = c->base_server; /* Can't use c - it might have been destroyed */

    apr_threadattr_t *ta;
    apr_thread_t *t;
    rv = apr_threadattr_create(&ta, newpool);
    if(rv != APR_SUCCESS) {
        apr_pool_destroy(newpool);
        return rv;
    }

    rv = apr_threadattr_detach_set(ta, FALSE);
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

    return rv;
}


static unsigned int brigade_single_seqfile(request_rec *r,
                                       apr_bucket_brigade *bb, apr_off_t size)
{
    apr_off_t begin = -1;
    apr_off_t pos = -1;
    apr_file_t *fd = NULL;
    apr_bucket *e;
    apr_bucket_file *a;

    if (APLOGrtrace5(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                "brigade_single_seqfile: called.");
    }

    for (e = APR_BRIGADE_FIRST(bb);
            e != APR_BRIGADE_SENTINEL(bb);
            e = APR_BUCKET_NEXT(e))
    {
        if(APR_BUCKET_IS_EOS(e)) {
            break;
        }

        /* Ignore any interspersed metadata buckets */
        if(APR_BUCKET_IS_METADATA(e)) {
            continue;
        }

        if(!APR_BUCKET_IS_FILE(e)) {
            if (APLOGrtrace5(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                              "brigade_single_seqfile: not FILE bucket, "
                              "return FALSE");
            }
            return FALSE;
        }

        a = e->data;

        if(begin < 0) {
            begin = pos = e->start;
            fd = a->fd;
        }

        if(fd != a->fd || pos != e->start) {
            if (APLOGrtrace5(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                              "brigade_single_seqfile: fd/pos mispmatch, "
                              "return FALSE");
            }
            return FALSE;
        }

        pos += e->length;
    }
    if(begin+pos < size) {
        if (APLOGrtrace5(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                    "brigade_single_seqfile: begin %" APR_OFF_T_FMT
                    " + pos %" APR_OFF_T_FMT
                    " < size %" APR_OFF_T_FMT ", return FALSE",
                    begin, pos, size);
        }
        return FALSE;
    }

    if (APLOGrtrace5(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                      "brigade_single_seqfile: return TRUE");
    }

    return TRUE;
}


static apr_status_t preallocate_file(request_rec *r, apr_file_t *fd, 
                                     apr_off_t size)
{
    apr_status_t rv;

#ifdef __linux
    int bfd_os;

    rv = apr_os_file_get(&bfd_os, fd);
    if(rv != APR_SUCCESS) {
        return rv;
    }

    errno = 0; /* Not set on success */

    if(fallocate(bfd_os, FALLOC_FL_KEEP_SIZE, 0, size) != 0) 
    {
        /* Only choke on relevant errors */
        if(errno == EBADF || errno == ENOSPC || errno == EIO) {
            rv = APR_FROM_OS_ERROR(errno);
        }
    }

    if (APLOGrtrace4(r)) {
        const char *fname;
        apr_file_name_get(&fname, fd);

        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, APR_FROM_OS_ERROR(errno), r,
                "preallocate_file: %" APR_OFF_T_FMT "  "
                "%s", size, fname);
    }
#endif /* __linux */

    return rv;
}


static apr_status_t store_body(cache_handle_t *h, request_rec *r,
                               apr_bucket_brigade *in, apr_bucket_brigade *out)
{
    apr_bucket *e, *fbout=NULL;
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *fdpool = NULL;
    int did_bgcopy = FALSE;
    int readflags = APR_FOPEN_READ | APR_FOPEN_BINARY;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_largefile_module);

#if APR_HAS_SENDFILE
    core_dir_config *pdconf = ap_get_core_module_config(r->per_dir_config);
    /* When we are in the quick handler we don't have the per-directory
     * configuration, so this check only takes the global setting of
     * the EnableSendFile directive into account.  */
    readflags |= AP_SENDFILE_ENABLED(pdconf->enable_sendfile);
#endif  

    if (APLOGrtrace1(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Called store_body.  "
                "pools:  r: %pp  conn: %pp  in->p: %pp  out->p: %pp",
                r->pool, r->connection->pool, in->p, out->p);

        if (APLOGrtrace2(r)) {
            debug_rlog_brigade(APLOG_MARK, APLOG_TRACE2, 0, r, in, 
                               "store_body in");
        }
    }

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
        if (APLOGrtrace3(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "store_body: initial_size==0, bypassing");
        }
        return APR_SUCCESS;
    }

    /* This is is plain weird. In some cases, for example a dir index, the
       first call to store_body() has a different in->p pool. When this is
       the case, allocating fd:s from r->pool yields a Bad File Descriptor
       error in the core output filter for some reason. However, it does
       work to allocate the fd on the connection pool instead. To avoid
       collecting multiple fds on a connection, for example during keepalive,
       we do this only when necessary */
    if(r->pool == in->p) {
        if (APLOGrtrace4(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "store_body: r->pool == in->p");
        }
        fdpool = r->pool;
    }
    else {
        if (APLOGrtrace4(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "store_body: r->pool != in->p");
        }
        fdpool = r->connection->pool;
    }

    /* Only perform these actions when called the first time */
    if(!dobj->store_body_called) {
        dobj->store_body_called = TRUE;

        if (APLOGrtrace4(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "store_body: first call");
        }

        rv = apr_file_open(&dobj->bfd_read, dobj->bodyfile, readflags, 
                           0, fdpool);

        if(rv == APR_SUCCESS) {
            apr_finfo_t firstfinfo;
            rv = check_dest_invalid(dobj->bfd_read, &firstfinfo,
                                      apr_time_now(), conf->updtimeout,
                                      dobj->initial_size, 0,
                                      dobj->lastmod);
            if(rv == APR_SUCCESS) {
                /* Assume it's a valid cached bodyfile, either being cached
                   or fully cached */
                int needhdrupdate = FALSE;
                /* skipstore can also be set by the first call
                   to store_headers */
                int hdrskipstore = dobj->skipstore;
                int bodyskipstore = FALSE;

                /* Do skipstore (ie, reuse already cached body) if either:
                   - initial_size >= 0
                   - initial_size < 0 AND mtime == Last-Modified. This ensures
                     that we know the final size.
                 */
                if(dobj->initial_size < 0) {
                    if(dobj->lastmod != APR_DATE_BAD
                            &&
                            apr_time_sec(dobj->lastmod) 
                            ==
                            apr_time_sec(firstfinfo.mtime)) 
                    {
                        dobj->initial_size = firstfinfo.size;
                        dobj->file_size = firstfinfo.size;

                        if(!hdrskipstore) {
                            /* Update header information with known size only
                               if initial call to store_headers didn't set
                               skipstore
                             */
                            needhdrupdate = TRUE;
                        }
                        bodyskipstore = TRUE;

                        if (APLOGrtrace4(r)) {
                            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, rv, r,
                                          "store_body: skipstore, "
                                          "initial_size updated to"
                                          " %" APR_OFF_T_FMT " from "
                                          "cached body", dobj->initial_size);
                        }
                    }
                }
                else {
                    bodyskipstore = TRUE;

                    if(dobj->bodyinode != firstfinfo.inode) {
                        if(!hdrskipstore) {
                            dobj->bodyinode = firstfinfo.inode;
                            needhdrupdate = TRUE;
                        }
                    }

                    /* Note: File might still be written */
                    dobj->file_size = firstfinfo.size;

                    if (APLOGrtrace4(r)) {
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                      "store_body: skipstore "
                                      "(found cached body)");
                    }
                }
                if(needhdrupdate) {
                    rv = store_headers(h, r, &(h->cache_obj->info));
                    if(rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                                "URL %s store_body store_headers failed"
                                , dobj->name);
                        return rv;
                    }
                }
                if(bodyskipstore) {
                    dobj->skipstore = TRUE;
                }
            }

            /* Should only be open if skipstore active */
            if(!dobj->skipstore) {
                apr_file_close(dobj->bfd_read);
                dobj->bfd_read = NULL;
            }
        }

        if(!dobj->skipstore) {
            rv = open_new_file(r, dobj->tpool, dobj->bodyfile, 
                               &(dobj->bfd_write), 
                               dobj->lastmod, dobj->initial_size,
                               conf->updtimeout);

            /* Preallocate the file to avoid
               fragmentation and ENOSPC surprises */
            if(rv == APR_SUCCESS) {
                rv = preallocate_file(r, dobj->bfd_write, dobj->initial_size);
            }

            if(rv == CACHE_EEXIST) {
                /* Someone else beat us to storing this */

                if (APLOGrtrace4(r)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                  "store_body: skipstore (open_new_file)");
                }
                dobj->skipstore = TRUE;

                /* Just assume that if we can open a file, it's the right one.
                   Someone just opened it for writing, after all */
                rv = apr_file_open(&dobj->bfd_read, dobj->bodyfile, readflags, 
                                   0, fdpool);
                if(rv != APR_SUCCESS) {
                    dobj->bfd_read = NULL; /* Clear it to play it safe */

                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "store_body: skipstore (open_new_file): "
                                  "failed to open bfd_read");
                }

            }
            else if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "store_body: open_new_file failed");

                dobj->errcleanflags |= ERRCLEAN_HEADER;
                file_cache_errorcleanup(dobj, r);

                return rv;
            }
            else { /* APR_SUCCESS */
                apr_finfo_t wfinfo, rfinfo;

                dobj->errcleanflags |= ERRCLEAN_BODY;

                /* Let's cheat a little to make error handling easier */
                wfinfo.valid = 0;
                rfinfo.valid = 0;

                dobj->file_size = 0;

                apr_file_info_get(&wfinfo, APR_FINFO_IDENT, dobj->bfd_write);

                if(wfinfo.valid & APR_FINFO_IDENT) {
                    dobj->bodyinode = wfinfo.inode;
                }

                /* Update the header with bodyinode info, but only if we've
                   got an initial_size
                 */
                if(dobj->initial_size > 0) {
                    rv = store_headers(h, r, &(h->cache_obj->info));
                    if(rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                "URL %s store_body store_headers failed"
                                , dobj->name);

                        file_cache_errorcleanup(dobj, r);
                        return rv;
                    }
                }

                rv = apr_file_open(&dobj->bfd_read, dobj->bodyfile, readflags, 
                                   0, fdpool);

                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                            "Error opening bodyfile %s for URL %s",
                            dobj->bodyfile, dobj->name);

                    file_cache_errorcleanup(dobj, r);
                    return rv;
                }

                apr_file_info_get(&rfinfo, APR_FINFO_IDENT, dobj->bfd_read);
                if(wfinfo.valid & rfinfo.valid & APR_FINFO_IDENT
                        && wfinfo.inode != rfinfo.inode) 
                {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "store_body: "
                                  "bfd_write and bfd_read inode mismatch");
                    file_cache_errorcleanup(dobj, r);

                    return APR_EBADF;
                }
            }

            if(dobj->initial_size > conf->minbgsize &&
                    APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(in)) &&
                    dobj->lastmod != APR_DATE_BAD &&
                    brigade_single_seqfile(r, in, dobj->initial_size) )
            {
                dobj->can_copy_file = TRUE;
            }
        }
        
        if(dobj->skipstore) {

            /* Can only expect to succeed in opening a cached body for files
               with a size ... */
            if( dobj->initial_size > 0) {

                /* If store_headers() sets skipstore, then we might not have
                   bfd_read opened here if it hadn't been created yet by
                   the thread that succeeded in writing the header! */
                if(!dobj->bfd_read || dobj->file_size == 0) {
                    if (APLOGrtrace4(r)) {
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                      "store_body: skipstore: wait for data "
                                      "in body cache file");
                    }

                    rv = open_body_timeout(r, h->cache_obj, dobj);
                    if( rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                "store_body: URL %s:  %s:  failed waiting "
                                "for data in cached body file",
                                dobj->name, dobj->bodyfile);

                        return rv;
                    }
                }

                /* Try to replace the body with the cached instance */
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "Reusing cached body for URL %s, len %"
                              APR_OFF_T_FMT, dobj->name, dobj->initial_size);

                /* in case we've already sent part, e.g. via mod_proxy */
                dobj->bytes_sent = r->bytes_sent;

                rv = recall_body(h, r->pool, out);
                if(rv == APR_SUCCESS) {
                    dobj->body_done = TRUE;
                    if (APLOGrtrace4(r)) {
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                "store_body: body replaced");
                    }
                }
            }

        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Caching body for URL %s, len %"
                          APR_OFF_T_FMT, dobj->name, dobj->initial_size);
        }
    }

    while (!APR_BRIGADE_EMPTY(in))
    {
        const char *str;
        apr_size_t length, written=0;

        e = APR_BRIGADE_FIRST(in);

        /* Junk input if skipping store and already done with body (likely
           due to replacing it with cached copy) */
        if(dobj->skipstore && dobj->body_done) {
            apr_bucket_delete(e);
            continue;
        }

        /* End Of Stream? */
        if (APR_BUCKET_IS_EOS(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            dobj->body_done = TRUE;
            continue;
        }

        /* Do passthrough if no actual processing needed */
        if(dobj->skipstore || dobj->body_done) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        /* honour flush buckets, we'll get called again */
        if (APR_BUCKET_IS_FLUSH(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            if (APLOGrtrace4(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                              "store_body: flush, returning");
            }
            return APR_SUCCESS;
        }

        /* Ignore the non-data-buckets */
        if(APR_BUCKET_IS_METADATA(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        if(dobj->can_copy_file && dobj->initial_size >= conf->minbgsize 
                && APR_BUCKET_IS_FILE(e))
        {
            apr_bucket_file *a = e->data;

            if(!did_bgcopy) {
                apr_file_t *srcfd;

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "Doing background copy of body for URL %s, offset %"
                        APR_OFF_T_FMT " len %" APR_OFF_T_FMT, 
                        dobj->name, dobj->file_size, dobj->initial_size);
 
                /* Need to dup the srcfd, as we don't control where it's
                   closed */
                rv = apr_file_dup(&srcfd, a->fd, dobj->tpool);
                if(rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                            "store_body: URL %s: apr_file_dup failed",
                            dobj->name);
                    break;
                }

                /* FIXME: Can we end up with incomplete files in cache here?
                          - We should really start at 0, not e->start,
                          otherwise we'll be missing the start of the file
                          which will play merry hell later on if someone
                          actually wants it!
                          - However, if some data has already been sent/stored
                            (file_size != 0 and file_size == e->start) then
                            this would be correct.
                 */
                rv = do_bgcopy(srcfd, e->start, dobj->lastmod,
                               dobj->bfd_write, dobj->file_size, 
                               dobj->initial_size-dobj->file_size, 
                               conf->updtimeout, r->connection);
                if(rv == APR_SUCCESS) {
                    did_bgcopy = TRUE;
                    /* do_bgcopy sets aside the fds to its own pool, so
                       we must not touch them afterwards */
                    dobj->bfd_write = NULL;
                }
                else {
                    /* Gracefully fall back to non-bgcopy */
                    dobj->can_copy_file = FALSE;
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                            "store_body: URL %s unable to initialize "
                            "background copy, "
                            "falling back to foreground copy",
                            dobj->name);
                }
            }
            if(did_bgcopy) {
                if((diskcache_brigade_insert(out, dobj->bfd_read, 
                                             e->start, e->length, 
                                             conf->updtimeout, r->pool))
                        == NULL)
                {
                    rv = APR_ENOMEM;
                    break;
                }
                if (APLOGrtrace3(r)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                            "store_body: URL %s added diskcache out bucket "
                            "start %" APR_OFF_T_FMT " "
                            "length %" APR_OFF_T_FMT,
                            dobj->name, e->start, e->length);
                }
                apr_bucket_delete(e);
                continue;
            }
        }

        /* FIXME: This isn't really useful right now, but doesn't hurt as
                  long as minbgsize is set lower than CACHE_FADVISE_WINDOW.
                  Leave it in until we decide on whether to implement the
                  incremental approach now possible with the in/out brigades */
        if(e->length > CACHE_FADVISE_WINDOW) {
            /* Try to split the bucket into our chunk size */
            rv = apr_bucket_split(e, CACHE_FADVISE_WINDOW);
            if(rv != APR_SUCCESS && !APR_STATUS_IS_ENOTIMPL(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "store_body: apr_bucket_split()");
                break;
            }
        }

        if(APR_BUCKET_IS_FILE(e)) {
            apr_bucket_file *a = e->data;
            apr_size_t len = e->length;
            apr_off_t off = e->start;

            if(dobj->tbuf == NULL) {
                /* Use large buffer for non-dynamic content */
                if(dobj->initial_size > 0) {
                    dobj->tbufsize = S_MIN(dobj->initial_size, CACHE_BUF_SIZE);
                }
                else {
                    dobj->tbufsize = APR_BUCKET_BUFF_SIZE;
                }
                dobj->tbuf = apr_palloc(dobj->tpool, dobj->tbufsize);
                if(dobj->tbuf == NULL && rv == APR_SUCCESS) {
                    rv = APR_ENOMEM;
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                                  "store_body: apr_palloc()");
                    break;
                }
            }

            rv = copy_file_region(dobj->tbuf, dobj->tbufsize,
                                  a->fd, off,
                                  dobj->bfd_write, -1,
                                  len, conf->updtimeout);

            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "store_body: copy_file_region()");

                break;
            }

            written = len;
        }
        else { /* Not FILE bucket */
            rv = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "store_body: apr_bucket_read()");
                break;
            }
            /* don't write empty buckets to the cache, we'll get those when
               we encounter morphing buckets */
            if (!length) {
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(out, e);
                continue;
            }

            rv = apr_file_write_full(dobj->bfd_write, str, length, &written);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "store_body: apr_file_write_full()");
                break;
            }
        }
        if(written > 0) {
            if(fbout) {
                /* Just extend the existing file cache bucket */
                /* FIXME: This isn't large-file safe on 32bit platforms */
                fbout->length += written;
                if (APLOGrtrace3(r)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                            "URL %s extended out brigade to len %" 
                            APR_OFF_T_FMT " off %" APR_OFF_T_FMT,
                            dobj->name, fbout->length, fbout->start);
                }
            }
            else {
                fbout = apr_brigade_insert_file(out, dobj->bfd_read, 
                                            dobj->file_size, written, r->pool);
                if (APLOGrtrace3(r)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                                 "URL %s added out brigade len %" APR_OFF_T_FMT
                                 " off %" APR_OFF_T_FMT,
                                 dobj->name, written, dobj->file_size);
                }
            }
            if(!fbout) {
                rv = APR_ENOMEM;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "store_body: !fbout");

                break;
            }

            apr_bucket_delete(e);
            dobj->file_size += written;
        }
        else {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
        }
        /* FIXME: Add handling of max time/bytes to handle in each call
           similar to upstream mod_cache_disk ?
           Also check if this can be used to get rid of the bgcopy stuff.
         */
    }

    if(rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "Error during store_body for URL %s", dobj->name);

        file_cache_errorcleanup(dobj, r);
        return rv;
    }

    if (APLOGrtrace2(r)) {
        debug_rlog_brigade(APLOG_MARK, APLOG_TRACE2, 0, r, out, 
                           "store_body out");
    }

    /* Drop out here if this wasn't the end */
    if (!dobj->body_done) {
        if (APLOGrtrace4(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "store_body: !body_done, returning");
        }
        return APR_SUCCESS;
    }

    /* Finishing touches if we actually wrote the body */
    if(!did_bgcopy && dobj->bfd_write) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "Done caching URL %s, len %" APR_OFF_T_FMT,
                     dobj->name, dobj->file_size);

        if(dobj->initial_size < 0) {
            /* Update header information now that we know the size */
            dobj->initial_size = dobj->file_size;
            rv = store_headers(h, r, &(h->cache_obj->info));
            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "Discarded body for URL %s "
                             "because store_headers failed",
                             dobj->name);

                return rv;
            }
            if (APLOGrtrace1(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                              "store_body: final size: %" APR_OFF_T_FMT,
                              dobj->file_size);
            }
        }
        else if(dobj->initial_size != dobj->file_size) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                         "URL %s - body size mismatch: suggested %"
                         APR_OFF_T_FMT "  file_size %" APR_OFF_T_FMT ")",
                         dobj->name, dobj->initial_size, dobj->file_size);
            dobj->errcleanflags |= ERRCLEAN_HEADER;
            file_cache_errorcleanup(dobj, r);

            return APR_EGENERAL;
        }

        /* Set mtime on body file */
        if(dobj->lastmod != APR_DATE_BAD) {
            rv = apr_file_mtime_set(dobj->bodyfile, dobj->lastmod, dobj->tpool);
            if(rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                        "store_body: set mtime failed on %s", dobj->bodyfile);
            }
        }

        /* All checks were fine, close output file */
        rv = apr_file_close(dobj->bfd_write);
        dobj->bfd_write = NULL;
        if(rv != APR_SUCCESS) {
            file_cache_errorcleanup(dobj, r);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "Discarded body for URL %s "
                         "because close failed",
                         dobj->name);

            return rv;
        }
    }

    dobj->errcleanflags &= ~ERRCLEAN_BODY;

    if (APLOGrtrace1(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "store_body: All done, returning SUCCESS");
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
    int threaded_mpm;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "post_config: %s started.",
                   rcsid);

    if(ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm) == APR_SUCCESS
            && threaded_mpm) 
    {
        return OK;
    }
    
    ap_log_error(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, s,
                 "FATAL ERROR: disk_largefile requires a thread-capable"
                " MPM!");

    return HTTP_NOT_IMPLEMENTED;
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
