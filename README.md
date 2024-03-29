# Introduction

Large-file optimized cache module for Apache httpd, https://httpd.apache.org/

Developed to meet the needs of https://mirror.accum.se/ - the file archive of
Academic Computer Club (ACC), Umeå, Sweden. The archive hosts
all kinds of Open Source software ranging from small archive files to
large DVD images.

ftp.acc.umu.se consists of a backend server delivering a shared file system
via NFS to multiple frontend and offloader servers running httpd and this
cache module to offload the backend. This module tries hard to avoid duplicated
files in the cache (caused by symlinks etc) while also providing good caching
performance by delivering the file from cache while still caching.

To leverage the cache for other protocols a wrapper library called
libhttpcacheopen has been developed that enables for example rsync and vsftp
to leverage the cache as well. It's available at
https://github.com/accumu/libhttpcacheopen

This work eventually became a part of the Master's thesis *Scaling a Content
Delivery system for Open Source Software*, available at
https://urn.kb.se/resolve?urn=urn:nbn:se:umu:diva-109779

# Building

Once upon a time built and used on AIX, Solaris and Linux.

Recently only built and used on Ubuntu Linux 64bit flavours, at the
time of this writing Ubuntu 14.04 LTS and older.

`apxs -c -D GIT_SOURCE_DESC='\"'`git describe --tags --always --dirty`'\"' mod_cache_disk_largefile.c`

# Installation

`apxs -i mod_cache_disk_largefile.la`

For adding a config entry add `-a` or `-A` as appropriate.

# Setup/config

You need:

* A backing store.
  * ACC uses an NFS share, and this gives the possibility to do duplicate
    avoidance by hashing on inode numbers.
  * Others have tried using this in combination with a proxy with moderate
    success.
* A suitable file system to store cached data.
  * 10k/15k RPM Enterprise HDDs or durable SSDs are recommended.
  * ACC uses XFS.
  * If using atime for cache cleanup, mount using lazytime or, if not available,
    strictatime. The Linux default relatime only updates every 24 hours.

# Housekeeping

The cache module assumes that you have arranged for deletion of old data
from the cache. This can be done in a number of ways, we are using an
in-house script called [cleanbyage](https://github.com/accumu/cleanbyage) that
looks at atime to figure out what to clean.
