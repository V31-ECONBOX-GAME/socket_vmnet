#include <os/lock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fdb.h"
#include "log.h"

// About four entries per bucket when the table is full.
#define FDB_BUCKET_BITS 11
#define FDB_BUCKETS (1u << FDB_BUCKET_BITS)
// Entries are referenced by index + 1 so that 0 can end a chain.
#define FDB_NIL 0
#define FDB_PURGE_INTERVAL_NS (1ULL * 1000 * 1000 * 1000)
#define FDB_FULL_WARNING_INTERVAL_NS (60ULL * 1000 * 1000 * 1000)

#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARGS(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

_Static_assert(FDB_CAPACITY < UINT32_MAX, "entry references are uint32_t");

struct fdb_entry {
  uint8_t mac[6];
  // Next entry of the same bucket, or of the free list.
  uint32_t next;
  const void *port;
  uint64_t seen_ns;
};

// Entries past used have never been touched, so their memory is not committed until needed.
struct fdb {
  os_unfair_lock lock;
  const void *host_port;
  uint32_t used;
  uint32_t free_list;
  uint64_t purged_ns;
  uint64_t warned_ns;
  uint32_t buckets[FDB_BUCKETS];
  struct fdb_entry entries[FDB_CAPACITY];
};

// Threads read the clock before taking the lock, so a later timestamp may already be stored.
static uint64_t elapsed(uint64_t now_ns, uint64_t then_ns) {
  return now_ns > then_ns ? now_ns - then_ns : 0;
}

static bool expired(const struct fdb_entry *e, uint64_t now_ns) {
  return elapsed(now_ns, e->seen_ns) > FDB_AGEING_NS;
}

static struct fdb_entry *at(struct fdb *fdb, uint32_t ref) { return &fdb->entries[ref - 1]; }

static uint32_t bucket_of(const uint8_t mac[6]) {
  uint64_t v = 0;
  memcpy(&v, mac, 6);
  return (uint32_t)((v * 0x9E3779B97F4A7C15ULL) >> (64 - FDB_BUCKET_BITS));
}

// Returns the link holding mac's entry, or the FDB_NIL link ending its bucket.
static uint32_t *find(struct fdb *fdb, const uint8_t mac[6]) {
  uint32_t *link = &fdb->buckets[bucket_of(mac)];
  while (*link != FDB_NIL && memcmp(at(fdb, *link)->mac, mac, 6) != 0)
    link = &at(fdb, *link)->next;
  return link;
}

static bool full(const struct fdb *fdb) {
  return fdb->free_list == FDB_NIL && fdb->used == FDB_CAPACITY;
}

static uint32_t alloc_entry(struct fdb *fdb) {
  if (fdb->free_list != FDB_NIL) {
    uint32_t ref = fdb->free_list;
    fdb->free_list = at(fdb, ref)->next;
    return ref;
  }
  return ++fdb->used;
}

static void unlink_entry(struct fdb *fdb, uint32_t *link) {
  uint32_t ref = *link;
  struct fdb_entry *e = at(fdb, ref);
  *link = e->next;
  e->port = NULL;
  e->next = fdb->free_list;
  fdb->free_list = ref;
}

static void purge_expired(struct fdb *fdb, uint64_t now_ns) {
  for (uint32_t b = 0; b < FDB_BUCKETS; b++) {
    uint32_t *link = &fdb->buckets[b];
    while (*link != FDB_NIL) {
      if (expired(at(fdb, *link), now_ns))
        unlink_entry(fdb, link);
      else
        link = &at(fdb, *link)->next;
    }
  }
}

struct fdb *fdb_create(const void *host_port) {
  struct fdb *fdb = calloc(1, sizeof(*fdb));
  if (fdb == NULL)
    return NULL;
  fdb->lock = OS_UNFAIR_LOCK_INIT;
  fdb->host_port = host_port;
  return fdb;
}

void fdb_learn(struct fdb *fdb, const uint8_t mac[6], const void *port, uint64_t now_ns) {
  static const uint8_t zero[6] = {0};
  if (!fdb_is_unicast(mac) || memcmp(mac, zero, sizeof(zero)) == 0)
    return;
  os_unfair_lock_lock(&fdb->lock);
  uint32_t *link = find(fdb, mac);
  if (*link != FDB_NIL) {
    struct fdb_entry *e = at(fdb, *link);
    if (e->port != port) {
      // A VM owns its MAC; the host side cannot claim it while the VM keeps using it.
      if (port == fdb->host_port && !expired(e, now_ns))
        goto out;
      DEBUGF("fdb: " MAC_FMT " moved to another port", MAC_ARGS(mac));
      e->port = port;
      e->seen_ns = now_ns;
    } else if (now_ns > e->seen_ns) {
      e->seen_ns = now_ns;
    }
    goto out;
  }
  if (full(fdb) && elapsed(now_ns, fdb->purged_ns) >= FDB_PURGE_INTERVAL_NS) {
    purge_expired(fdb, now_ns);
    fdb->purged_ns = now_ns;
    link = find(fdb, mac);
  }
  if (full(fdb)) {
    if (fdb->warned_ns == 0 || elapsed(now_ns, fdb->warned_ns) >= FDB_FULL_WARNING_INTERVAL_NS) {
      WARNF("fdb: table full (%u MACs), flooding frames to unlearned MACs", FDB_CAPACITY);
      fdb->warned_ns = now_ns;
    }
    goto out;
  }
  uint32_t ref = alloc_entry(fdb);
  struct fdb_entry *e = at(fdb, ref);
  memcpy(e->mac, mac, sizeof(e->mac));
  e->port = port;
  e->seen_ns = now_ns;
  e->next = FDB_NIL;
  *link = ref;
  DEBUGF("fdb: learned " MAC_FMT, MAC_ARGS(mac));
out:
  os_unfair_lock_unlock(&fdb->lock);
}

const void *fdb_lookup(struct fdb *fdb, const uint8_t mac[6], uint64_t now_ns) {
  if (!fdb_is_unicast(mac))
    return NULL;
  const void *port = NULL;
  os_unfair_lock_lock(&fdb->lock);
  uint32_t *link = find(fdb, mac);
  if (*link != FDB_NIL) {
    if (expired(at(fdb, *link), now_ns))
      unlink_entry(fdb, link);
    else
      port = at(fdb, *link)->port;
  }
  os_unfair_lock_unlock(&fdb->lock);
  return port;
}

void fdb_forget_port(struct fdb *fdb, const void *port) {
  os_unfair_lock_lock(&fdb->lock);
  for (uint32_t b = 0; b < FDB_BUCKETS; b++) {
    uint32_t *link = &fdb->buckets[b];
    while (*link != FDB_NIL) {
      if (at(fdb, *link)->port == port)
        unlink_entry(fdb, link);
      else
        link = &at(fdb, *link)->next;
    }
  }
  os_unfair_lock_unlock(&fdb->lock);
}
