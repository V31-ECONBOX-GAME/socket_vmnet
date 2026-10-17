#ifndef SOCKET_VMNET_FDB_H
#define SOCKET_VMNET_FDB_H

#include <stdbool.h>
#include <stdint.h>

// Forwarding database of a learning switch: the port each unicast MAC was last seen on.
// Ports are opaque pointers chosen by the caller; NULL is never a port.
// All functions are thread-safe.
struct fdb;

// Entries not refreshed for this long are forgotten, as in a Linux bridge.
#define FDB_AGEING_NS (300ULL * 1000 * 1000 * 1000)
// Once full, new MACs are not learned and frames to them are flooded.
#define FDB_CAPACITY (1u << 13)

// host_port is the uplink; a MAC learned from it never replaces a live entry of another port.
struct fdb *fdb_create(const void *host_port);

static inline bool fdb_is_unicast(const uint8_t mac[6]) { return (mac[0] & 1) == 0; }

// Records that a frame from mac arrived on port. Multicast and all-zero MACs are ignored.
void fdb_learn(struct fdb *fdb, const uint8_t mac[6], const void *port, uint64_t now_ns);

// Returns the port mac was learned on, or NULL when unknown.
const void *fdb_lookup(struct fdb *fdb, const uint8_t mac[6], uint64_t now_ns);

// Forgets every MAC learned on port.
void fdb_forget_port(struct fdb *fdb, const void *port);

#endif /* SOCKET_VMNET_FDB_H */
