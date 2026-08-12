#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>

#include <bpf/libbpf.h>

#define MAX_CONNECTIONS 1024
#define CONNECTION_TIMEOUT_SECONDS 30

#define MAX_PROCESSES 1024
#define PROCESS_NAME_LEN 256
#define TCP_LINE_LEN 512

/*
 * ============================================================
 * BPF EVENT
 * ============================================================
 */

struct pg_event {
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 packet_len;
};

/*
 * ============================================================
 * CANONICAL CONNECTION KEY
 *
 * Every PostgreSQL connection is represented as:
 *
 *     client_ip:client_port <-> server_ip:5432
 *
 * Both TCP directions therefore share one logical connection.
 * ============================================================
 */

struct connection_key {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
};

/*
 * ============================================================
 * PROCESS INFORMATION
 * ============================================================
 */

struct process_info {
    __u32 pid;
    char name[PROCESS_NAME_LEN];
};

/*
 * ============================================================
 * CONNECTION ENTRY
 *
 * Phase 2:
 *   - bidirectional packet/byte accounting
 *   - process/socket correlation
 *
 * Phase 3:
 *   - connection behavior metrics
 * ============================================================
 */

struct connection_entry {
    int used;

    struct connection_key key;

    /* Client -> Server */
    __u64 client_packets;
    __u64 client_bytes;

    /* Server -> Client */
    __u64 server_packets;
    __u64 server_bytes;

    /* Connection lifetime */
    struct timespec first_seen;
    struct timespec last_seen;

    /* Phase 3 intelligence */
    __u64 total_events;
    double peak_idle_seconds;
    double average_packet_size;

    /* Client process */
    __u32 owner_pid;
    char owner_name[PROCESS_NAME_LEN];

    /* Server process */
    __u32 server_pid;
    char server_name[PROCESS_NAME_LEN];

    int process_resolved;
};

/*
 * ============================================================
 * PROCESS SUMMARY
 * ============================================================
 */

/*
 * ============================================================
 * PHASE 6 - CONNECTION REUSE INTELLIGENCE
 * ============================================================
 *
 * Tracks repeated connection lifecycles associated with a
 * process so connection churn can be distinguished from
 * sustained/reused connections.
 */

struct process_reuse_profile {
    int used;

    __u32 pid;
    char name[PROCESS_NAME_LEN];

    __u64 connections;
    __u64 short_lived_connections;

    double total_connection_duration;

    double average_connection_duration;

    double reuse_score;
};

struct process_summary {
    int used;

    __u32 pid;
    char name[PROCESS_NAME_LEN];

    __u64 connections;
    __u64 packets;
    __u64 bytes;

    /* Phase 4 connection behavior profile */
    __u64 short_lived_connections;
    __u64 idle_pattern_connections;
    __u64 chatter_connections;
    __u64 heavy_connections;
    __u64 normal_connections;
    double total_connection_duration;

    struct timespec first_seen;
    struct timespec last_seen;
};

/*
 * ============================================================
 * GLOBAL STATE
 * ============================================================
 */

static struct connection_entry connections[MAX_CONNECTIONS];
static struct process_summary processes[MAX_PROCESSES];
static struct process_reuse_profile reuse_profiles[MAX_PROCESSES];


static volatile sig_atomic_t running = 1;

/*
 * ============================================================
 * SIGNAL HANDLING
 * ============================================================
 */

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static double calculate_reuse_score(
    const struct process_reuse_profile *reuse
)
{
    if (!reuse || reuse->connections == 0)
        return 100.0;

    double short_ratio =
        (100.0 *
         (double)reuse->short_lived_connections) /
        (double)reuse->connections;

    if (short_ratio >= 75.0)
        return 0.0;

    if (short_ratio >= 50.0)
        return 25.0;

    if (short_ratio >= 25.0)
        return 50.0;

    if (short_ratio > 0.0)
        return 75.0;

    return 100.0;
}

static struct process_reuse_profile *
find_or_create_reuse_profile(
    __u32 pid,
    const char *name
)
{
    int free_slot = -1;

    for (int i = 0;
         i < MAX_PROCESSES;
         i++)
    {
        if (!reuse_profiles[i].used) {

            if (free_slot == -1)
                free_slot = i;

            continue;
        }

        if (reuse_profiles[i].pid == pid)
            return &reuse_profiles[i];
    }

    if (free_slot == -1)
        return NULL;

    memset(
        &reuse_profiles[free_slot],
        0,
        sizeof(reuse_profiles[free_slot])
    );

    reuse_profiles[free_slot].used = 1;
    reuse_profiles[free_slot].pid = pid;

    snprintf(
        reuse_profiles[free_slot].name,
        sizeof(reuse_profiles[free_slot].name),
        "%s",
        name ? name : "unknown"
    );

    return &reuse_profiles[free_slot];
}


/*
 * ============================================================
 * TIME HELPERS
 * ============================================================
 */

static __u64 time_to_ns(const struct timespec *ts)
{
    return ((__u64)ts->tv_sec * 1000000000ULL) +
           (__u64)ts->tv_nsec;
}

static double duration_seconds(
    const struct timespec *first,
    const struct timespec *last
)
{
    __u64 start = time_to_ns(first);
    __u64 end = time_to_ns(last);

    if (end < start)
        return 0.0;

    return (double)(end - start) / 1000000000.0;
}

static double idle_seconds(
    const struct timespec *last,
    const struct timespec *now
)
{
    __u64 last_ns = time_to_ns(last);
    __u64 now_ns = time_to_ns(now);

    if (now_ns < last_ns)
        return 0.0;

    return (double)(now_ns - last_ns) / 1000000000.0;
}

/*
 * ============================================================
 * PHASE 3 METRICS
 * ============================================================
 */

static double packets_per_second(
    const struct connection_entry *connection
)
{
    if (!connection)
        return 0.0;

    __u64 packets =
        connection->client_packets +
        connection->server_packets;

    double duration =
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    if (duration <= 0.0)
        return (double)packets;

    return (double)packets / duration;
}

static double bytes_per_second(
    const struct connection_entry *connection
)
{
    if (!connection)
        return 0.0;

    __u64 bytes =
        connection->client_bytes +
        connection->server_bytes;

    double duration =
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    if (duration <= 0.0)
        return (double)bytes;

    return (double)bytes / duration;
}

static const char *classify_connection(
    const struct connection_entry *connection
)
{
    if (!connection)
        return "UNKNOWN";

    double duration =
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    __u64 packets =
        connection->client_packets +
        connection->server_packets;

    __u64 bytes =
        connection->client_bytes +
        connection->server_bytes;

    /*
     * SHORT_LIVED:
     * Very short connection with relatively few packets.
     */
    if (duration < 1.0)
        return "SHORT_LIVED";

    /*
     * IDLE_PATTERN:
     * Significant idle gaps occurred between packets.
     *
     * This deliberately does NOT use the final 30-second
     * expiration period, otherwise every expired connection
     * would automatically be classified as idle.
     */
    if (connection->peak_idle_seconds >= 10.0)
        return "IDLE_PATTERN";

    /*
     * CHATTER:
     * High packet count.
     */
    if (packets >= 50)
        return "CHATTER";

    /*
     * HEAVY:
     * At least 1 MiB transferred.
     */
    if (bytes >= 1024ULL * 1024ULL)
        return "HEAVY";

    return "NORMAL";
}

static const char *classification_reason(
    const struct connection_entry *connection
)
{
    if (!connection)
        return "No connection data";

    const char *classification =
        classify_connection(connection);

    if (strcmp(classification, "SHORT_LIVED") == 0)
        return
            "Very short-lived connection with low packet count";

    if (strcmp(classification, "IDLE_PATTERN") == 0)
        return
            "Connection experienced a long idle gap between packets";

    if (strcmp(classification, "CHATTER") == 0)
        return
            "Connection generated a high number of packets";

    if (strcmp(classification, "HEAVY") == 0)
        return
            "Connection transferred at least 1 MiB";

    return
        "No Phase 3 behavioral pattern detected";
}

/*
 * ============================================================
 * PROCESS NAME
 * ============================================================
 */

static int read_process_name(
    __u32 pid,
    char *name,
    size_t name_size
)
{
    char path[PATH_MAX];

    if (!name || name_size == 0)
        return -1;

    snprintf(
        path,
        sizeof(path),
        "/proc/%u/comm",
        pid
    );

    FILE *fp = fopen(path, "r");

    if (!fp)
        return -1;

    if (!fgets(name, name_size, fp)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    name[strcspn(name, "\n")] = '\0';

    return 0;
}

/*
 * ============================================================
 * SOCKET INODE -> PROCESS PID
 * ============================================================
 */

static int find_pid_for_socket_inode(
    unsigned long long target_inode,
    struct process_info *info
)
{
    if (!info)
        return -1;

    memset(info, 0, sizeof(*info));

    DIR *proc_dir = opendir("/proc");

    if (!proc_dir)
        return -1;

    struct dirent *proc_entry;

    while ((proc_entry = readdir(proc_dir)) != NULL) {

        if (!isdigit(
                (unsigned char)proc_entry->d_name[0]))
            continue;

        char *endptr = NULL;

        unsigned long pid_ul =
            strtoul(
                proc_entry->d_name,
                &endptr,
                10
            );

        if (!endptr || *endptr != '\0')
            continue;

        if (pid_ul > UINT32_MAX)
            continue;

        __u32 pid = (__u32)pid_ul;

        char fd_path[PATH_MAX];

        snprintf(
            fd_path,
            sizeof(fd_path),
            "/proc/%u/fd",
            pid
        );

        DIR *fd_dir = opendir(fd_path);

        if (!fd_dir)
            continue;

        struct dirent *fd_entry;
        int found = 0;

        while ((fd_entry = readdir(fd_dir)) != NULL) {

            if (fd_entry->d_name[0] == '.')
                continue;

            char link_path[PATH_MAX];

            snprintf(
                link_path,
                sizeof(link_path),
                "%s/%s",
                fd_path,
                fd_entry->d_name
            );

            char target[PATH_MAX];

            ssize_t len =
                readlink(
                    link_path,
                    target,
                    sizeof(target) - 1
                );

            if (len <= 0)
                continue;

            target[len] = '\0';

            unsigned long long inode = 0;

            if (sscanf(
                    target,
                    "socket:[%llu]",
                    &inode
                ) != 1)
            {
                continue;
            }

            if (inode != target_inode)
                continue;

            info->pid = pid;

            if (read_process_name(
                    pid,
                    info->name,
                    sizeof(info->name)
                ) != 0)
            {
                snprintf(
                    info->name,
                    sizeof(info->name),
                    "unknown"
                );
            }

            found = 1;
            break;
        }

        closedir(fd_dir);

        if (found) {
            closedir(proc_dir);
            return 0;
        }
    }

    closedir(proc_dir);

    return -1;
}

/*
 * ============================================================
 * /proc/net/tcp SOCKET LOOKUP
 * ============================================================
 */

static int find_tcp_socket_inode(
    __u32 local_ip,
    __u16 local_port,
    __u32 remote_ip,
    __u16 remote_port,
    unsigned long long *inode_out
)
{
    if (!inode_out)
        return -1;

    FILE *fp = fopen("/proc/net/tcp", "r");

    if (!fp)
        return -1;

    char line[TCP_LINE_LEN];

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {

        char local_field[64];
        char remote_field[64];

        unsigned int state = 0;
        unsigned int entry_number = 0;

        int matched =
            sscanf(
                line,
                " %u: %63s %63s %x",
                &entry_number,
                local_field,
                remote_field,
                &state
            );

        if (matched != 4)
            continue;

        /*
         * TCP_ESTABLISHED
         */
        if (state != 0x01)
            continue;

        char *local_colon =
            strrchr(local_field, ':');

        char *remote_colon =
            strrchr(remote_field, ':');

        if (!local_colon || !remote_colon)
            continue;

        *local_colon = '\0';
        *remote_colon = '\0';

        unsigned long parsed_local_ip =
            strtoul(local_field, NULL, 16);

        unsigned long parsed_remote_ip =
            strtoul(remote_field, NULL, 16);

        unsigned long parsed_local_port =
            strtoul(
                local_colon + 1,
                NULL,
                16
            );

        unsigned long parsed_remote_port =
            strtoul(
                remote_colon + 1,
                NULL,
                16
            );

        if (parsed_local_ip != local_ip ||
            parsed_remote_ip != remote_ip)
        {
            continue;
        }

        if (parsed_local_port != local_port ||
            parsed_remote_port != remote_port)
        {
            continue;
        }

        /*
         * Tokenize original line again.
         * Token 9 is the socket inode.
         */
        char token_line[TCP_LINE_LEN];

        snprintf(
            token_line,
            sizeof(token_line),
            "%s",
            line
        );

        char *tokens[32];
        int token_count = 0;
        char *saveptr = NULL;

        char *token =
            strtok_r(
                token_line,
                " \t",
                &saveptr
            );

        while (token &&
               token_count < 32)
        {
            tokens[token_count++] = token;

            token =
                strtok_r(
                    NULL,
                    " \t",
                    &saveptr
                );
        }

        if (token_count <= 9)
            continue;

        unsigned long long inode =
            strtoull(
                tokens[9],
                NULL,
                10
            );

        if (inode == 0)
            continue;

        *inode_out = inode;

        fclose(fp);

        return 0;
    }

    fclose(fp);

    return -1;
}

/*
 * ============================================================
 * RESOLVE ONE TCP ENDPOINT
 * ============================================================
 */

static int resolve_endpoint(
    __u32 local_ip,
    __u16 local_port,
    __u32 remote_ip,
    __u16 remote_port,
    struct process_info *info
)
{
    if (!info)
        return -1;

    memset(info, 0, sizeof(*info));

    unsigned long long inode = 0;

    if (find_tcp_socket_inode(
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            &inode
        ) != 0)
    {
        return -1;
    }

    return find_pid_for_socket_inode(
        inode,
        info
    );
}

/*
 * ============================================================
 * CANONICAL CONNECTION KEY
 * ============================================================
 */

static int make_connection_key(
    const struct pg_event *event,
    struct connection_key *key,
    int *client_to_server
)
{
    if (!event ||
        !key ||
        !client_to_server)
        return -1;

    /*
     * Client -> PostgreSQL server
     */
    if (event->dst_port == 5432 &&
        event->src_port != 5432)
    {
        key->client_ip =
            event->src_ip;

        key->client_port =
            event->src_port;

        key->server_ip =
            event->dst_ip;

        key->server_port =
            event->dst_port;

        *client_to_server = 1;

        return 0;
    }

    /*
     * PostgreSQL server -> client
     */
    if (event->src_port == 5432 &&
        event->dst_port != 5432)
    {
        key->client_ip =
            event->dst_ip;

        key->client_port =
            event->dst_port;

        key->server_ip =
            event->src_ip;

        key->server_port =
            event->src_port;

        *client_to_server = 0;

        return 0;
    }

    return -1;
}

/*
 * ============================================================
 * CONNECTION KEY COMPARISON
 * ============================================================
 */

static int connection_key_equal(
    const struct connection_key *a,
    const struct connection_key *b
)
{
    return
        a->client_ip == b->client_ip &&
        a->client_port == b->client_port &&
        a->server_ip == b->server_ip &&
        a->server_port == b->server_port;
}

/*
 * ============================================================
 * RESOLVE PROCESSES
 * ============================================================
 */

static void resolve_connection_processes(
    const struct connection_key *key,
    struct connection_entry *connection
)
{
    if (!key || !connection)
        return;

    struct process_info info;

    memset(&info, 0, sizeof(info));

    /*
     * Client socket
     */
    if (resolve_endpoint(
            key->client_ip,
            key->client_port,
            key->server_ip,
            key->server_port,
            &info
        ) == 0)
    {
        connection->owner_pid =
            info.pid;

        snprintf(
            connection->owner_name,
            sizeof(connection->owner_name),
            "%s",
            info.name
        );

        connection->process_resolved = 1;
    }

    /*
     * Server socket
     */
    memset(&info, 0, sizeof(info));

    if (resolve_endpoint(
            key->server_ip,
            key->server_port,
            key->client_ip,
            key->client_port,
            &info
        ) == 0)
    {
        connection->server_pid =
            info.pid;

        snprintf(
            connection->server_name,
            sizeof(connection->server_name),
            "%s",
            info.name
        );
    }
}

/*
 * ============================================================
 * PRINT CONNECTION KEY
 * ============================================================
 */

static void print_connection_key(
    const struct connection_key *key
)
{
    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &key->client_ip,
        client_ip,
        sizeof(client_ip)
    );

    inet_ntop(
        AF_INET,
        &key->server_ip,
        server_ip,
        sizeof(server_ip)
    );

    printf(
        "%s:%u <-> %s:%u",
        client_ip,
        key->client_port,
        server_ip,
        key->server_port
    );
}

/*
 * ============================================================
 * PROCESS SUMMARY
 * ============================================================
 */

static struct process_summary *
find_or_create_process(
    __u32 pid,
    const char *name,
    const struct timespec *now
)
{
    int free_slot = -1;

    for (int i = 0;
         i < MAX_PROCESSES;
         i++)
    {
        if (!processes[i].used) {

            if (free_slot == -1)
                free_slot = i;

            continue;
        }

        if (processes[i].pid == pid)
            return &processes[i];
    }

    if (free_slot == -1)
        return NULL;

    memset(
        &processes[free_slot],
        0,
        sizeof(processes[free_slot])
    );

    processes[free_slot].used = 1;
    processes[free_slot].pid = pid;

    snprintf(
        processes[free_slot].name,
        sizeof(processes[free_slot].name),
        "%s",
        name ? name : "unknown"
    );

    processes[free_slot].first_seen =
        *now;

    processes[free_slot].last_seen =
        *now;

    return &processes[free_slot];
}

static void update_process_summary(
    const struct connection_entry *connection
)
{
    if (!connection)
        return;

    if (!connection->process_resolved)
        return;

    struct timespec now;

    if (clock_gettime(
            CLOCK_MONOTONIC,
            &now
        ) != 0)
    {
        return;
    }

    struct process_summary *summary =
        find_or_create_process(
            connection->owner_pid,
            connection->owner_name,
            &now
        );

    if (!summary)
        return;

    summary->connections++;

    summary->packets +=
        connection->client_packets +
        connection->server_packets;

    summary->bytes +=
        connection->client_bytes +
        connection->server_bytes;

    /*
     * Phase 4:
     * Aggregate the behavioral classification of each completed
     * PostgreSQL connection at the owning-process level.
     */
    const char *classification =
        classify_connection(connection);

    if (strcmp(classification, "SHORT_LIVED") == 0) {
        summary->short_lived_connections++;
    } else if (strcmp(classification, "IDLE_PATTERN") == 0) {
        summary->idle_pattern_connections++;
    } else if (strcmp(classification, "CHATTER") == 0) {
        summary->chatter_connections++;
    } else if (strcmp(classification, "HEAVY") == 0) {
        summary->heavy_connections++;
    } else {
        summary->normal_connections++;
    }

    summary->total_connection_duration +=
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    /*
     * ========================================================
     * PHASE 6 CONNECTION REUSE INTELLIGENCE
     * ========================================================
     */

    struct process_reuse_profile *reuse =
        find_or_create_reuse_profile(
            connection->owner_pid,
            connection->owner_name
        );

    if (reuse) {

        reuse->connections++;

        if (strcmp(classification, "SHORT_LIVED") == 0)
            reuse->short_lived_connections++;

        reuse->total_connection_duration +=
            duration_seconds(
                &connection->first_seen,
                &connection->last_seen
            );

        reuse->average_connection_duration =
            reuse->total_connection_duration /
            (double)reuse->connections;

        reuse->reuse_score =
            calculate_reuse_score(reuse);
    }

    summary->last_seen = now;
}

/*
 * ============================================================
 * EXPIRE CONNECTION
 * ============================================================
 */

static void expire_connection(
    struct connection_entry *connection
)
{
    if (!connection ||
        !connection->used)
        return;

    double duration =
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    __u64 total_packets =
        connection->client_packets +
        connection->server_packets;

    __u64 total_bytes =
        connection->client_bytes +
        connection->server_bytes;

    /*
     * Calculate final average packet size.
     */
    connection->average_packet_size =
        total_packets > 0
            ? (double)total_bytes /
              (double)total_packets
            : 0.0;

    double packet_rate =
        packets_per_second(connection);

    double byte_rate =
        bytes_per_second(connection);

    const char *classification =
        classify_connection(connection);

    const char *reason =
        classification_reason(connection);

    printf(
        "PG-SQUEEZE CONNECTION EXPIRED: "
    );

    print_connection_key(
        &connection->key
    );

    printf(
        " duration=%.3fs\n",
        duration
    );

    printf(
        "  CLIENT -> SERVER: "
        "packets=%llu bytes=%llu\n",
        (unsigned long long)
            connection->client_packets,
        (unsigned long long)
            connection->client_bytes
    );

    printf(
        "  SERVER -> CLIENT: "
        "packets=%llu bytes=%llu\n",
        (unsigned long long)
            connection->server_packets,
        (unsigned long long)
            connection->server_bytes
    );

    printf(
        "  TOTAL: packets=%llu bytes=%llu",
        (unsigned long long)
            total_packets,
        (unsigned long long)
            total_bytes
    );

    if (connection->process_resolved) {

        printf(
            " process=%s pid=%u",
            connection->owner_name,
            connection->owner_pid
        );

    } else {

        printf(
            " process=unresolved"
        );
    }

    if (connection->server_pid != 0) {

        printf(
            " server=%s pid=%u",
            connection->server_name,
            connection->server_pid
        );
    }

    printf("\n");

    /*
     * ========================================================
     * PHASE 3 INTELLIGENCE
     * ========================================================
     */

    printf(
        "\n"
        "  PHASE 3 INTELLIGENCE:\n"
        "  Classification: %s\n"
        "  Reason:         %s\n"
        "  Packet rate:    %.2f packets/sec\n"
        "  Byte rate:      %.2f bytes/sec\n"
        "  Avg packet:     %.2f bytes\n"
        "  Peak idle:      %.3f sec\n"
        "  Events:         %llu\n",
        classification,
        reason,
        packet_rate,
        byte_rate,
        connection->average_packet_size,
        connection->peak_idle_seconds,
        (unsigned long long)
            connection->total_events
    );

    update_process_summary(
        connection
    );

    fflush(stdout);

    memset(
        connection,
        0,
        sizeof(*connection)
    );
}

/*
 * ============================================================
 * EXPIRE IDLE CONNECTIONS
 * ============================================================
 */

static void expire_idle_connections(
    const struct timespec *now
)
{
    for (int i = 0;
         i < MAX_CONNECTIONS;
         i++)
    {
        if (!connections[i].used)
            continue;

        double idle =
            idle_seconds(
                &connections[i].last_seen,
                now
            );

        if (idle >=
            CONNECTION_TIMEOUT_SECONDS)
        {
            expire_connection(
                &connections[i]
            );
        }
    }
}

/*
 * ============================================================
 * FIND OR CREATE CONNECTION
 * ============================================================
 */

static struct connection_entry *
find_or_create_connection(
    const struct connection_key *key,
    const struct timespec *now
)
{
    int free_slot = -1;

    for (int i = 0;
         i < MAX_CONNECTIONS;
         i++)
    {
        if (!connections[i].used) {

            if (free_slot == -1)
                free_slot = i;

            continue;
        }

        if (connection_key_equal(
                &connections[i].key,
                key
            ))
        {
            return &connections[i];
        }
    }

    if (free_slot == -1)
        return NULL;

    memset(
        &connections[free_slot],
        0,
        sizeof(connections[free_slot])
    );

    connections[free_slot].used = 1;

    connections[free_slot].key =
        *key;

    connections[free_slot].first_seen =
        *now;

    connections[free_slot].last_seen =
        *now;

    /*
     * First process correlation attempt.
     */
    resolve_connection_processes(
        key,
        &connections[free_slot]
    );

    return &connections[free_slot];
}

/*
 * ============================================================
 * RING BUFFER EVENT HANDLER
 * ============================================================
 */

static int handle_event(
    void *ctx,
    void *data,
    size_t data_sz
)
{
    (void)ctx;

    struct pg_event *event = data;

    if (data_sz < sizeof(*event)) {

        fprintf(
            stderr,
            "Invalid event size: %zu\n",
            data_sz
        );

        return 0;
    }

    struct timespec now;

    if (clock_gettime(
            CLOCK_MONOTONIC,
            &now
        ) != 0)
    {
        perror("clock_gettime");
        return 0;
    }

    /*
     * Expire stale connections before
     * processing the new packet.
     */
    expire_idle_connections(&now);

    struct connection_key key;

    int client_to_server = 0;

    if (make_connection_key(
            event,
            &key,
            &client_to_server
        ) != 0)
    {
        return 0;
    }

    struct connection_entry *connection =
        find_or_create_connection(
            &key,
            &now
        );

    if (!connection) {

        fprintf(
            stderr,
            "Connection table is full\n"
        );

        return 0;
    }

    /*
     * Retry process correlation if it
     * wasn't available initially.
     */
    if (!connection->process_resolved) {

        resolve_connection_processes(
            &key,
            connection
        );
    }

    /*
     * Phase 3:
     * Measure the idle gap between packets.
     *
     * We intentionally exclude the final
     * 30-second timeout gap.
     */
    if (connection->total_events > 0) {

        double current_idle =
            idle_seconds(
                &connection->last_seen,
                &now
            );

        if (current_idle >
            connection->peak_idle_seconds)
        {
            connection->peak_idle_seconds =
                current_idle;
        }
    }

    connection->total_events++;

    /*
     * Direction accounting.
     */
    if (client_to_server) {

        connection->client_packets++;

        connection->client_bytes +=
            event->packet_len;

    } else {

        connection->server_packets++;

        connection->server_bytes +=
            event->packet_len;
    }

    connection->last_seen =
        now;

    __u64 total_packets =
        connection->client_packets +
        connection->server_packets;

    __u64 total_bytes =
        connection->client_bytes +
        connection->server_bytes;

    connection->average_packet_size =
        total_packets > 0
            ? (double)total_bytes /
              (double)total_packets
            : 0.0;

    double duration =
        duration_seconds(
            &connection->first_seen,
            &connection->last_seen
        );

    /*
     * ========================================================
     * LIVE EVENT
     * ========================================================
     */

    printf(
        "PG-SQUEEZE CONNECTION EVENT: "
    );

    print_connection_key(
        &key
    );

    printf(
        " direction=%s",
        client_to_server
            ? "CLIENT->SERVER"
            : "SERVER->CLIENT"
    );

    printf(
        " packets=%llu bytes=%llu "
        "duration=%.3fs",
        (unsigned long long)
            total_packets,
        (unsigned long long)
            total_bytes,
        duration
    );

    if (connection->process_resolved) {

        printf(
            " process=%s pid=%u",
            connection->owner_name,
            connection->owner_pid
        );

    } else {

        printf(
            " process=unresolved"
        );
    }

    if (connection->server_pid != 0) {

        printf(
            " server=%s pid=%u",
            connection->server_name,
            connection->server_pid
        );
    }

    printf("\n");

    fflush(stdout);

    return 0;
}

/*
 * ============================================================
 * PHASE 5 - OPTIMIZATION / RECOMMENDATION ENGINE
 * ============================================================
 *
 * Phase 5 converts observed connection behavior into
 * conservative optimization guidance.  It does not claim a
 * root cause; it reports an observed pattern and a suggested
 * area to investigate.
 */

static int phase5_score_process(
    const struct process_summary *summary
)
{
    if (!summary || summary->connections == 0)
        return 100;

    double short_ratio =
        (100.0 * (double)summary->short_lived_connections) /
        (double)summary->connections;

    double idle_ratio =
        (100.0 * (double)summary->idle_pattern_connections) /
        (double)summary->connections;

    double chatter_ratio =
        (100.0 * (double)summary->chatter_connections) /
        (double)summary->connections;

    double heavy_ratio =
        (100.0 * (double)summary->heavy_connections) /
        (double)summary->connections;

    int penalty = 0;

    /*
     * A single short-lived connection is not enough evidence of
     * connection churn. Require a small sample before penalizing.
     */
    if (summary->connections >= 5) {
        if (short_ratio >= 75.0)
            penalty += 40;
        else if (short_ratio >= 50.0)
            penalty += 30;
        else if (short_ratio >= 25.0)
            penalty += 15;
    }

    if (summary->connections >= 3) {
        if (idle_ratio >= 75.0)
            penalty += 20;
        else if (idle_ratio >= 50.0)
            penalty += 12;
    }

    if (chatter_ratio >= 50.0)
        penalty += 12;
    else if (chatter_ratio > 0.0)
        penalty += 6;

    if (heavy_ratio >= 50.0)
        penalty += 10;
    else if (heavy_ratio > 0.0)
        penalty += 5;

    if (penalty > 100)
        penalty = 100;

    return 100 - penalty;
}

static const char *phase5_health_label(int score)
{
    if (score >= 85)
        return "GOOD";

    if (score >= 70)
        return "REVIEW";

    if (score >= 50)
        return "ATTENTION";

    return "HIGH RISK";
}

static void print_phase5_aggregate(void);
static void print_phase7_hotspot(void);

static void print_phase5_recommendations(
    const struct process_summary *summary
)
{
    if (!summary || summary->connections == 0)
        return;

    double short_ratio =
        (100.0 * (double)summary->short_lived_connections) /
        (double)summary->connections;

    double idle_ratio =
        (100.0 * (double)summary->idle_pattern_connections) /
        (double)summary->connections;

    double chatter_ratio =
        (100.0 * (double)summary->chatter_connections) /
        (double)summary->connections;

    double heavy_ratio =
        (100.0 * (double)summary->heavy_connections) /
        (double)summary->connections;

    int findings = 0;

    printf("\n");
    printf("PHASE 5 OPTIMIZATION RECOMMENDATIONS:\n");

    /* Connection churn */
    if (summary->connections >= 5 && short_ratio >= 50.0) {
        printf(
            "  Finding:      CONNECTION CHURN (%0.1f%% short-lived)\n",
            short_ratio
        );
        printf(
            "  Recommendation: Investigate PostgreSQL connection pooling "
            "and connection reuse.\n"
        );
        findings++;
    } else if (summary->connections >= 5 && short_ratio >= 25.0) {
        printf(
            "  Finding:      POSSIBLE CONNECTION CHURN (%0.1f%% short-lived)\n",
            short_ratio
        );
        printf(
            "  Recommendation: Review connection lifecycle and consider "
            "pooling/reuse.\n"
        );
        findings++;
    }

    /* Idle behavior */
    if (summary->connections >= 3 && idle_ratio >= 50.0) {
        printf(
            "  Finding:      IDLE CONNECTION PATTERN (%0.1f%% affected)\n",
            idle_ratio
        );
        printf(
            "  Recommendation: Review pool idle timeout and connection "
            "lifecycle settings.\n"
        );
        findings++;
    }

    /* Packet chatter */
    if (chatter_ratio >= 50.0) {
        printf(
            "  Finding:      NETWORK CHATTER (%0.1f%% affected)\n",
            chatter_ratio
        );
        printf(
            "  Recommendation: Investigate frequent small request/response "
            "exchanges and batching opportunities.\n"
        );
        findings++;
    } else if (chatter_ratio > 0.0) {
        printf(
            "  Finding:      SOME NETWORK CHATTER (%0.1f%% affected)\n",
            chatter_ratio
        );
        printf(
            "  Recommendation: Review high-frequency database interactions "
            "for batching opportunities.\n"
        );
        findings++;
    }

    /* Large transfers */
    if (heavy_ratio >= 50.0) {
        printf(
            "  Finding:      HEAVY DATA TRANSFER (%0.1f%% affected)\n",
            heavy_ratio
        );
        printf(
            "  Recommendation: Investigate large result sets, payload size, "
            "and query/result pagination.\n"
        );
        findings++;
    } else if (heavy_ratio > 0.0) {
        printf(
            "  Finding:      LARGE DATA TRANSFER OBSERVED (%0.1f%% affected)\n",
            heavy_ratio
        );
        printf(
            "  Recommendation: Review large query results and unnecessary "
            "data transfer.\n"
        );
        findings++;
    }

    if (findings == 0) {
        printf(
            "  Finding:      NO CLEAR OPTIMIZATION ISSUE DETECTED\n"
        );
        printf(
            "  Recommendation: Continue monitoring connection behavior.\n"
        );
    }

    int score = phase5_score_process(summary);

    printf(
        "  Health score: %d/100 (%s)\n",
        score,
        phase5_health_label(score)
    );
}

/*
 * ============================================================
 * PRINT PROCESS SUMMARY
 * ============================================================
 */

static void print_process_summary(void)
{
    printf("\n");

    printf(
        "============================================================\n"
    );

    printf(
        "              PG-SQUEEZE PROCESS SUMMARY\n"
    );

    printf(
        "============================================================\n"
    );

    int found = 0;

    for (int i = 0;
         i < MAX_PROCESSES;
         i++)
    {
        if (!processes[i].used)
            continue;

        found = 1;

        printf(
            "PROCESS: %s\n",
            processes[i].name
        );

        printf(
            "PID:     %u\n",
            processes[i].pid
        );

        printf(
            "Connections: %llu\n",
            (unsigned long long)
                processes[i].connections
        );

        printf(
            "Packets:     %llu\n",
            (unsigned long long)
                processes[i].packets
        );

        printf(
            "Bytes:       %llu\n",
            (unsigned long long)
                processes[i].bytes
        );

        double average_connection_duration =
            processes[i].connections > 0
                ? processes[i].total_connection_duration /
                  (double)processes[i].connections
                : 0.0;

        double short_lived_ratio =
            processes[i].connections > 0
                ? (100.0 *
                   (double)processes[i].short_lived_connections) /
                  (double)processes[i].connections
                : 0.0;

        printf("\n");
        printf("PHASE 4 CONNECTION INTELLIGENCE:\n");
        printf(
            "  Short-lived:       %llu\n",
            (unsigned long long)
                processes[i].short_lived_connections
        );
        printf(
            "  Idle-pattern:      %llu\n",
            (unsigned long long)
                processes[i].idle_pattern_connections
        );
        printf(
            "  Chatter:           %llu\n",
            (unsigned long long)
                processes[i].chatter_connections
        );
        printf(
            "  Heavy:             %llu\n",
            (unsigned long long)
                processes[i].heavy_connections
        );
        printf(
            "  Normal:            %llu\n",
            (unsigned long long)
                processes[i].normal_connections
        );
        printf(
            "  Avg lifetime:      %.3f sec\n",
            average_connection_duration
        );
        printf(
            "  Short-lived ratio: %.2f%%\n",
            short_lived_ratio
        );

        print_phase5_recommendations(
            &processes[i]
        );

        struct process_reuse_profile *reuse =
            find_or_create_reuse_profile(
                processes[i].pid,
                processes[i].name
            );

        if (reuse && reuse->connections > 0) {

            double short_ratio =
                (100.0 *
                 (double)reuse->short_lived_connections) /
                (double)reuse->connections;

            printf("\n");
            printf("PHASE 6 CONNECTION REUSE INTELLIGENCE:\n");
            printf(
                "  Connections observed: %llu\n",
                (unsigned long long)reuse->connections
            );
            printf(
                "  Short-lived:         %llu\n",
                (unsigned long long)reuse->short_lived_connections
            );
            printf(
                "  Short-lived ratio:   %.2f%%\n",
                short_ratio
            );
            printf(
                "  Avg lifetime:        %.3f sec\n",
                reuse->average_connection_duration
            );
        printf(
            "  Reuse score:        %.2f/100\n",
            reuse->reuse_score
        );
        }

        printf(
            "------------------------------------------------------------\n"
        );
    }

    if (!found) {

        printf(
            "No resolved process traffic recorded.\n"
        );
    }

    print_phase5_aggregate();
    print_phase7_hotspot();

    printf(
        "============================================================\n"
    );
}


/*
 * ============================================================
 * PHASE 5 AGGREGATE OPTIMIZATION
 * ============================================================
 *
 * Aggregate resolved process statistics so repeated
 * short-lived connections across different PIDs are visible.
 */

static void print_phase5_aggregate(void)
{
    __u64 total_connections = 0;
    __u64 total_short_lived = 0;
    __u64 total_idle_pattern = 0;
    __u64 total_chatter = 0;
    __u64 total_heavy = 0;

    for (int i = 0; i < MAX_PROCESSES; i++) {

        if (!processes[i].used)
            continue;

        total_connections += processes[i].connections;
        total_short_lived += processes[i].short_lived_connections;
        total_idle_pattern += processes[i].idle_pattern_connections;
        total_chatter += processes[i].chatter_connections;
        total_heavy += processes[i].heavy_connections;
    }

    if (total_connections == 0)
        return;

    double short_ratio =
        100.0 * (double)total_short_lived /
        (double)total_connections;

    double idle_ratio =
        100.0 * (double)total_idle_pattern /
        (double)total_connections;

    double chatter_ratio =
        100.0 * (double)total_chatter /
        (double)total_connections;

    double heavy_ratio =
        100.0 * (double)total_heavy /
        (double)total_connections;

    int penalty = 0;
    int findings = 0;

    printf("\n");
    printf("============================================================\n");
    printf("          PHASE 5 AGGREGATE OPTIMIZATION\n");
    printf("============================================================\n");

    printf(
        "  Total connections: %llu\n",
        (unsigned long long)total_connections
    );

    printf(
        "  Short-lived:       %llu\n",
        (unsigned long long)total_short_lived
    );

    printf(
        "  Idle-pattern:      %llu\n",
        (unsigned long long)total_idle_pattern
    );

    printf(
        "  Chatter:           %llu\n",
        (unsigned long long)total_chatter
    );

    printf(
        "  Heavy:             %llu\n",
        (unsigned long long)total_heavy
    );

    printf(
        "  Short-lived ratio: %.2f%%\n",
        short_ratio
    );

    /*
     * Aggregate connection churn.
     */
    if (total_connections >= 5) {

        if (short_ratio >= 75.0) {

            penalty += 40;

            printf(
                "  Finding:           CONNECTION CHURN (%.1f%% short-lived)\n",
                short_ratio
            );

            printf(
                "  Recommendation:    Investigate PostgreSQL connection "
                "pooling and connection reuse.\n"
            );

            findings++;

        } else if (short_ratio >= 50.0) {

            penalty += 30;

            printf(
                "  Finding:           CONNECTION CHURN (%.1f%% short-lived)\n",
                short_ratio
            );

            printf(
                "  Recommendation:    Investigate connection pooling "
                "and connection reuse.\n"
            );

            findings++;

        } else if (short_ratio >= 25.0) {

            penalty += 15;

            printf(
                "  Finding:           POSSIBLE CONNECTION CHURN "
                "(%.1f%% short-lived)\n",
                short_ratio
            );

            printf(
                "  Recommendation:    Review connection lifecycle "
                "and consider pooling/reuse.\n"
            );

            findings++;
        }
    }

    /*
     * Aggregate idle behavior.
     */
    if (total_connections >= 3 && idle_ratio >= 50.0) {

        if (idle_ratio >= 75.0)
            penalty += 20;
        else
            penalty += 12;

        printf(
            "  Finding:           IDLE CONNECTION PATTERN "
            "(%.1f%% affected)\n",
            idle_ratio
        );

        printf(
            "  Recommendation:    Review pool idle timeout "
            "and connection lifecycle settings.\n"
        );

        findings++;
    }

    /*
     * Aggregate packet chatter.
     */
    if (chatter_ratio >= 50.0) {

        penalty += 12;

        printf(
            "  Finding:           NETWORK CHATTER "
            "(%.1f%% affected)\n",
            chatter_ratio
        );

        printf(
            "  Recommendation:    Investigate frequent small "
            "request/response exchanges and batching opportunities.\n"
        );

        findings++;
    }

    /*
     * Aggregate heavy transfers.
     */
    if (heavy_ratio >= 50.0) {

        penalty += 10;

        printf(
            "  Finding:           HEAVY DATA TRANSFER "
            "(%.1f%% affected)\n",
            heavy_ratio
        );

        printf(
            "  Recommendation:    Investigate large result sets, "
            "payload size, and query/result pagination.\n"
        );

        findings++;
    }

    if (penalty > 100)
        penalty = 100;

    int score = 100 - penalty;

    if (findings == 0) {

        printf(
            "  Finding:           NO CLEAR AGGREGATE ISSUE DETECTED\n"
        );

        printf(
            "  Recommendation:    Continue monitoring aggregate "
            "connection behavior.\n"
        );
    }

    printf(
        "  Aggregate health:  %d/100 (%s)\n",
        score,
        phase5_health_label(score)
    );

}

/*
 * ============================================================
 * PHASE 7 CONNECTION HOTSPOT INTELLIGENCE
 * ============================================================
 *
 * Identify the process contributing the most short-lived
 * PostgreSQL connections to the observed workload.
 * ============================================================
 */

static void print_phase7_hotspot(void)
{
    __u64 total_short_lived = 0;
    struct process_summary *top = NULL;

    for (int i = 0; i < MAX_PROCESSES; i++) {

        if (!processes[i].used)
            continue;

        total_short_lived +=
            processes[i].short_lived_connections;

        if (!top ||
            processes[i].short_lived_connections >
                top->short_lived_connections)
        {
            top = &processes[i];
        }
    }

    if (!top || total_short_lived == 0)
        return;

    double hotspot_contribution =
        (100.0 *
         (double)top->short_lived_connections) /
        (double)total_short_lived;

    double short_ratio =
        top->connections > 0
            ? (100.0 *
               (double)top->short_lived_connections) /
              (double)top->connections
            : 0.0;

    double average_lifetime =
        top->connections > 0
            ? top->total_connection_duration /
              (double)top->connections
            : 0.0;

    struct process_reuse_profile *reuse =
        find_or_create_reuse_profile(
            top->pid,
            top->name
        );

    double reuse_score =
        reuse
            ? reuse->reuse_score
            : 0.0;

    const char *risk;

    if (hotspot_contribution >= 75.0 &&
        short_ratio >= 75.0)
    {
        risk = "HIGH";
    } else if (hotspot_contribution >= 50.0 ||
               short_ratio >= 50.0)
    {
        risk = "MEDIUM";
    } else {
        risk = "LOW";
    }

    printf("\n");
    printf("============================================================\n");
    printf("          PHASE 7 CONNECTION HOTSPOT INTELLIGENCE\n");
    printf("============================================================\n");

    printf(
        "  Top contributor:    %s\n",
        top->name
    );

    printf(
        "  PID:                %u\n",
        top->pid
    );

    printf(
        "  Connections:        %llu\n",
        (unsigned long long)top->connections
    );

    printf(
        "  Short-lived:        %llu\n",
        (unsigned long long)
            top->short_lived_connections
    );

    printf(
        "  Short-lived ratio:  %.2f%%\n",
        short_ratio
    );

    printf(
        "  Avg lifetime:       %.3f sec\n",
        average_lifetime
    );

    printf(
        "  Reuse score:        %.2f/100\n",
        reuse_score
    );

    printf(
        "  Churn contribution:  %.2f%%\n",
        hotspot_contribution
    );

    printf(
        "  Risk:               %s\n",
        risk
    );

    printf(
        "  Recommendation:     Prioritize connection pooling/"
        "reuse investigation for this process.\n"
    );

    printf("============================================================\n");
}


/*
 * ============================================================
 * MAIN
 * ============================================================
 */

int main(void)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    struct ring_buffer *rb;

    int err;

    signal(
        SIGINT,
        handle_signal
    );

    signal(
        SIGTERM,
        handle_signal
    );

    memset(
        connections,
        0,
        sizeof(connections)
    );

    memset(
        processes,
        0,
        sizeof(processes)
    );

    /*
     * ========================================================
     * OPEN BPF OBJECT
     * ========================================================
     */

    obj =
        bpf_object__open_file(
            "net.bpf.o",
            NULL
        );

    if (!obj) {

        fprintf(
            stderr,
            "Failed to open net.bpf.o\n"
        );

        return 1;
    }

    /*
     * ========================================================
     * LOAD BPF OBJECT
     * ========================================================
     */

    err =
        bpf_object__load(obj);

    if (err) {

        fprintf(
            stderr,
            "Failed to load net.bpf.o: %d\n",
            err
        );

        bpf_object__close(obj);

        return 1;
    }

    /*
     * ========================================================
     * FIND RING BUFFER MAP
     * ========================================================
     */

    map =
        bpf_object__find_map_by_name(
            obj,
            "events"
        );

    if (!map) {

        fprintf(
            stderr,
            "Failed to find events map\n"
        );

        bpf_object__close(obj);

        return 1;
    }

    /*
     * ========================================================
     * CREATE RING BUFFER
     * ========================================================
     */

    rb =
        ring_buffer__new(
            bpf_map__fd(map),
            handle_event,
            NULL,
            NULL
        );

    if (!rb) {

        fprintf(
            stderr,
            "Failed to create ring buffer\n"
        );

        bpf_object__close(obj);

        return 1;
    }

    /*
     * ========================================================
     * START
     * ========================================================
     */

    printf(
        "PG-SQUEEZE connection collector started.\n"
    );

    printf(
        "Connection timeout: %d seconds.\n",
        CONNECTION_TIMEOUT_SECONDS
    );

    printf(
        "Process/socket correlation: enabled.\n"
    );

    printf(
        "Bidirectional connection aggregation: enabled.\n"
    );

    printf(
        "Phase 3 connection intelligence: enabled.\n"
    );

    printf(
        "Phase 4 process-level connection intelligence: enabled.\n"
    );

    printf(
        "Tracking PostgreSQL network connections...\n"
    );

    fflush(stdout);

    /*
     * ========================================================
     * MAIN LOOP
     * ========================================================
     */

    while (running) {

        err =
            ring_buffer__poll(
                rb,
                1000
            );

        if (err < 0) {

            if (err == -EINTR)
                continue;

            fprintf(
                stderr,
                "Ring buffer polling failed: %d\n",
                err
            );

            break;
        }

        struct timespec now;

        if (clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) == 0)
        {
            expire_idle_connections(
                &now
            );
        }
    }

    /*
     * ========================================================
     * EXPIRE REMAINING CONNECTIONS
     * ========================================================
     */

    for (int i = 0;
         i < MAX_CONNECTIONS;
         i++)
    {
        if (connections[i].used)
            expire_connection(
                &connections[i]
            );
    }

    /*
     * ========================================================
     * PROCESS SUMMARY
     * ========================================================
     */

    print_process_summary();

    /*
     * ========================================================
     * CLEANUP
     * ========================================================
     */

    ring_buffer__free(rb);

    bpf_object__close(obj);

    printf(
        "PG-SQUEEZE connection collector stopped.\n"
    );

    return 0;
}
