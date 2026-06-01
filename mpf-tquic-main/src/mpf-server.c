
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <ev.h>
#include <tquic.h>

#define MAX_DGRAM         2048
#define MAX_STREAM_CHUNK  65536
#define MIN_PACKET_SIZE   28 // IPv4 (20) + UDP (8)

struct server_state {
    struct quic_endpoint_t *ep;
    int sock;
    struct sockaddr_storage local;
    socklen_t local_len;

    int tun_fd;
    uint64_t stream_id;
    struct quic_conn_t *conn;

    struct ev_loop *loop;
    ev_io sock_w;
    ev_io tun_w;
    ev_timer timer_w;
    bool stream_writable; // Track back-pressure state
    uint8_t leftover_buf[MAX_STREAM_CHUNK]; // Buffer for incomplete packets
    size_t leftover_len; // Length of leftover data
};

// Forward declaration
static void drain_tun(struct server_state *st);

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int open_udp_server(const char *ip, uint16_t port, struct sockaddr_storage *out, socklen_t *out_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) { close(fd); return -1; }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    set_nonblock(fd);
    memset(out, 0, sizeof(*out)); memcpy(out, &addr, sizeof(addr)); *out_len = sizeof(addr);
    return fd;
}

static int open_tun(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    set_nonblock(fd);
    return fd;
}

static int on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts, unsigned int count) {
    struct server_state *st = psctx; unsigned int sent = 0;
    for (unsigned int i = 0; i < count; i++) {
        struct msghdr msg; memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void*)pkts[i].dst_addr; msg.msg_namelen = pkts[i].dst_addr_len;
        msg.msg_iov = (struct iovec*)pkts[i].iov; msg.msg_iovlen = pkts[i].iovlen;
        ssize_t n = sendmsg(st->sock, &msg, 0);
        if (n >= 0) sent++; else break;
    }
    return (int)sent;
}
static const struct quic_packet_send_methods_t send_methods = { .on_packets_send = on_packets_send };

static void on_conn_created(void *tctx, struct quic_conn_t *conn) {
    struct server_state *st = tctx; st->conn = conn;
    st->stream_writable = true;
    st->leftover_len = 0;
    fprintf(stderr, "Server: Connection created, conn=%p\n", (void*)conn);
}
static void on_conn_established(void *tctx, struct quic_conn_t *conn) {
    (void)tctx; (void)conn;
    fprintf(stderr, "Server: Connection established\n");
}
static void on_conn_closed(void *tctx, struct quic_conn_t *conn) {
    (void)conn; struct server_state *st = tctx;
    fprintf(stderr, "Server: Connection closed\n"); ev_break(st->loop, EVBREAK_ALL);
}
static void on_stream_created(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) {
    struct server_state *st = tctx;
    st->stream_id = stream_id;
    fprintf(stderr, "Server: Stream created %lu (valid: %d)\n", (unsigned long)stream_id, stream_id != UINT64_MAX);
    quic_stream_wantread(conn, stream_id, true);
    quic_stream_wantwrite(conn, stream_id, true);
}
static void on_stream_readable(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) {
    struct server_state *st = tctx;
    uint8_t buf[MAX_STREAM_CHUNK];
    bool fin = false;
    ssize_t n = quic_stream_read(conn, stream_id, buf, sizeof(buf), &fin);
    if (n < 0) {
        fprintf(stderr, "Server: stream_read err=%zd\n", n);
        quic_stream_wantread(conn, stream_id, true);
        return;
    }
    if (n == 0) {
        fprintf(stderr, "Server: stream_read 0 bytes (fin=%d)\n", (int)fin);
        quic_stream_wantread(conn, stream_id, true);
        return;
    }

    // Combine with leftover data
    size_t total_len = st->leftover_len + n;
    if (total_len > sizeof(st->leftover_buf)) {
        fprintf(stderr, "Server: Buffer overflow, discarding %zu bytes\n", st->leftover_len);
        st->leftover_len = 0;
        total_len = n;
        memcpy(st->leftover_buf, buf, n);
    } else {
        memcpy(st->leftover_buf + st->leftover_len, buf, n);
    }
    st->leftover_len = total_len;

    size_t offset = 0;
    while (offset < st->leftover_len) {
        if (st->leftover_len - offset < MIN_PACKET_SIZE) {
            // Not enough data for a full packet, shift buffer
            if (offset > 0) {
                memmove(st->leftover_buf, st->leftover_buf + offset, st->leftover_len - offset);
                st->leftover_len -= offset;
            }
            break;
        }
        // Assume client sends valid IPv4 packets (validated in client_drain_tun)
        if (st->leftover_buf[offset] != 0x45 || st->leftover_buf[offset + 1] != 0x00) {
            fprintf(stderr, "Server: Invalid IP header at offset %zu, discarding %zu bytes ", offset, st->leftover_len - offset);
            fprintf(stderr, "first_20=[");
            for (size_t i = 0; i < 20 && offset + i < st->leftover_len; i++) {
                fprintf(stderr, "%02x ", st->leftover_buf[offset + i]);
            }
            fprintf(stderr, "]\n");
            st->leftover_len = 0;
            offset = 0;
            break;
        }
        // Extract packet length from IPv4 header (bytes 2-3)
        uint16_t ip_len = (st->leftover_buf[offset + 2] << 8) | st->leftover_buf[offset + 3];
        if (offset + ip_len > st->leftover_len) {
            // Incomplete packet, shift buffer
            if (offset > 0) {
                memmove(st->leftover_buf, st->leftover_buf + offset, st->leftover_len - offset);
                st->leftover_len -= offset;
            }
            break;
        }
        fprintf(stderr, "Server: stream_read %u bytes (fin=%d) ", ip_len, (int)fin);
        fprintf(stderr, "first_20=[");
        for (size_t i = 0; i < 20 && offset + i < st->leftover_len; i++) {
            fprintf(stderr, "%02x ", st->leftover_buf[offset + i]);
        }
        fprintf(stderr, "]\n");
        if (st->tun_fd >= 0 && ip_len >= MIN_PACKET_SIZE) {
            ssize_t w = write(st->tun_fd, st->leftover_buf + offset, ip_len);
            if (w < 0) {
                perror("Server: write(tunS)");
            } else {
                fprintf(stderr, "Server: wrote %zd bytes to tunS\n", w);
            }
        } else {
            fprintf(stderr, "Server: skipped write to tunS (size %u < %d)\n", ip_len, MIN_PACKET_SIZE);
        }
        offset += ip_len;
    }
    // Final cleanup: shift remaining data only if offset > 0 and leftover_len >= offset
    if (offset > 0 && st->leftover_len >= offset) {
        memmove(st->leftover_buf, st->leftover_buf + offset, st->leftover_len - offset);
        st->leftover_len -= offset;
    }
    quic_stream_wantread(conn, stream_id, true);
}
static void on_stream_writable(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) {
    struct server_state *st = tctx;
    if (stream_id == st->stream_id) {
        st->stream_writable = true;
        fprintf(stderr, "Server: Stream %lu writable, resuming drain\n", (unsigned long)stream_id);
        drain_tun(st);
    }
}
static const struct quic_transport_methods_t transport_methods = {
    .on_conn_created = on_conn_created,
    .on_conn_established = on_conn_established,
    .on_conn_closed = on_conn_closed,
    .on_stream_created = on_stream_created,
    .on_stream_readable = on_stream_readable,
    .on_stream_writable = on_stream_writable,
};

static void sock_cb(struct ev_loop *loop, ev_io *w, int revents) {
    (void)loop; (void)revents; struct server_state *st = w->data;
    uint8_t buf[MAX_DGRAM];
    struct sockaddr_storage from; struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg; memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from; msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    ssize_t n = recvmsg(st->sock, &msg, 0);
    if (n <= 0) return;
    struct quic_packet_info_t info = {
        .src = (struct sockaddr*)&from, .src_len = msg.msg_namelen,
        .dst = (struct sockaddr*)&st->local, .dst_len = st->local_len
    };
    quic_endpoint_recv(st->ep, buf, (size_t)n, &info);
    quic_endpoint_process_connections(st->ep);
}

static void drain_tun(struct server_state *st) {
    if (!st->conn) {
        fprintf(stderr, "Server: Skipping drain_tun (conn=%p est=unknown sid=%lu)\n",
                (void*)st->conn, (unsigned long)st->stream_id);
        return;
    }
    bool est = quic_conn_is_established(st->conn);
    if (!est || st->stream_id == UINT64_MAX) {
        fprintf(stderr, "Server: Skipping drain_tun (conn=%p est=%d sid=%lu)\n",
                (void*)st->conn, est, (unsigned long)st->stream_id);
        return;
    }
    if (!st->stream_writable) {
        fprintf(stderr, "Server: Stream not writable, skipping drain\n");
        return;
    }
    fprintf(stderr, "Server: Draining TUN (sid=%lu, writable=%d)\n", (unsigned long)st->stream_id, st->stream_writable);
    for (;;) {
        uint8_t buf[MAX_STREAM_CHUNK];
        ssize_t n = read(st->tun_fd, buf, sizeof(buf));
        if (n > 0) {
            bool valid_ip = (n >= MIN_PACKET_SIZE && buf[0] == 0x45 && buf[1] == 0x00);
            fprintf(stderr, "Server: Read %zd bytes from TUN valid_ip=%d ", n, valid_ip);
            if (n >= 20) {
                fprintf(stderr, "first_20=[");
                for (int i = 0; i < 20; i++) fprintf(stderr, "%02x ", buf[i]);
                fprintf(stderr, "]");
            }
            fprintf(stderr, "\n");
            if (!valid_ip) {
                fprintf(stderr, "Server: Skipped write to QUIC stream (invalid IP header)\n");
                continue;
            }
            ssize_t nw = quic_stream_write(st->conn, st->stream_id, buf, (size_t)n, false);
            if (nw < 0) {
                if (nw == -100) { // QUIC_STREAM_ERROR_STREAM_BLOCKED
                    st->stream_writable = false;
                    quic_stream_wantwrite(st->conn, st->stream_id, true);
                    fprintf(stderr, "Server: Stream blocked (err=%zd), pausing drain\n", nw);
                    break;
                }
                fprintf(stderr, "Server: quic_stream_write err=%zd\n", nw);
            } else {
                fprintf(stderr, "Server: Wrote %zd bytes to QUIC stream\n", nw);
            }
            quic_stream_wantwrite(st->conn, st->stream_id, true);
            continue;
        }
        if (n == 0) break;
        if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; perror("Server: read(tunS)"); break; }
    }
}

static void tun_cb(struct ev_loop *loop, ev_io *w, int revents) {
    (void)loop; (void)revents; struct server_state *st = w->data;
    fprintf(stderr, "Server: TUN watcher triggered\n");
    drain_tun(st);
}

static void fast_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    (void)revents; struct server_state *st = w->data;
    quic_endpoint_on_timeout(st->ep);
    quic_endpoint_process_connections(st->ep);
    drain_tun(st);
    // Log path stats every 1 second
    static double last_log = 0.0;
    double now = ev_time();
    if (now - last_log >= 1.0 && st->conn) {
        struct quic_path_address_iter_t *iter = quic_conn_paths(st->conn);
        if (iter) {
            struct quic_path_address_t path_addr;
            while (quic_conn_path_iter_next(iter, &path_addr)) {
                const struct quic_path_stats_t *stats = quic_conn_path_stats(st->conn,
                    (const struct sockaddr*)&path_addr.local_addr, path_addr.local_addr_len,
                    (const struct sockaddr*)&path_addr.remote_addr, path_addr.remote_addr_len);
                if (stats) {
                    char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in*)&path_addr.local_addr)->sin_addr, local, sizeof(local));
                    inet_ntop(AF_INET, &((struct sockaddr_in*)&path_addr.remote_addr)->sin_addr, remote, sizeof(remote));
                    fprintf(stderr, "Server: Path %s<->%s: sent_bytes=%lu recv_bytes=%lu lost=%lu srtt=%lu us\n",
                            local, remote, stats->sent_bytes, stats->recv_bytes, stats->lost_count, stats->srtt);
                }
            }
            quic_conn_path_iter_free(iter);
        }
        last_log = now;
    }
    ev_timer_again(loop, w);
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "Usage: %s <tun_if> <listen_ip> <port>\n", argv[0]); return 1; }
    const char *tun_if = argv[1]; const char *listen_ip = argv[2]; int port = atoi(argv[3]);

    struct server_state st;
    memset(&st, 0, sizeof(st));
    st.stream_id = UINT64_MAX;
    st.stream_writable = true;
    st.leftover_len = 0;
    st.tun_fd = open_tun(tun_if);
    if (st.tun_fd < 0) return 1;

    st.sock = open_udp_server(listen_ip, (uint16_t)port, &st.local, &st.local_len);
    if (st.sock < 0) { fprintf(stderr, "Server: Failed to bind %s:%d\n", listen_ip, port); return 1; }
    fprintf(stderr, "Server: Bound to %s:%d\n", listen_ip, port);

    struct quic_config_t *cfg = quic_config_new();
    quic_config_enable_multipath(cfg, true);
    quic_config_set_multipath_algorithm(cfg, QUIC_MULTIPATH_ALGORITHM_ROUND_ROBIN);
    quic_config_set_active_connection_id_limit(cfg, 8);
    quic_config_set_recv_udp_payload_size(cfg, 1350);
    quic_config_set_initial_max_stream_data_bidi_remote(cfg, 33554432); // 32MB stream buffer
    quic_config_set_initial_max_data(cfg, 335544320);                  // 320MB connection buffer

    const char *alpn[] = {"http/0.9"};
    quic_tls_config_t *tls = quic_tls_config_new_server_config(
        "/home/racom/mptquic/tquic/cert.crt",
        "/home/racom/mptquic/tquic/cert.key",
        alpn, 1, false);
    if (!tls) { fprintf(stderr, "Server: TLS config failed\n"); return 1; }
    quic_config_set_tls_config(cfg, tls);

    st.ep = quic_endpoint_new(cfg, true, &transport_methods, &st, &send_methods, &st);
    if (!st.ep) { fprintf(stderr, "Server: endpoint_new failed\n"); return 1; }

    st.loop = EV_DEFAULT;
    ev_io_init(&st.sock_w, sock_cb, st.sock, EV_READ); st.sock_w.data = &st; ev_io_start(st.loop, &st.sock_w);
    ev_io_init(&st.tun_w, tun_cb, st.tun_fd, EV_READ); st.tun_w.data = &st; ev_io_start(st.loop, &st.tun_w);
    ev_timer_init(&st.timer_w, fast_cb, 0.005, 0.005); st.timer_w.data = &st; ev_timer_start(st.loop, &st.timer_w);

    ev_run(st.loop, 0);

    ev_loop_destroy(st.loop);
    quic_endpoint_free(st.ep);
    quic_tls_config_free(tls);
    quic_config_free(cfg);
    close(st.sock);
    close(st.tun_fd);
    return 0;
}
