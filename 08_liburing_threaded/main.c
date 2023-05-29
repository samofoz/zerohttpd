#include <stdio.h>
#include <math.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <liburing.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <pthread.h>
#include "mpscq.h"

#define SERVER_STRING                   "Server: zerohttpd/0.1\r\n"
#define DEFAULT_SERVER_PORT             8000
#define QUEUE_DEPTH                     8192*2
#define READ_SZ                         8192
#define MAX_THREADS                     128
#define MAX_SOCKETS                     14000*MAX_THREADS

#define EVENT_TYPE_ACCEPT       0
#define EVENT_TYPE_READ         1
#define EVENT_TYPE_WRITE        2

#define MIN_KERNEL_VERSION      5
#define MIN_MAJOR_VERSION       5

int server_port = DEFAULT_SERVER_PORT;
int total_threads = MAX_THREADS;
int total_sockets = MAX_SOCKETS;
int *server_socket;

struct io_uring *client_ring;

int fd;
char *buf;
struct stat path_stat;

unsigned long long connections;
unsigned long long concurrent;
unsigned long long total;
pthread_mutex_t lock;

struct request {
    int event_type;
    int iovec_count;
    int client_socket;
    struct iovec iov[];
};

struct client_event {
    int res;
    struct request *req;
};

const char *unimplemented_content = \
                                "HTTP/1.0 400 Bad Request\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>ZeroHTTPd: Unimplemented</title>"
                                "</head>"
                                "<body>"
                                "<h1>Bad Request (Unimplemented)</h1>"
                                "<p>Your client sent a request ZeroHTTPd did not understand and it is probably not your fault.</p>"
                                "</body>"
                                "</html>";

const char *http_404_content = \
                                "HTTP/1.0 404 Not Found\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>ZeroHTTPd: Not Found</title>"
                                "</head>"
                                "<body>"
                                "<h1>Not Found (404)</h1>"
                                "<p>Your client is asking for an object that was not found on this server.</p>"
                                "</body>"
                                "</html>";

/*
 One function that prints the system call and the error details
 and then exits with error code 1. Non-zero meaning things didn't go well.
 */
void fatal_error(const char *syscall) {
    perror(syscall);
    exit(1);
}

int check_kernel_version() {
    struct utsname buffer;
    char *p;
    long ver[16];
    int i=0;

    if (uname(&buffer) != 0) {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    p = buffer.release;

    while (*p) {
        if (isdigit(*p)) {
            ver[i] = strtol(p, &p, 10);
            i++;
        } else {
            p++;
        }
    }
    printf("Minimum kernel version required is: %d.%d\n",
            MIN_KERNEL_VERSION, MIN_MAJOR_VERSION);
    if (ver[0] >= MIN_KERNEL_VERSION && ver[1] >= MIN_MAJOR_VERSION ) {
        printf("Your kernel version is: %ld.%ld\n", ver[0], ver[1]);
        return 0;
    }
    fprintf(stderr, "Error: your kernel version is: %ld.%ld\n",
                    ver[0], ver[1]);
    return 1;
}

void check_for_index_file() {
    int ret = stat("public/index.html", &path_stat);
    if(ret < 0 ) {
        fprintf(stderr, "ZeroHTTPd needs the \"public\" directory to be "
                "present in the current directory.\n");
        fatal_error("stat: public/index.html");
    }
}

/*
 * Utility function to convert a string to lower case.
 * */

void strtolower(char *str) {
    for (; *str; ++str)
        *str = (char)tolower(*str);
}
/*
 * Helper function for cleaner looking code.
 * */

void *zh_malloc(size_t size) {
    void *buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "Fatal error: unable to allocate memory.\n");
        exit(1);
    }
    return buf;
}

/*
 * This function is responsible for setting up the main listening socket used by the
 * web server.
 * */

int setup_listening_socket(int port) {
    int sock;
    struct sockaddr_in srv_addr;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        fatal_error("socket()");

    int enable = 1;
    if (setsockopt(sock,
                   SOL_SOCKET, SO_REUSEPORT,
                   &enable, sizeof(int)) < 0)
        fatal_error("setsockopt(SO_REUSEPORT)");
/*
    enable = 1;
    if (setsockopt(sock,
                   SOL_SOCKET, SO_REUSEADDR,
                   &enable, sizeof(int)) < 0)
        fatal_error("setsockopt(SO_REUSEADDR)");
*/
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* We bind to a port and turn this socket into a listening
     * socket.
     * */
    if (bind(sock,
             (const struct sockaddr *)&srv_addr,
             sizeof(srv_addr)) < 0)
        fatal_error("bind()");

    if (listen(sock, 2000) < 0)
        fatal_error("listen()");

    return (sock);
}

int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len, int queue) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&client_ring[queue]);
    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *) client_addr,
                         client_addr_len, SOCK_NONBLOCK);
    struct request *req = malloc(sizeof(*req));
    req->event_type = EVENT_TYPE_ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&client_ring[queue]);
    return 0;
}

int add_read_request(int client_socket, int queue) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&client_ring[queue]);
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_SZ);
    req->iov[0].iov_len = READ_SZ;
    req->event_type = EVENT_TYPE_READ;
    req->client_socket = client_socket;
    memset(req->iov[0].iov_base, 0, READ_SZ);
    /* Linux kernel 5.5 has support for readv, but not for recv() or read() */
    io_uring_prep_readv(sqe, client_socket, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&client_ring[queue]);
    return 0;
}

int add_write_request(struct request *req, int client_socket, int queue) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&client_ring[queue]);
    req->event_type = EVENT_TYPE_WRITE;
    io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&client_ring[queue]);
    return 0;
}

void _send_static_string_content(const char *str, int client_socket, int queue) {
    struct request *req = zh_malloc(sizeof(*req) + sizeof(struct iovec));
    unsigned long slen = strlen(str);
    req->iovec_count = 1;
    req->client_socket = client_socket;
    req->iov[0].iov_base = zh_malloc(slen);
    req->iov[0].iov_len = slen;
    memcpy(req->iov[0].iov_base, str, slen);
    add_write_request(req, client_socket, queue);
}

/*
 * When ZeroHTTPd encounters any other HTTP method other than GET or POST, this function
 * is used to inform the client.
 * */

void handle_unimplemented_method(int client_socket, int queue) {
    _send_static_string_content(unimplemented_content, client_socket, queue);
}

/*
 * This function is used to send a "HTTP Not Found" code and message to the client in
 * case the file requested is not found.
 * */

void handle_http_404(int client_socket, int queue) {
    _send_static_string_content(http_404_content, client_socket, queue);
}

/*
 * Once a static file is identified to be served, this function is used to read the file
 * and write it over the client socket using Linux's sendfile() system call. This saves us
 * the hassle of transferring file buffers from kernel to user space and back.
 * */
void open_index_file(char *file_path) {
    if(!fd){
    buf = zh_malloc(path_stat.st_size);
    fd = open(file_path, O_RDONLY);
    if (fd < 0)
        fatal_error("read");

    /* We should really check for short reads here */
    int ret = read(fd, buf, path_stat.st_size);
    if (ret < path_stat.st_size) {
        fprintf(stderr, "Encountered a short read.\n");
    }
    close(fd);
    }
}


void copy_file_contents(char *file_path, off_t file_size, struct iovec *iov) {
    iov->iov_base = buf;
    iov->iov_len = file_size;
}

/*
 * Simple function to get the file extension of the file that we are about to serve.
 * */

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";
    return dot + 1;
}

/*
 * Sends the HTTP 200 OK header, the server string, for a few types of files, it can also
 * send the content type based on the file extension. It also sends the content length
 * header. Finally it send a '\r\n' in a line by itself signalling the end of headers
 * and the beginning of any content.
 * */

void send_headers(const char *path, off_t len, struct iovec *iov) {
    char small_case_path[1024];
    char send_buffer[1024];
    strcpy(small_case_path, path);
    strtolower(small_case_path);

    char *str = "HTTP/1.0 200 OK\r\n";
    unsigned long slen = strlen(str);
    iov[0].iov_base = zh_malloc(slen);
    iov[0].iov_len = slen;
    memcpy(iov[0].iov_base, str, slen);

    slen = strlen(SERVER_STRING);
    iov[1].iov_base = zh_malloc(slen);
    iov[1].iov_len = slen;
    memcpy(iov[1].iov_base, SERVER_STRING, slen);

    /*
     * Check the file extension for certain common types of files
     * on web pages and send the appropriate content-type header.
     * Since extensions can be mixed case like JPG, jpg or Jpg,
     * we turn the extension into lower case before checking.
     * */
    const char *file_ext = get_filename_ext(small_case_path);
    if (strcmp("jpg", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    if (strcmp("jpeg", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    if (strcmp("png", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/png\r\n");
    if (strcmp("gif", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/gif\r\n");
    if (strcmp("htm", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/html\r\n");
    if (strcmp("html", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/html\r\n");
    if (strcmp("js", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: application/javascript\r\n");
    if (strcmp("css", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/css\r\n");
    if (strcmp("txt", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/plain\r\n");
    slen = strlen(send_buffer);
    iov[2].iov_base = zh_malloc(slen);
    iov[2].iov_len = slen;
    memcpy(iov[2].iov_base, send_buffer, slen);

    /* S/end the content-length header, which is the file size in this case. */
    sprintf(send_buffer, "content-length: %ld\r\n", len);
    slen = strlen(send_buffer);
    iov[3].iov_base = zh_malloc(slen);
    iov[3].iov_len = slen;
    memcpy(iov[3].iov_base, send_buffer, slen);

    /*
     * When the browser sees a '\r\n' sequence in a line on its own,
     * it understands there are no more headers. Content may follow.
     * */
    strcpy(send_buffer, "\r\n");
    slen = strlen(send_buffer);
    iov[4].iov_base = zh_malloc(slen);
    iov[4].iov_len = slen;
    memcpy(iov[4].iov_base, send_buffer, slen);
}
void handle_get_method(char *path, int client_socket, int queue) {
    char final_path[1024];

    /*
     If a path ends in a trailing slash, the client probably wants the index
     file inside of that directory.
     */
    if (path[strlen(path) - 1] == '/') {
        strcpy(final_path, "public");
        strcat(final_path, path);
        strcat(final_path, "index.html");
    }
    else {
        strcpy(final_path, "public");
        strcat(final_path, path);
    }

    /* The stat() system call will give you information about the file
     * like type (regular file, directory, etc), size, etc. */
    {
        /* Check if this is a normal/regular file and not a directory or something else */
        if (S_ISREG(path_stat.st_mode)) {
            struct request *req = zh_malloc(sizeof(*req) + (sizeof(struct iovec) * 6));
            req->iovec_count = 6;
            req->client_socket = client_socket;
            send_headers(final_path, path_stat.st_size, req->iov);
            copy_file_contents(final_path, path_stat.st_size, &req->iov[5]);
            //printf("200 %s %ld bytes\n", final_path, path_stat.st_size);
            add_write_request( req, client_socket, queue);
        }
        else {
            handle_http_404(client_socket, queue);
            printf("404 Not Found: %s\n", final_path);
        }
    }
}

/*
 * This function looks at method used and calls the appropriate handler function.
 * Since we only implement GET and POST methods, it calls handle_unimplemented_method()
 * in case both these don't match. This sends an error to the client.
 * */

void handle_http_method(char *method_buffer, int client_socket, int queue) {
    char *method, *path, *saveptr;

    method = strtok_r(method_buffer, " ", &saveptr);
    strtolower(method);
    path = strtok_r(NULL, " ", &saveptr);

    if (strcmp(method, "get") == 0) {
        handle_get_method(path, client_socket, queue);
    }
    else {
        handle_unimplemented_method(client_socket, queue);
    }
}

int get_line(const char *src, char *dest, int dest_sz) {
    for (int i = 0; i < dest_sz; i++) {
        dest[i] = src[i];
        if (src[i] == '\r' && src[i+1] == '\n') {
            dest[i] = '\0';
            return 0;
        }
    }
    return 1;
}

int handle_client_request(struct request *req, int queue) {
    char http_request[1024];
    /* Get the first line, which will be the request */
    if(get_line(req->iov[0].iov_base, http_request, sizeof(http_request))) {
        fprintf(stderr, "Malformed request\n");
        exit(1);
    }
    handle_http_method(http_request, req->client_socket, queue);
    return 0;
}



void server_loop(int i) {
    int port = server_port;// + i;
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int conns = 0;

    server_socket[i] = setup_listening_socket(port);
    add_accept_request(server_socket[i], &client_addr, &client_addr_len, i);
    printf("ZeroHTTPd[%d] listening on port: %d\n", i, port);

    while(1){
        int ret = io_uring_wait_cqe(&client_ring[i], &cqe);
        struct request *req = (struct request *) cqe->user_data;
        if (ret < 0)
            fatal_error("io_uring_wait_cqe");
        //fprintf(stderr, "Event [%d] received on ring [%d]\n", req->event_type, i);
        if (cqe->res < 0) {
            fprintf(stderr, "Async request failed: %s for event: %d\n",
                    strerror(-cqe->res), req->event_type);
            close(req->client_socket);
            pthread_mutex_lock(&lock);
            connections--;
            if(!connections) {
                fprintf(stderr, "Total connections [%lld], Max Concurrent [%lld]\n", total, concurrent);
                total = concurrent = 0;
            }
            pthread_mutex_unlock(&lock);
            free(req);
            io_uring_cqe_seen(&client_ring[i], cqe);
            continue;
        }
        switch (req->event_type) {
            case EVENT_TYPE_ACCEPT:
                //fprintf(stderr, "New connection received on ring [%d], count [%d]\n", i, ++conns);
                pthread_mutex_lock(&lock);
                connections++;
                total++;
                if(connections > concurrent)
                    concurrent = connections;
                pthread_mutex_unlock(&lock);
                add_accept_request(server_socket[i], &client_addr, &client_addr_len, i);
                add_read_request(cqe->res, i);
                break;
            case EVENT_TYPE_READ:
                if (!cqe->res) {
                    //fprintf(stderr, "Connection terminated on ring [%d], count [%d]\n", i, --conns);
                    close(req->client_socket);
                    pthread_mutex_lock(&lock);
                    connections--;
                    if(!connections) {
                        fprintf(stderr, "Total connections [%lld], Max Concurrent [%lld]\n", total, concurrent);
                        total = concurrent = 0;
                    }
                    pthread_mutex_unlock(&lock);
                    break;
                }
                handle_client_request(req, i);
                free(req->iov[0].iov_base);
                break;
            case EVENT_TYPE_WRITE:
                for (int i = 0; i < req->iovec_count-1; i++) {
                    free(req->iov[i].iov_base);
                }
                //fprintf(stderr, "Connection terminated on ring [%d], count [%d]\n", i, --conns);
                close(req->client_socket);
                pthread_mutex_lock(&lock);
                connections--;
                if(!connections) {
                    fprintf(stderr, "Total connections [%lld], Max Concurrent [%lld]\n", total, concurrent);
                    total = concurrent = 0;
                }
                pthread_mutex_unlock(&lock);
                break;
            default:
                fprintf(stderr, "Unknown event! [%d]\n", req->event_type);
                close(req->client_socket);
                pthread_mutex_lock(&lock);
                connections--;
                if(!connections) {
                    fprintf(stderr, "Total connections [%lld], Max Concurrent [%lld]\n", total, concurrent);
                    total = concurrent = 0;
                }
                pthread_mutex_unlock(&lock);
                break;
        }
        free(req);
        io_uring_cqe_seen(&client_ring[i], cqe);
    }
    return;
}

void sigint_handler(int signo) {
    printf("^C pressed. Shutting down.\n");
    for(int i = 0; i < total_threads; ++i)
        io_uring_queue_exit(&client_ring[i]);
    exit(0);
}

void *client_thread(void *p) {
    int i = (int)(intptr_t)p;

    server_loop(i);
    return NULL;
}

/*
void *liburing_thread(void *p) {
    int i = (int)(intptr_t)p;

    while(1){
        struct io_uring_sqe *temp = (struct io_uring_sqe *)mpscq_dequeue(liburing_queues[i]);
        if(!temp)
            continue;
        //fprintf(stderr, "Submitting sqe on ring [%d]\n", i);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&client_ring[i]);
        memcpy(sqe, temp, sizeof(struct io_uring_sqe));
        free(temp);
        io_uring_submit(&client_ring[i]);
    }
    return NULL;
}
*/


int main(int argc, char*argv[]) {
    if (check_kernel_version()) {
        return EXIT_FAILURE;
    }
    if (argc > 1)
      server_port = atoi(argv[1]);
    if (argc > 2)
      total_threads = atoi(argv[2]);
    if (argc > 3)
      total_sockets = total_threads * atoi(argv[3]);

    pthread_mutex_init(&lock, NULL);

    check_for_index_file();
    open_index_file("public/index.html");

    signal(SIGINT, sigint_handler);
    nice(100);

    client_ring = (struct io_uring*)malloc(total_threads * sizeof(struct io_uring));
    server_socket = (int *)malloc(total_threads * sizeof(int));

    if(total_threads > 1) {
        pthread_t pt;
        for(int i = 0; i < total_threads; ++i) {
            io_uring_queue_init(QUEUE_DEPTH, &client_ring[i], 0);
            pthread_create(&pt, NULL, client_thread, (void *)(intptr_t)i);
        }

        while(1)
            sleep(10);
    } else {
        io_uring_queue_init(QUEUE_DEPTH, &client_ring[0], 0);
        server_loop(0);
    }

    return 0;
}

