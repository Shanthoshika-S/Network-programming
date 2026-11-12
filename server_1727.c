/* server_1727.c
   IE2102 Network Programming Assignment
   Registration No: IT24101727
   Port: 50727
   SID: 4101
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

/* ── configuration ── */
#define PORT          50727
#define SID           "4101"
#define REGNO         "IT24101727"
#define MAX_PAYLOAD   4096
#define MAX_USERS     100
#define MAX_SESSIONS  100
#define TOKEN_EXPIRY  300   /* 5 minutes in seconds          */
#define MAX_ATTEMPTS  3     /* failed logins before lockout  */
#define LOCKOUT_TIME  60    /* lockout duration in seconds   */
#define RATE_LIMIT    10    /* max requests per 10 seconds   */
#define RATE_WINDOW   10    /* rate window in seconds        */
#define LOG_FILE      "server_IT24101727.log"
#define DATA_DIR      "/srv/ie2102/IT24101727"

/* ── simple salted hash (XOR + sum, stays within syllabus) ── */
void hash_password(const char *pass, const char *salt, char *out, int outlen) {
    unsigned long h = 5381;
    int i;
    /* mix salt */
    for (i = 0; salt[i]; i++)
        h = ((h << 5) + h) ^ (unsigned char)salt[i];
    /* mix password */
    for (i = 0; pass[i]; i++)
        h = ((h << 5) + h) ^ (unsigned char)pass[i];
    snprintf(out, outlen, "%s$%lu", salt, h);
}

/* ── user store ── */
typedef struct {
    char username[64];
    char hash[128];      /* salt$hash */
    int  active;
} User;

/* ── session store ── */
typedef struct {
    char token[64];
    char username[64];
    time_t last_active;
    int  active;
} Session;

/* ── shared file paths ── */
char user_file[256];
char log_file_path[256];

/* ── logging ── */
void write_log(const char *client_ip, int client_port,
               pid_t pid, const char *username,
               const char *command, const char *result) {
    FILE *f = fopen(log_file_path, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(f, "[%s] IP:%s:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            timebuf,
            client_ip, client_port,
            pid,
            username[0] ? username : "NONE",
            command, result);
    fclose(f);
}

/* ── send a response to client ── */
void send_response(int sock, const char *type, const char *code,
                   const char *message) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "%s %s SID:%s %s\n", type, code, SID, message);
    send(sock, buf, strlen(buf), 0);
}

/* ── recv exact n bytes (handles partial recv) ── */
int recv_exact(int sock, char *buf, int n) {
    int total = 0;
    while (total < n) {
        int r = recv(sock, buf + total, n - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    buf[total] = '\0';
    return total;
}

/* ── read one framed message: LEN:<n>\n<payload> ── */
int read_framed(int sock, char *payload_out, int maxlen) {
    /* read header byte by byte until newline */
    char header[64];
    int hi = 0;
    while (hi < (int)sizeof(header) - 1) {
        char c;
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\n') break;
        header[hi++] = c;
    }
    header[hi] = '\0';

    /* parse LEN:<n> */
    if (strncmp(header, "LEN:", 4) != 0) return -2; /* invalid format */
    int n = atoi(header + 4);

    /* A1 edge cases */
    if (n <= 0)      return -3; /* invalid length  */
    if (n > maxlen)  return -4; /* oversized        */

    return recv_exact(sock, payload_out, n);
}

/* ── username validation (alphanumeric + underscore only) ── */
int valid_username(const char *u) {
    if (strlen(u) < 3 || strlen(u) > 32) return 0;
    for (int i = 0; u[i]; i++)
        if (!isalnum((unsigned char)u[i]) && u[i] != '_') return 0;
    return 1;
}

/* ── load users from file ── */
int load_users(User *users) {
    FILE *f = fopen(user_file, "r");
    if (!f) return 0;
    int count = 0;
    while (count < MAX_USERS &&
           fscanf(f, "%63s %127s", users[count].username,
                  users[count].hash) == 2) {
        users[count].active = 1;
        count++;
    }
    fclose(f);
    return count;
}

/* ── save users to file ── */
void save_users(User *users, int count) {
    FILE *f = fopen(user_file, "w");
    if (!f) return;
    for (int i = 0; i < count; i++)
        if (users[i].active)
            fprintf(f, "%s %s\n", users[i].username, users[i].hash);
    fclose(f);
}

/* ── generate simple session token ── */
void gen_token(const char *username, char *token_out) {
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    snprintf(token_out, 64, "%s_%lu_%d",
             username, (unsigned long)time(NULL), rand() % 9999);
}

/* ── SIGCHLD handler — reaps zombies ── */
void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* ════════════════════════════════════════════
   handle_client — runs in child process
   ════════════════════════════════════════════ */
void handle_client(int client_fd,
                   struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr,
              client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);
    pid_t my_pid   = getpid();

    /* ── per-session state ── */
    char logged_user[64] = "";
    char session_token[64] = "";
    time_t token_time = 0;
    int logged_in = 0;

    /* ── abuse protection counters ── */
    int   fail_attempts = 0;
    time_t lockout_start = 0;
    int   req_count  = 0;
    time_t rate_start = time(NULL);

    write_log(client_ip, client_port, my_pid, "",
              "CONNECT", "Client connected");

    printf("[PID %d] Client connected: %s:%d\n",
           my_pid, client_ip, client_port);

    /* ── create user data directory ── */
    char payload[MAX_PAYLOAD + 1];

    while (1) {
        memset(payload, 0, sizeof(payload));

        /* ── rate limiting ── */
        time_t now = time(NULL);
        if (now - rate_start >= RATE_WINDOW) {
            req_count  = 0;
            rate_start = now;
        }
        req_count++;
        if (req_count > RATE_LIMIT) {
            send_response(client_fd, "ERR", "429",
                          "Rate limit exceeded. Slow down.");
            write_log(client_ip, client_port, my_pid,
                      logged_user, "RATE_LIMIT", "Rejected");
            continue;
        }

        /* ── read framed message ── */
        int r = read_framed(client_fd, payload, MAX_PAYLOAD);
        if (r == -1) {
            /* client disconnected */
            printf("[PID %d] Client disconnected: %s:%d\n",
                   my_pid, client_ip, client_port);
            write_log(client_ip, client_port, my_pid,
                      logged_user, "DISCONNECT", "Client disconnected");
            break;
        }
        if (r == -2) {
            send_response(client_fd, "ERR", "400",
                          "Invalid frame format. Use LEN:<n>");
            write_log(client_ip, client_port, my_pid,
                      logged_user, "BAD_FRAME", "Invalid format");
            continue;
        }
        if (r == -3) {
            send_response(client_fd, "ERR", "400",
                          "Invalid length value.");
            write_log(client_ip, client_port, my_pid,
                      logged_user, "BAD_LEN", "Invalid length");
            continue;
        }
        if (r == -4) {
            send_response(client_fd, "ERR", "413",
                          "Payload too large. Max 4096 bytes.");
            write_log(client_ip, client_port, my_pid,
                      logged_user, "OVERFLOW", "Payload too large");
            continue;
        }

        /* strip trailing newline */
        payload[strcspn(payload, "\n")] = '\0';
        printf("[PID %d] Received: %s\n", my_pid, payload);

        /* ── parse command ── */
        char cmd[32]   = "";
        char arg1[128] = "";
        char arg2[128] = "";
        sscanf(payload, "%31s %127s %127s", cmd, arg1, arg2);

        /* ════ REGISTER ════ */
        if (strcmp(cmd, "REGISTER") == 0) {
            if (!valid_username(arg1)) {
                send_response(client_fd, "ERR", "400",
                    "Invalid username. Use 3-32 alphanumeric chars.");
                write_log(client_ip, client_port, my_pid,
                          arg1, "REGISTER", "Invalid username");
                continue;
            }
            if (strlen(arg2) < 4) {
                send_response(client_fd, "ERR", "400",
                    "Password too short. Min 4 chars.");
                write_log(client_ip, client_port, my_pid,
                          arg1, "REGISTER", "Password too short");
                continue;
            }

            User users[MAX_USERS];
            int  count = load_users(users);

            /* check duplicate */
            int found = 0;
            for (int i = 0; i < count; i++)
                if (strcmp(users[i].username, arg1) == 0)
                    { found = 1; break; }

            if (found) {
                send_response(client_fd, "ERR", "409",
                              "Username already exists.");
                write_log(client_ip, client_port, my_pid,
                          arg1, "REGISTER", "Duplicate username");
                continue;
            }

            /* salt = first 8 chars of username + pid */
            char salt[160];
            snprintf(salt, sizeof(salt), "%s%d",
                     arg1, (int)getpid() % 1000);
            char hashed[128];
            hash_password(arg2, salt, hashed, sizeof(hashed));

            strncpy(users[count].username, arg1, 63);
            strncpy(users[count].hash,     hashed, 127);
            users[count].active = 1;
            count++;
            save_users(users, count);

            /* create user directory */
            char udir[256];
            snprintf(udir, sizeof(udir),
                     DATA_DIR "/%s/%s", REGNO, arg1);
            mkdir(DATA_DIR "/" REGNO, 0755);
            mkdir(udir, 0755);

            send_response(client_fd, "OK", "201",
                          "User registered successfully.");
            write_log(client_ip, client_port, my_pid,
                      arg1, "REGISTER", "Success");

        /* ════ LOGIN ════ */
        } else if (strcmp(cmd, "LOGIN") == 0) {

            /* brute-force lockout check */
            now = time(NULL);
            if (fail_attempts >= MAX_ATTEMPTS) {
                if (now - lockout_start < LOCKOUT_TIME) {
                    send_response(client_fd, "ERR", "403",
                        "Account locked. Try again later.");
                    write_log(client_ip, client_port, my_pid,
                              arg1, "LOGIN", "Locked out");
                    continue;
                } else {
                    /* lockout expired */
                    fail_attempts = 0;
                }
            }

            User users[MAX_USERS];
            int  count = load_users(users);

            int  matched = 0;
            for (int i = 0; i < count; i++) {
                if (strcmp(users[i].username, arg1) == 0) {
                    /* re-hash with stored salt */
                    char stored[128];
                    strncpy(stored, users[i].hash, 127);
                    /* extract salt (part before $) */
                    char *dollar = strchr(stored, '$');
                    if (!dollar) break;
                    *dollar = '\0';
                    char *salt = stored; /* now just the salt */

                    char attempt[128];
                    hash_password(arg2, salt, attempt,
                                  sizeof(attempt));

                    if (strcmp(attempt, users[i].hash) == 0) {
                        matched = 1;
                    }
                    break;
                }
            }

            if (matched) {
                fail_attempts = 0;
                logged_in = 1;
                strncpy(logged_user, arg1, 63);
                gen_token(arg1, session_token);
                token_time = time(NULL);

                char msg[128];
                snprintf(msg, sizeof(msg),
                         "Login successful. Token:%s",
                         session_token);
                send_response(client_fd, "OK", "200", msg);
                write_log(client_ip, client_port, my_pid,
                          arg1, "LOGIN", "Success");
            } else {
                fail_attempts++;
                if (fail_attempts >= MAX_ATTEMPTS)
                    lockout_start = time(NULL);

                char msg[64];
                snprintf(msg, sizeof(msg),
                         "Invalid credentials. Attempts:%d/%d",
                         fail_attempts, MAX_ATTEMPTS);
                send_response(client_fd, "ERR", "401", msg);
                write_log(client_ip, client_port, my_pid,
                          arg1, "LOGIN", "Failed");
            }

        /* ════ LOGOUT ════ */
        } else if (strcmp(cmd, "LOGOUT") == 0) {
            if (!logged_in) {
                send_response(client_fd, "ERR", "401",
                              "Not logged in.");
                write_log(client_ip, client_port, my_pid,
                          logged_user, "LOGOUT", "Not logged in");
                continue;
            }
            /* token expiry check */
            if (time(NULL) - token_time > TOKEN_EXPIRY) {
                logged_in = 0;
                memset(logged_user,    0, sizeof(logged_user));
                memset(session_token,  0, sizeof(session_token));
                send_response(client_fd, "ERR", "440",
                              "Session expired. Please login again.");
                write_log(client_ip, client_port, my_pid,
                          logged_user, "LOGOUT", "Session expired");
                continue;
            }
            logged_in = 0;
            memset(logged_user,   0, sizeof(logged_user));
            memset(session_token, 0, sizeof(session_token));
            send_response(client_fd, "OK", "200",
                          "Logged out successfully.");
            write_log(client_ip, client_port, my_pid,
                      arg1, "LOGOUT", "Success");

        /* ════ STATUS (protected command example) ════ */
        } else if (strcmp(cmd, "STATUS") == 0) {
            if (!logged_in) {
                send_response(client_fd, "ERR", "401",
                              "Login required.");
                write_log(client_ip, client_port, my_pid,
                          "", "STATUS", "Unauthorized");
                continue;
            }
            /* token expiry check */
            if (time(NULL) - token_time > TOKEN_EXPIRY) {
                logged_in = 0;
                send_response(client_fd, "ERR", "440",
                              "Session expired. Please login again.");
                write_log(client_ip, client_port, my_pid,
                          logged_user, "STATUS", "Session expired");
                continue;
            }
            token_time = time(NULL); /* refresh token timer */
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "Logged in as %s. Token active.",
                     logged_user);
            send_response(client_fd, "OK", "200", msg);
            write_log(client_ip, client_port, my_pid,
                      logged_user, "STATUS", "Success");

        /* ════ UNKNOWN COMMAND ════ */
        } else {
            send_response(client_fd, "ERR", "400",
                          "Unknown command.");
            write_log(client_ip, client_port, my_pid,
                      logged_user, cmd, "Unknown command");
        }
    }

    close(client_fd);
    exit(0);
}

/* ════════════════════════════════════════════
   MAIN — parent process
   ════════════════════════════════════════════ */
int main(void) {
    /* set up paths */
    snprintf(user_file,      sizeof(user_file),
             DATA_DIR "/%s/users.db", REGNO);
    snprintf(log_file_path,  sizeof(log_file_path),
             "%s", LOG_FILE);

    /* ensure data directory exists */
    mkdir(DATA_DIR,           0755);
    mkdir(DATA_DIR "/" REGNO, 0755);

    /* SIGCHLD — reap zombie children */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    /* create TCP socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    /* allow port reuse */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
               &opt, sizeof(opt));

    /* bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    /* listen */
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        exit(1);
    }

    printf("============================================\n");
    printf("  IE2102 NP Assignment Server\n");
    printf("  RegNo : %s\n", REGNO);
    printf("  SID   : %s\n", SID);
    printf("  Port  : %d\n", PORT);
    printf("  PID   : %d\n", getpid());
    printf("============================================\n");

    write_log("SERVER", 0, getpid(), "",
              "START", "Server started");

    /* ── main accept loop ── */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t clen = sizeof(client_addr);

        int client_fd = accept(server_fd,
                               (struct sockaddr *)&client_addr,
                               &clen);
        if (client_fd < 0) {
            if (errno == EINTR) continue; /* interrupted by signal */
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            /* ── child process ── */
            close(server_fd);
            handle_client(client_fd, client_addr);
            /* handle_client calls exit() */
        } else {
            /* ── parent process ── */
            close(client_fd); /* parent doesn't use this */
            printf("[PARENT PID:%d] Forked child PID:%d\n",
                   getpid(), pid);
        }
    }

    close(server_fd);
    return 0;
}
