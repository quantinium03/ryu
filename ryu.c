#include <asm-generic/socket.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#define CRLF "\r\n"
#define HTTP_PROTOCOL_11 "HTTP/1.1"
#define HEADER_SEP ": "

static char *directory_name;

typedef struct {
    char *key;
    char *value;
} Header;

typedef struct {
    int length;
    Header **header;
} Header_Data;

typedef struct {
    char *method, *path, *body;
    Header_Data *header;
} request;

void *http_handler(void *args);
void parse_req_buf(char buff[1024], request *req);
bool str_starts_with(const char *str, const char *searchStr);
char **get_str_tokens(const char *str, const char *delim);
char *res_code_builder(const int status, const char *status_text);
char *build_header(const char *key, const char *value);
char *gzip_compress(const char *data, size_t data_len, size_t *len);
int client_accepts_compression(request *req, const char *scheme);
bool accept_gzip(request *req);
void free_request(request *req);

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: ryu --directory <directory_name>\n");
        return 1;
    }

    if (strcmp(argv[1], "--directory") != 0) {
        printf("Usage: ryu --directory <directory_name>\n");
        return 1;
    }
    directory_name = argv[2];

    printf("Logs: \n");

    int server_fd;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s... \n", strerror(errno));
        return 1;
    }

    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEPORT failed: %s \n", strerror(errno));
        close(server_fd);
        return 1;
    }

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(server_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        printf("Bind failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    int connection_limit = 5;
    if (listen(server_fd, connection_limit) != 0) {
        printf("Listen failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    printf("Server is listening on port %u\n", ntohs(srv.sin_port));

    socklen_t client_addr_len;
    struct sockaddr_in client_addr;
    pthread_t tid;

    while (true) {
        printf("Waiting for a client to connect... \n");
        client_addr_len = sizeof(client_addr);
        int client = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client < 0) {
            printf("Couldn't accept client %s \n", strerror(errno));
            continue;
        }

        printf("Client connected. Creating thread to handle request.\n");

        if (pthread_create(&tid, NULL, http_handler, (void *)(intptr_t)client) != 0) {
            printf("Failed to create thread: %s\n", strerror(errno));
            close(client);
            continue;
        }
        printf("Thread created successfully\n");
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}

void *http_handler(void *args) {
    char buff[1024] = {0};
    int client = (int)(intptr_t)args;
    printf("Handler thread started for client %d\n", client);

    ssize_t bytes_read = read(client, buff, sizeof(buff) - 1);
    if (bytes_read <= 0) {
        close(client);
        return NULL;
    }

    printf("%s", buff);

    request *req = calloc(1, sizeof(request));
    parse_req_buf(buff, req);

    char *res = NULL;
    if (strcmp(req->method, "GET") == 0 && str_starts_with(req->path, "/files/")) {
        char *file_name = req->path + 7;  // Skip "/files/"
        
        size_t file_path_size = strlen(directory_name) + strlen(file_name) + 2;
        char *file_path = calloc(sizeof(char), file_path_size);
        snprintf(file_path, file_path_size, "%s/%s", directory_name, file_name);

        if (access(file_path, R_OK) == 0) {
            FILE *file = fopen(file_path, "rb");
            if (file) {
                fseek(file, 0, SEEK_END);
                long file_length = ftell(file);
                fseek(file, 0, SEEK_SET);

                char *file_content = malloc(file_length + 1);
                if (file_content) {
                    size_t bytes_read = fread(file_content, 1, file_length, file);
                    if (bytes_read == (size_t)file_length) {
                        file_content[file_length] = '\0';

                        char *res_start = res_code_builder(200, "OK");
                        char *type_header = build_header("Content-Type", "application/octet-stream");
                        char len_header_value[32];
                        snprintf(len_header_value, sizeof(len_header_value), "%ld", file_length);
                        char *len_header = build_header("Content-Length", len_header_value);

                        size_t res_size = strlen(res_start) + strlen(type_header) +
                                        strlen(len_header) + strlen(CRLF) + file_length + 1;
                        res = calloc(sizeof(char), res_size);
                        if (res) {
                            snprintf(res, res_size, "%s%s%s%s", res_start, type_header,
                                   len_header, CRLF);
                            memcpy(res + strlen(res), file_content, file_length);
                        }

                        free(res_start);
                        free(type_header);
                        free(len_header);
                    }
                    free(file_content);
                }
                fclose(file);
            }
        }
        free(file_path);
        
        if (!res) {
            res = strdup("HTTP/1.1 404 Not Found\r\n\r\n");
        }
    } else if (strcmp(req->method, "POST") == 0 && str_starts_with(req->path, "/files/")) {
        char *file_name = req->path + 7;  // Skip "/files/"
        
        size_t file_path_size = strlen(directory_name) + strlen(file_name) + 2;
        char *file_path = calloc(sizeof(char), file_path_size);
        snprintf(file_path, file_path_size, "%s/%s", directory_name, file_name);

        FILE *file = fopen(file_path, "w");
        if (file && req->body) {
            fputs(req->body, file);
            fclose(file);
            res = strdup("HTTP/1.1 201 Created\r\n\r\n");
        } else {
            res = strdup("HTTP/1.1 500 Internal Server Error\r\n\r\n");
        }
        free(file_path);
    } else if (str_starts_with(req->path, "/user-agent")) {
        const char *user_agent = NULL;
        for (int i = 0; i < req->header->length; i++) {
            if (strcasecmp(req->header->header[i]->key, "User-Agent") == 0) {
                user_agent = req->header->header[i]->value;
                break;
            }
        }

        char *res_start = res_code_builder(200, "OK");
        char *type_header = build_header("Content-Type", "text/plain");
        
        size_t content_length = user_agent ? strlen(user_agent) : 0;
        char len_str[32];
        snprintf(len_str, sizeof(len_str), "%zu", content_length);
        char *len_header = build_header("Content-Length", len_str);

        size_t res_size = strlen(res_start) + strlen(type_header) +
                         strlen(len_header) + strlen(CRLF) + content_length + 1;
        res = calloc(sizeof(char), res_size);
        if (res) {
            snprintf(res, res_size, "%s%s%s%s%s", res_start, type_header,
                    len_header, CRLF, user_agent ? user_agent : "");
        }

        free(res_start);
        free(type_header);
        free(len_header);
    } else if (str_starts_with(req->path, "/echo/")) {
        char *echo_str = req->path + 6;  // Skip "/echo/"
        bool use_gzip = accept_gzip(req);
        
        char *body;
        size_t body_len;

        if (use_gzip) {
            size_t compressed_len;
            body = gzip_compress(echo_str, strlen(echo_str), &compressed_len);
            if (body) {
                body_len = compressed_len;
            } else {
                use_gzip = false;
                body = strdup(echo_str);
                body_len = strlen(body);
            }
        } else {
            body = strdup(echo_str);
            body_len = strlen(body);
        }

        if (body) {
            char *res_start = res_code_builder(200, "OK");
            char *type_header = build_header("Content-Type", "text/plain");
            char len_str[32];
            snprintf(len_str, sizeof(len_str), "%zu", body_len);
            char *len_header = build_header("Content-Length", len_str);
            char *encoding_header = use_gzip ? build_header("Content-Encoding", "gzip") : "";

            size_t headers_size = strlen(res_start) + strlen(type_header) +
                                strlen(len_header) + strlen(encoding_header) + strlen(CRLF);
            size_t res_size = headers_size + body_len;
            res = calloc(sizeof(char), res_size);
            if (res) {
                snprintf(res, headers_size + 1, "%s%s%s%s%s", res_start, type_header,
                        len_header, encoding_header, CRLF);
                memcpy(res + headers_size, body, body_len);
            }

            free(res_start);
            free(type_header);
            free(len_header);
            if (use_gzip) {
                free(encoding_header);
            }
            free(body);
        }
    } else {
        res = strdup("HTTP/1.1 404 Not Found\r\n\r\n");
    }

    if (res) {
        write(client, res, strlen(res));
        free(res);
    }

    printf("Response has been sent to client %d\n", client);
    free_request(req);
    close(client);
    printf("Client %d connection closed\n", client);
    return NULL;
}

void free_request(request *req) {
    if (req) {
        free(req->method);
        free(req->path);
        free(req->body);
        
        if (req->header) {
            for (int i = 0; i < req->header->length; i++) {
                if (req->header->header[i]) {
                    free(req->header->header[i]->key);
                    free(req->header->header[i]->value);
                    free(req->header->header[i]);
                }
            }
            free(req->header->header);
            free(req->header);
        }
        free(req);
    }
}

bool accept_gzip(request *req) {
    int use_gzip = client_accepts_compression(req, "gzip");
/*     int use_deflate = client_accepts_compression(req, "deflate"); */

    if (use_gzip) {
        return true;
    } else {
        return false;
    }
}

int client_accepts_compression(request *req, const char *scheme) {
    for (int i = 0; i < req->header->length; i++) {
        if (strcmp(req->header->header[i]->key, "Accept-Encoding") == 0) {
            char *encodings = strdup(req->header->header[i]->value);
            char *enc = strtok(encodings, ",");
            while (enc != NULL) {
                while (isspace(*enc)) {
                    enc++;
                }

                char *end = enc + strlen(enc) - 1;
                while (end > enc && isspace(*end)) {
                    end--;
                }
                *(end + 1) = 0;

                if (strcmp(enc, scheme) == 0) {
                    free(encodings);
                    return 1;
                }
                enc = strtok(NULL, ",");
            }
            free(encodings);
        }
    }
    return 0;
}

char *gzip_compress(const char *data, size_t data_len, size_t *len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return NULL;
    }

    zs.next_in = (Bytef *)data;
    zs.avail_in = data_len;

    size_t buffer_size = deflateBound(&zs, data_len);
    char *compressed = malloc(buffer_size);
    zs.next_out = (Bytef *)compressed;
    zs.avail_in = buffer_size;

    int ret = deflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END) {
        free(compressed);
        deflateEnd(&zs);
        return NULL;
    }
    *len = zs.total_out;
    deflateEnd(&zs);
    return compressed;
}

char *build_header(const char *key, const char *value) {
    size_t header_size =
        (strlen(key) + strlen(HEADER_SEP) + strlen(value) + strlen(CRLF) + 1);
    char *header = calloc(sizeof(char), header_size);
    snprintf(header, header_size, "%s%s%s%s", key, HEADER_SEP, value, CRLF);
    return header;
}

char *res_code_builder(const int status, const char *status_text) {
    char *status_num_str = malloc(6 * sizeof(char));
    snprintf(status_num_str, 6, "%d", status);
    size_t res_len = (strlen(HTTP_PROTOCOL_11) + 1 + strlen(status_num_str) +
                      1 + strlen(status_text) + strlen(CRLF) + 1);

    char *res = calloc(sizeof(char), res_len);
    snprintf(res, res_len, "%s %s %s%s", HTTP_PROTOCOL_11, status_num_str,
             status_text, CRLF);
    return res;
}
char **get_str_tokens(const char *str, const char *delim) {
    char **parts = malloc(5 * sizeof(*parts));
    char *token;
    char *rest = strdup(str);
    for (int i = 0; (token = strtok_r(rest, delim, &rest)); i++) {
        parts[i] = calloc(sizeof(char), strlen(token) + 1);
        strcpy(parts[i], token);
    }
    return parts;
}

bool str_starts_with(const char *str, const char *searchStr) {
    return strncmp(str, searchStr, strlen(searchStr)) == 0;
}

void parse_req_buf(char buff[1024], request *req) {
    char *rest = strdup(buff);

    size_t method_len = strcspn(rest, " ");
    req->method = calloc(sizeof(char), method_len + 1);
    memcpy(req->method, rest, &rest[method_len] - rest);
    rest += method_len + 1;

    size_t path_len = strcspn(rest, " ");
    req->path = calloc(sizeof(char), path_len + 1);
    memcpy(req->path, rest, &rest[path_len] - rest);
    rest += path_len + 1;

    size_t version_len = strcspn(rest, CRLF);
    rest += version_len + 2;

    int header_len = 0;
    Header_Data *headers_data = malloc(sizeof(Header_Data));
    Header **headers = malloc(sizeof(Header*) * 32);  // Preallocate space for up to 32 headers

    while (rest[0] != '\r' || rest[1] != '\n') {
        if (header_len >= 32) {
            // Too many headers, prevent buffer overflow
            break;
        }

        size_t key_len = strcspn(rest, ":");
        char *key = calloc(sizeof(char), key_len + 1);
        memcpy(key, rest, key_len);
        key[key_len] = '\0';
        rest += key_len + 1;
        
        while (isspace(*rest)) {
            rest++;
        }

        size_t value_len = strcspn(rest, CRLF);
        char *value = calloc(sizeof(char), value_len + 1);
        memcpy(value, rest, value_len);
        value[value_len] = '\0';
        rest += value_len + 2;  // Skip CRLF

        headers[header_len] = malloc(sizeof(Header));  // Allocate for Header struct, not pointer
        headers[header_len]->key = key;
        headers[header_len]->value = value;
        header_len++;
    }

    headers_data->header = headers;
    headers_data->length = header_len;
    req->header = headers_data;
    rest += 2;  // Skip final CRLF

    req->body = strdup(rest);
    free(rest - (strlen(buff) - strlen(rest)));  // Free the original duplicated buffer
}
