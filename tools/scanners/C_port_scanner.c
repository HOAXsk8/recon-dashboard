#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <json-c/json.h>

#define MONGO_URI "mongodb://admin:5I2ZKu83YQL7%2BfGu@localhost:27017/?authSource=admin"
#define DB_NAME "recon_db"
#define COLLECTION_NAME "domains"
#define RESOURCE_LIMIT 50.0

int max_workers = 4;
int stop_signal = 0;

typedef struct {
    char domain[256];
} recon_task_t;

// --- Utility: Get CPU Usage ---
double get_cpu_usage() {
    static long long last_user = 0, last_nice = 0, last_system = 0, last_idle = 0, last_iowait = 0, last_irq = 0, last_softirq = 0;
    long long user, nice, system, idle, iowait, irq, softirq;
    
    FILE* fp = fopen("/proc/stat", "r");
    if (!fp) return 0.0;
    
    char cpu[10];
    if (fscanf(fp, "%s %lld %lld %lld %lld %lld %lld %lld", cpu, &user, &nice, &system, &idle, &iowait, &irq, &softirq) < 8) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);
    
    long long prev_idle = last_idle + last_iowait;
    long long curr_idle = idle + iowait;
    
    long long prev_non_idle = last_user + last_nice + last_system + last_irq + last_softirq;
    long long curr_non_idle = user + nice + system + irq + softirq;
    
    long long prev_total = prev_idle + prev_non_idle;
    long long curr_total = curr_idle + curr_non_idle;
    
    long long total_diff = curr_total - prev_total;
    long long idle_diff = curr_idle - prev_idle;
    
    last_user = user; last_nice = nice; last_system = system; last_idle = idle;
    last_iowait = iowait; last_irq = irq; last_softirq = softirq;
    
    if (total_diff <= 0) return 0.0;
    return (double)(total_diff - idle_diff) / total_diff * 100.0;
}

// --- Utility: Run Shell Command ---
char* run_command(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;
    
    size_t size = 1024, len = 0;
    char* buf = malloc(size);
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t line_len = strlen(line);
        if (len + line_len + 1 > size) {
            size *= 2;
            buf = realloc(buf, size);
        }
        strcpy(buf + len, line);
        len += line_len;
    }
    pclose(fp);
    buf[len] = '\0';
    return buf;
}

// --- Step 1: Aliveness Check ---
int is_alive(const char* domain) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) return 0;
    
    int ports[] = {80, 443, 22, 53, 8080};
    int alive = 0;
    
    for (int i = 0; i < 5; i++) {
        int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
        addr->sin_port = htons(ports[i]);
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        connect(sock, (struct sockaddr*)addr, sizeof(*addr));
        if (poll(&pfd, 1, 1500) > 0) {
            int err;
            socklen_t lon = sizeof(int);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&err), &lon);
            if (err == 0) alive = 1;
        }
        
        close(sock);
        if (alive) break;
    }
    
    freeaddrinfo(res);
    return alive;
}

mongoc_client_pool_t* pool;

void read_config() {
    mongoc_client_t* client = mongoc_client_pool_pop(pool);
    mongoc_collection_t* collection = mongoc_client_get_collection(client, DB_NAME, "scanners");
    bson_t* query = BCON_NEW("key", BCON_UTF8("recon_agent_c"));
    mongoc_cursor_t* cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
    const bson_t* doc;
    
    if (mongoc_cursor_next(cursor, &doc)) {
        bson_iter_t iter;
        if (bson_iter_init_find(&iter, doc, "max_workers")) {
            max_workers = bson_iter_int32(&iter);
            if (max_workers < 1) max_workers = 1;
            if (max_workers > 20) max_workers = 20;
        }
        if (bson_iter_init_find(&iter, doc, "status")) {
            const char* status = bson_iter_utf8(&iter, NULL);
            if (strcmp(status, "Stopped") == 0) {
                stop_signal = 1;
            } else {
                stop_signal = 0;
            }
        }
    }
    
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(pool, client);
}

void update_scanner_status(const char* status) {
    mongoc_client_t* client = mongoc_client_pool_pop(pool);
    mongoc_collection_t* collection = mongoc_client_get_collection(client, DB_NAME, "scanners");
    bson_error_t error;
    
    bson_t* query = BCON_NEW("key", BCON_UTF8("recon_agent_c"));
    bson_t* update = BCON_NEW("$set", "{", 
        "status", BCON_UTF8(status), 
        "last_heartbeat", BCON_DATE_TIME(time(NULL) * 1000),
        "pid", BCON_INT32(getpid()),
        "name", BCON_UTF8("C Recon Agent"),
    "}");
    
    mongoc_collection_update_one(collection, query, update, BCON_NEW("upsert", BCON_BOOL(true)), NULL, &error);
    
    bson_destroy(query);
    bson_destroy(update);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(pool, client);
}

void* recon_thread(void* arg) {
    char* domain = (char*)arg;
    printf("[*] Starting thread for %s\n", domain);
    
    while (get_cpu_usage() > RESOURCE_LIMIT) {
        sleep(5);
    }
    
    mongoc_client_t* client = mongoc_client_pool_pop(pool);
    mongoc_collection_t* collection = mongoc_client_get_collection(client, DB_NAME, COLLECTION_NAME);
    bson_error_t error;
    
    if (!is_alive(domain)) {
        printf("[-] %s is dead. Removing.\n", domain);
        bson_t* query = BCON_NEW("domain", BCON_UTF8(domain));
        mongoc_collection_remove(collection, MONGOC_REMOVE_SINGLE_REMOVE, query, NULL, &error);
        bson_destroy(query);
        goto cleanup;
    }
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "subfinder -d %s -silent", domain);
    char* sub_out = run_command(cmd);
    bson_t* subs_arr = bson_new();
    if (sub_out) {
        char* line = strtok(sub_out, "\n");
        int i = 0;
        while (line) {
            char index[16];
            const char* key;
            bson_uint32_to_string(i++, &key, index, sizeof(index));
            bson_t child;
            bson_append_document_begin(subs_arr, key, -1, &child);
            BSON_APPEND_UTF8(&child, "name", line);
            bson_append_document_end(subs_arr, &child);
            
            bson_t* sub_query = BCON_NEW("domain", BCON_UTF8(line));
            bson_t* sub_doc = BCON_NEW("domain", BCON_UTF8(line), "scanned", BCON_BOOL(false), "recon_date", BCON_NULL);
            mongoc_collection_update_one(collection, sub_query, sub_doc, BCON_NEW("upsert", BCON_BOOL(true)), NULL, &error);
            bson_destroy(sub_query); bson_destroy(sub_doc);
            
            line = strtok(NULL, "\n");
        }
        free(sub_out);
    }
    
    snprintf(cmd, sizeof(cmd), "nmap -sS -sU --top-ports 1000 --max-retries 1 --max-rtt-timeout 2s %s", domain);
    char* nmap_out = run_command(cmd);
    int web_found = 0;
    if (nmap_out) {
        if (strstr(nmap_out, "80/tcp") || strstr(nmap_out, "443/tcp") || strstr(nmap_out, "8080/tcp")) web_found = 1;
        free(nmap_out);
    }
    
    bson_t* sensitive_files = bson_new();
    if (web_found) {
        snprintf(cmd, sizeof(cmd), "whatweb http://%s --color=never", domain);
        char* ww_out = run_command(cmd); free(ww_out);
        
        snprintf(cmd, sizeof(cmd), "ffuf -u http://%s/FUZZ -w /usr/share/wordlists/dirb/common.txt -s -mc 200,204,301,302,307,401,403,405 -o /tmp/ffuf.json -of json", domain);
        system(cmd);
        FILE* jf = fopen("/tmp/ffuf.json", "r");
        if (jf) {
            fseek(jf, 0, SEEK_END); long fsize = ftell(jf); fseek(jf, 0, SEEK_SET);
            if (fsize > 0) {
                char* jbuf = malloc(fsize + 1); fread(jbuf, 1, fsize, jf); jbuf[fsize] = '\0';
                struct json_object* root = json_tokener_parse(jbuf);
                struct json_object* results;
                if (root && json_object_object_get_ex(root, "results", &results)) {
                    for (int i = 0; i < json_object_array_length(results); i++) {
                        struct json_object* res = json_object_array_get_idx(results, i);
                        struct json_object* input; json_object_object_get_ex(res, "input", &input);
                        struct json_object* fuzz; json_object_object_get_ex(input, "FUZZ", &fuzz);
                        struct json_object* status; json_object_object_get_ex(res, "status", &status);
                        
                        char idx[16]; const char* fkey;
                        bson_uint32_to_string(i, &fkey, idx, sizeof(idx));
                        
                        bson_t child;
                        bson_append_document_begin(sensitive_files, fkey, -1, &child);
                        BSON_APPEND_UTF8(&child, "path", json_object_get_string(fuzz));
                        BSON_APPEND_INT32(&child, "status", json_object_get_int(status));
                        bson_append_document_end(sensitive_files, &child);
                    }
                }
                if (root) json_object_put(root);
                free(jbuf);
            }
            fclose(jf);
        }
    }
    
    bson_t* update_query = BCON_NEW("domain", BCON_UTF8(domain));
    bson_t* update_doc = BCON_NEW("$set", "{", 
        "scanned", BCON_BOOL(true), 
        "recon_date", BCON_DATE_TIME(time(NULL) * 1000),
        "infrastructure", "{", "subdomains", BCON_DOCUMENT(subs_arr), "}",
        "sensitive_files", BCON_DOCUMENT(sensitive_files),
    "}");
    mongoc_collection_update_one(collection, update_query, update_doc, NULL, NULL, &error);
    bson_destroy(update_query); bson_destroy(update_doc);
    bson_destroy(subs_arr); bson_destroy(sensitive_files);
    printf("[+] %s scan complete.\n", domain);

cleanup:
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(pool, client);
    free(domain);
    return NULL;
}

int main() {
    mongoc_init();
    mongoc_uri_t* uri = mongoc_uri_new(MONGO_URI);
    pool = mongoc_client_pool_new(uri);
    
    printf("[*] C Recon Agent Starting...\n");
    update_scanner_status("Idle");
    
    while (1) {
        read_config();
        
        if (stop_signal) {
            update_scanner_status("Stopped");
            sleep(30);
            continue;
        }

        mongoc_client_t* client = mongoc_client_pool_pop(pool);
        mongoc_collection_t* collection = mongoc_client_get_collection(client, DB_NAME, COLLECTION_NAME);
        
        bson_t* query = BCON_NEW("$or", "[", "{", "scanned", BCON_BOOL(false), "}", "{", "recon_date", BCON_NULL, "}", "]");
        mongoc_cursor_t* cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
        
        const bson_t* doc;
        pthread_t threads[20]; // Cap at 20 workers
        int t_count = 0;
        
        while (mongoc_cursor_next(cursor, &doc) && t_count < max_workers && t_count < 20) {
            if (t_count == 0) update_scanner_status("Running");
            bson_iter_t iter;
            if (bson_iter_init_find(&iter, doc, "domain")) {
                char* d = strdup(bson_iter_utf8(&iter, NULL));
                pthread_create(&threads[t_count++], NULL, recon_thread, d);
            }
        }
        
        for (int i = 0; i < t_count; i++) pthread_join(threads[i], NULL);
        
        mongoc_cursor_destroy(cursor);
        bson_destroy(query);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(pool, client);
        
        if (t_count == 0) {
            update_scanner_status("Idle");
            sleep(60);
        } else {
            sleep(5);
        }
    }
    
    mongoc_client_pool_destroy(pool);
    mongoc_uri_destroy(uri);
    mongoc_cleanup();
    return 0;
}
