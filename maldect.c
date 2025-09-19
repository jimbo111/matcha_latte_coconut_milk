#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

#define MIN_STRING_LEN 4
#define MAX_FILE_READ (200 * 1024 * 1024)

static const char *suspicious_keywords[] = {
    "socket","connect","accept","listen","bind","send","recv",
    "gethostbyname","getaddrinfo","http://","https://","ftp://",
    "wget","curl","URLDownloadToFile","InternetConnect","InternetOpen",
    "cmd.exe","powershell","pwsh","/bin/sh","/bin/bash","system(","popen(","exec(","execve(",
    "CreateProcess","CreateRemoteThread","VirtualAlloc","LoadLibrary","WinExec",
    "RegSetValue","HKLM\\","HKCU\\","RunOnce",
    "UPX!","UPX0","UPX1",
    "WScript","cscript","wscript.exe",
    "fopen(","fwrite(","fread(","remove(","unlink(",
    "ssh ","nc ","netcat","reverse","bindshell","backshell",
    NULL
};

static void hexprint(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", digest[i]);
}

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if ((size_t)sz > MAX_FILE_READ) {
        fprintf(stderr, "file too large (> %d MiB)\n", MAX_FILE_READ / (1024*1024));
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    buf[n] = 0;
    *out_size = n;
    return buf;
}

static void compute_sha256(const unsigned char *buf, size_t n, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_MD_CTX_new failed\n"); exit(1); }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) { EVP_MD_CTX_free(ctx); fprintf(stderr, "EVP_DigestInit_ex failed\n"); exit(1); }
    if (!EVP_DigestUpdate(ctx, buf, n)) { EVP_MD_CTX_free(ctx); fprintf(stderr, "EVP_DigestUpdate failed\n"); exit(1); }
    unsigned int outlen = 0;
    if (!EVP_DigestFinal_ex(ctx, out, &outlen) || outlen != 32) { EVP_MD_CTX_free(ctx); fprintf(stderr, "EVP_DigestFinal_ex failed\n"); exit(1); }
    EVP_MD_CTX_free(ctx);
}

static double shannon_entropy(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; ++i) freq[buf[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)n;
        ent -= p * log2(p);
    }
    return ent;
}

static char **extract_strings(const unsigned char *buf, size_t n, size_t *out_count) {
    size_t cap = 256;
    char **strings = malloc(cap * sizeof(char*));
    size_t count = 0;
    size_t i = 0;
    while (i < n) {
        if (isprint(buf[i])) {
            size_t j = i;
            while (j < n && isprint(buf[j])) j++;
            size_t len = j - i;
            if (len >= MIN_STRING_LEN) {
                char *s = malloc(len + 1);
                memcpy(s, buf + i, len);
                s[len] = '\0';
                if (count >= cap) {
                    cap *= 2;
                    strings = realloc(strings, cap * sizeof(char*));
                }
                strings[count++] = s;
            }
            i = j;
        } else {
            i++;
        }
    }
    *out_count = count;
    return strings;
}

static void free_strings(char **arr, size_t count) {
    for (size_t i = 0; i < count; ++i) free(arr[i]);
    free(arr);
}

static int contains_keyword_ci(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t hn = strlen(hay), nn = strlen(needle);
    if (nn == 0 || hn < nn) return 0;
    for (size_t i = 0; i <= hn - nn; ++i) {
        size_t j = 0;
        for (; j < nn; ++j) {
            char a = tolower((unsigned char)hay[i+j]);
            char b = tolower((unsigned char)needle[j]);
            if (a != b) break;
        }
        if (j == nn) return 1;
    }
    return 0;
}

static const char *detect_file_type(const unsigned char *buf, size_t n) {
    if (n >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') return "ELF";
    if (n >= 2 && buf[0] == 'M' && buf[1] == 'Z') return "PE (Windows .exe / .dll)";
    if (n >= 4) {
        if ((buf[0]==0xfe && buf[1]==0xed && buf[2]==0xfa && (buf[3]==0xce || buf[3]==0xcf)) ||
            (buf[0]==0xcf && buf[1]==0xfa && buf[2]==0xed && (buf[3]==0xfe || buf[3]==0xce))) return "Mach-O";
    }
    return "Unknown/Other";
}

static void scan_for_indicators(const unsigned char *buf, size_t n, char **strings, size_t s_count,
                                size_t *out_suspicious_hits, size_t *out_url_hits, int *out_upx,
                                size_t *out_keyword_hits) {
    size_t suspicious_hits = 0, url_hits = 0, keyword_hits = 0;
    int upx = 0;
    if (n >= 4) {
        for (size_t i = 0; i + 4 <= n; ++i) {
            if (buf[i] == 'U' && buf[i+1] == 'P' && buf[i+2] == 'X') { upx = 1; break; }
        }
    }
    for (size_t i = 0; i < s_count; ++i) {
        const char *str = strings[i];
        if (contains_keyword_ci(str, "http://") || contains_keyword_ci(str, "https://") || contains_keyword_ci(str, "ftp://")) {
            url_hits++;
        }
        for (const char **k = suspicious_keywords; *k; ++k) {
            if (contains_keyword_ci(str, *k)) {
                keyword_hits++;
            }
        }
    }
    for (size_t i = 0; i + 4 <= n; ++i) {
        if (buf[i] == 'h' && buf[i+1] == 't' && buf[i+2] == 't' && buf[i+3] == 'p') { url_hits++; break; }
    }
    *out_suspicious_hits = suspicious_hits;
    *out_url_hits = url_hits;
    *out_upx = upx;
    *out_keyword_hits = keyword_hits;
}

static int is_executable_mode(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (st.st_mode & S_IXUSR) ? 1 : 0;
}

static int has_quarantine_xattr(const char *path, char *outval, size_t outlen) {
#ifdef __APPLE__
    ssize_t r = getxattr(path, "com.apple.quarantine", outval, outlen, 0, 0);
    if (r > 0) { outval[(size_t)r < outlen ? (size_t)r : outlen-1] = '\0'; return 1; }
    return 0;
#else
    (void)path; (void)outval; (void)outlen;
    return 0;
#endif
}

static double score_risk(const char *ftype, double entropy, size_t keyword_hits, int upx, int executable, size_t url_hits) {
    double score = 0.0;
    if (strcmp(ftype, "PE (Windows .exe / .dll)") == 0) score += 2.0;
    if (strcmp(ftype, "ELF") == 0) score += 1.5;
    if (strcmp(ftype, "Mach-O") == 0) score += 1.5;
    if (entropy > 7.0) score += 2.0;
    else if (entropy > 6.0) score += 1.0;
    score += (double)keyword_hits * 0.7;
    if (url_hits) score += 1.0;
    if (upx) score += 1.5;
    if (executable) score += 1.0;
    if (score < 0) score = 0;
    return score;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file-to-scan>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    size_t fsize = 0;
    unsigned char *buf = read_file(path, &fsize);
    if (!buf) {
        fprintf(stderr, "Failed to read file '%s': %s\n", path, strerror(errno));
        return 3;
    }
    unsigned char digest[32];
    compute_sha256(buf, fsize, digest);
    const char *ftype = detect_file_type(buf, fsize);
    double entropy = shannon_entropy(buf, fsize);
    size_t s_count = 0;
    char **strings = extract_strings(buf, fsize, &s_count);
    size_t suspicious_hits = 0, url_hits = 0, keyword_hits = 0;
    int upx = 0;
    scan_for_indicators(buf, fsize, strings, s_count, &suspicious_hits, &url_hits, &upx, &keyword_hits);
    int exec_mode = is_executable_mode(path);
    char qval[512] = {0};
    int has_quar = has_quarantine_xattr(path, qval, sizeof(qval));
    double risk = score_risk(ftype, entropy, keyword_hits, upx, exec_mode, url_hits);
    printf("=== maldet report ===\n");
    printf("File: %s\n", path);
    printf("Size: %zu bytes\n", fsize);
    printf("SHA-256: "); hexprint(digest, 32); printf("\n");
    printf("Type detector: %s\n", ftype);
    printf("Executable bit: %s\n", exec_mode ? "yes" : "no");
#ifdef __APPLE__
    if (has_quar) printf("macOS quarantine attribute: present -> %s\n", qval);
    else printf("macOS quarantine attribute: not present\n");
#endif
    printf("Shannon entropy: %.3f bits/byte (0..8)\n", entropy);
    printf("UPX-like packer marker: %s\n", upx ? "yes" : "no");
    printf("Extracted printable strings: %zu\n", s_count);
    printf("Suspicious keyword hits in strings: %zu\n", keyword_hits);
    printf("URL-like strings found: %zu\n", url_hits);
    printf("\nTop suspicious strings (first 20):\n");
    size_t shown = 0;
    for (size_t i = 0; i < s_count && shown < 20; ++i) {
        int show = 0;
        for (const char **k = suspicious_keywords; *k; ++k) {
            if (contains_keyword_ci(strings[i], *k)) { show = 1; break; }
        }
        if (!show && (contains_keyword_ci(strings[i], "http://") || contains_keyword_ci(strings[i], "https://"))) show = 1;
        if (show) { printf("  - %s\n", strings[i]); shown++; }
    }
    if (shown == 0) printf("  (none matched suspicious list)\n");
    printf("\nHeuristic risk score: %.2f (higher = more suspicious)\n", risk);
    if (risk >= 6.0) {
        printf("=> HIGH suspicion: consider sandboxing, YARA, VirusTotal, or professional analysis.\n");
    } else if (risk >= 3.0) {
        printf("=> MEDIUM suspicion: manual review recommended.\n");
    } else {
        printf("=> LOW suspicion: likely benign but not guaranteed.\n");
    }
    free_strings(strings, s_count);
    free(buf);
    return 0;
}

