#pragma once

#define TIMEOUT_MS 5000 // HTTP/1.1
#define TIMEOUT_HTTP2_MS 60000

#define CHUNK_SIZE 8192
#define MIN_TRANSMIT_FILE_SIZE 64 * 1024 // 64KB
#define WORKER_THREADS 4

#define KEEP_ALIVE 1
#define KEEP_ALIVE_MAX_CONNECTIONS 100

#define _USE_TLS
#define PFX_FILE _T(".\\localhost.pfx")
#define STATIC_PATH _T(".\\www2\\")
#define PFX_PASSWORD L"pwd1234"

#define ALLOW_HTTP2