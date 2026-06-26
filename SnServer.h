#pragma once
#include "config.h"

#pragma warning(disable : 28159 6258)
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <Mswsock.h>
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <string.h>
#include <unordered_set>
#include <sstream>
#include <iostream>
#include <vector>
#include <strsafe.h>
#include <shlwapi.h>
#include <mutex>
#include <algorithm>
#include <map>
#include <string_view>

//#define SNSRV_PROTOCOL_HTTP1_1 1
//#define SNSRV_PROTOCOL_HTTP2   2

enum SnSrvProtocolType {
	SNSRV_PROTOCOL_UNSPECIFIED,
	SNSRV_PROTOCOL_HTTP1_1,
	SNSRV_PROTOCOL_HTTP2
};

#ifdef _USE_TLS
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#include <wincrypt.h>
#define SECURITY_WIN32
#include <Security.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Secur32.lib")
#endif

#ifndef __INTELLISENSE__
#define _PRIVATE private:
#define _PUBLIC public:
#else
#define _PRIVATE 
#define _PUBLIC 
#endif

#define TLS_MAX_RECORD_SIZE 16 * 1024 

std::string get_mime_type(const std::wstring& wextension);
std::string systemtime_to_str(const SYSTEMTIME& sysTime);
bool http_date_to_filetime(const std::string& str, FILETIME& ft);
void display_latest_err(LPCTSTR lptczDescription);
void display_latest_win_err(LPCTSTR lptczDescription);
DWORD CALLBACK TimeoutHandler(LPVOID lpParam);
std::string gen_etag(HANDLE hFile);
std::string gen_etag(FILETIME ftCreate, FILETIME ftWrite);
void display_latest_err(LPCTSTR lptczDescription, INT WSAError);

#ifdef _USE_TLS
BOOL CryptEncrypt(PVOID pIo, const BYTE* pbContent, DWORD* dwContentSize, std::vector<BYTE>* pvRes);
#endif

#ifdef UNICODE
#define tstring std::wstring
#else
#define tstring std::string
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Mswsock.lib")

#include <unordered_map>
#include <functional>

class Response;
class Request;
typedef std::function<Response(const Request&)> Handler;

typedef struct {
	ULONGLONG uStart;
	ULONGLONG uSize;
} SN_RANGE;

struct ci_less {
	bool operator()(const std::string& a, const std::string& b) const {
		return std::lexicographical_compare(
			a.begin(), a.end(),
			b.begin(), b.end(),
			[](unsigned char c1, unsigned char c2) { return std::tolower(c1) < std::tolower(c2); }
		);
	}
};

class HeaderMap {
public:
	std::string& operator[](const std::string& key) {
		return headers_[key]; 
	}

	const std::string& operator[](const std::string& key) const {
		auto it = headers_.find(key);
		static const std::string empty;
		return (it != headers_.end()) ? it->second : empty;
	}

	bool contains(const std::string& key) const {
		return headers_.find(key) != headers_.end();
	}

	bool erase(const std::string& key) {
		return headers_.erase(key) > 0;
	}

	void clear() {
		headers_.clear();
	}

	auto begin() { return headers_.begin(); }
	auto end() { return headers_.end(); }
	auto begin() const { return headers_.begin(); }
	auto end()   const { return headers_.end(); }

	bool get_range(SN_RANGE* pRange, DWORD dwFileSize) {
		auto range = (*this)["Range"];

		if (range.empty() || range.length() < 6)
			return false;

		if (range.substr(0, 6) != "bytes=")
			goto exc;

		range = range.substr(6);

		if (range.empty())
			goto exc;

		if (range[0] == '-') {
			range = range.substr(1);
			pRange->uSize = std::stoull(range);
			pRange->uStart = dwFileSize - pRange->uSize;
			goto check_rettrue;
			
		} else if (range[range.length() - 1] == '-') {
			range.pop_back();
			pRange->uStart = std::stoull(range);
			pRange->uSize = dwFileSize - pRange->uStart;

			if (pRange->uStart >= dwFileSize)
				goto exc;

			goto check_rettrue;
		} else {
			ULONGLONG start, end;

			if (std::sscanf(range.c_str(), "%llu-%llu", &start, &end) != 2)
				goto exc;

			if (start > end)
				goto exc;

			if (end >= dwFileSize)
				goto exc;

			pRange->uStart = start;
			pRange->uSize = end - start + 1;
			goto check_rettrue;
		}

	check_rettrue:
		if (pRange->uSize > dwFileSize) {
			exc:
				throw std::out_of_range("Range size exceeds file size");
		}

		return true;
	}

	std::string to_string() {
		std::string res;

		for (auto kv : headers_)
			res += kv.first + " = " + kv.second + '\n';

		return res;
	}

	__forceinline BOOL is_forbidden_h2(std::string_view key) {
		static const std::unordered_set<std::string_view> forbidden = {
			"connection", "keep-alive", "proxy-connection",
			"transfer-encoding", "upgrade", "te", "content-length"
		};
		return forbidden.find(key) != forbidden.end();
	}

	void make_http2(WORD wStatus) {
		HeaderMap hdrs;
		hdrs[":status"] = std::to_string(wStatus);

		for (auto kv : headers_) {
			std::string key = kv.first;
			std::transform(key.begin(), key.end(), key.begin(),
				[](BYTE c) { return std::tolower(c); });

			if (is_forbidden_h2(key))
				continue;

			hdrs[key] = kv.second;
		}

		headers_ = hdrs.headers_;
	}

	BOOL verify_http2() {
		if (!headers_[":path"].length())
			return FALSE;

		if (contains("TE")) {
			if (headers_["TE"] != "trailers")
				return FALSE;
		} else
			headers_.erase("TE");

		if (contains("connection-specific"))
			return FALSE;

		headers_.erase("connection-specific");
		return contains(":method") && contains(":scheme");
	}

	BOOL add_headers(HeaderMap& newHeaders) {
		for (auto kv : newHeaders.headers_) {
			if (contains(kv.first))
				return FALSE;

			headers_[kv.first] = kv.second;
		}
		return TRUE;
	}

private:
	std::map<std::string, std::string, ci_less> headers_;
};

#include "request.h"
class SnServer;
typedef struct {
	SnServer& server;
	SOCKET clientSock;
} HSC_PARAM;

DWORD WINAPI WorkerThread(LPVOID lpParam);

class Http2ClientObject;

typedef struct {
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	CHAR buffer[4096];
	SOCKET sock;
	SnServer* server;
	DWORD dwLastActivityTick;
	BOOL bClosed;
	//DWORD dwReferenceCount;

	SnSrvProtocolType ProtocolType;

#ifdef ALLOW_HTTP2
	Http2ClientObject* http2Client;
#endif

#ifdef _USE_TLS
	BOOL bTlsHandshakeCompleted, bFirstHandshakeReceivement;
	std::vector<char> tlsBuffer;
	CtxtHandle hContext;
#endif

	std::vector<char> requestBuffer;
} PER_IO_OPERATION_DATA;


#include "response.h"
#ifdef ALLOW_HTTP2
#include "http2.h"
#include "hpack.h"
#endif

class SnServer {
	HANDLE hWorkerThreads[WORKER_THREADS];
	HANDLE hTimeoutThread = NULL;
public:
	std::vector<PER_IO_OPERATION_DATA*> g_activeConnections;
	std::mutex g_connectionsMutex;
	CHAR keep_alive_val[32] = "\0";
	HANDLE hIocp;
	std::vector<std::string> allowedMethods = {
		"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"
	};

	std::unordered_map<std::string, std::unordered_map<std::string, Handler>> routes;

#ifdef _USE_TLS
	#include "crypt.h"
#endif

	void add_route(std::string method, const std::string& path, Handler handler) {
		routes[method][path] = handler;
	}

	BOOL has_route(std::string method, const std::string& path) {
		auto methodIt = routes.find(method);
		if (methodIt != routes.end()) {
			auto& pathMap = methodIt->second;
			return pathMap.find(path) != pathMap.end();
		}

		return FALSE;
	}

	Response process_request(const Request& rq, SOCKET clientSock) {
		HeaderMap headers;
		tstring subPath;
		LPCSTR lptczForbiddenChars = ("\\:*?\"<>|\r\n");
		DWORD dwLen = (DWORD)staticPath.length();

		auto methodIt = routes.find(rq.method);
		if (methodIt != routes.end()) {
			auto& pathMap = methodIt->second;

			auto pathIt = pathMap.find(rq.path);
			if (pathIt != pathMap.end())
				return pathIt->second(rq).set_client_socket(clientSock);
			
		}

		// Fallback to static file serving

		if (rq.path == "/" || !rq.path.length()) {
			subPath = _T("index.html");
		} else {
			tstring currentDir;

			BOOLEAN bFirst = TRUE;

			for (CHAR c : rq.path) {
				if (c == '/' && bFirst) {
					bFirst = FALSE;
					continue;
				}

				bFirst = FALSE;

				if (c == '?')
					break;

				if (c == '/') {
					if (currentDir == _T(".") || currentDir == _T(".."))
						continue;

					subPath += currentDir + _T("\\");
					currentDir.clear();
					continue;
				}
				
				if (lptczForbiddenChars && strchr(lptczForbiddenChars, c))
					return Response(400, "Bad Request: Forbidden characters in path", clientSock);
				
				currentDir += c;
			}

			if (!currentDir.empty()) {
				if (currentDir == _T(".") || currentDir == _T(".."))
					goto skip;

				subPath += currentDir;

			skip:
				if (currentDir.find(_T(".")) == std::string::npos) {
					if (subPath.back() != '\\')
						subPath += '\\';

					subPath += _T("index.html");
				}
			}

			if (!subPath.length())
				subPath = _T("index.html");
		}

		dwLen += (DWORD)subPath.length();

		if (dwLen >= (MAX_PATH - 1))
			return Response(414, "Request-URI Too Long", clientSock);

		WCHAR wcPath[MAX_PATH];
		StringCchPrintf(wcPath, MAX_PATH, L"%s%s", staticPath.c_str(), subPath.c_str());
		
		wprintf(L"[SnServer] Sending %s\n", wcPath);

		HANDLE hFile = CreateFile(wcPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
			return Response(404, "File Not Found", clientSock);
		
		//headers["Connection"] = "close";

		return Response(200, headers, rq, hFile, clientSock);
	}

	std::vector<BYTE> construct_http_reply(WORD wStatus, HeaderMap Headers, LPCVOID pContent, DWORD dwContentSize) {
		std::string http_reply;
		std::ostringstream oss;
		oss << "HTTP/1.1 " << wStatus << " OK\r\n";

		for (const auto& header : Headers) {
			oss << header.first << ": " << header.second << "\r\n";
		}

		oss << "Content-Length: " << dwContentSize << "\r\n\r\n";

		std::vector<BYTE> reply;
		std::string header_str = oss.str();
		reply.insert(reply.end(), header_str.begin(), header_str.end());

		if ( pContent ) {
			const BYTE* content_bytes = static_cast<const BYTE*>(pContent);
			reply.insert(reply.end(), content_bytes, content_bytes + dwContentSize);
		}

		return reply;
	}

	std::vector<BYTE> construct_http_reply(WORD wStatus, HeaderMap Headers, LPCSTR lpcszContent) {
		return construct_http_reply(wStatus, Headers, lpcszContent, (DWORD)strlen(lpcszContent));
	}

	SOCKET create_listen_socket() {
		SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listen_sock == INVALID_SOCKET) {
			display_latest_err(_T("Failed to create listen socket"));
			return INVALID_SOCKET;
		}
		return listen_sock;
	}

//public:
	WORD wPort;
	tstring staticPath;

	BOOL start() {
		SOCKET sock = create_listen_socket();

		if (sock == INVALID_SOCKET)
			return FALSE;

		sockaddr_in serverAddr{};
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(wPort);
		serverAddr.sin_addr.s_addr = INADDR_ANY;

		if (bind(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
			display_latest_err(_T("Failed to bind to socket"));
			closesocket(sock);
			return FALSE;
		}

		if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
			display_latest_err(_T("Failed to listen to socket"));
			closesocket(sock);
			return FALSE;
		}

		for (DWORD i = 0; i < WORKER_THREADS; i++) {
			hWorkerThreads[i] = CreateThread(NULL, 0, WorkerThread, (LPVOID)hIocp, 0, NULL);
			if (!hWorkerThreads[i]) {
				display_latest_err(_T("Failed to create worker thread"));
				// Cleanup previously created threads
				for (DWORD j = 0; j < i; j++) {
					CloseHandle(hWorkerThreads[j]);
					hWorkerThreads[j] = NULL;
				}
				CloseHandle(hIocp);
				closesocket(sock);
				return FALSE;
			}
		}

		hTimeoutThread = CreateThread(NULL, 0, TimeoutHandler, (LPVOID)this, 0, NULL);

		printf("[SnServer] Listening on port %u...\n", wPort);

		sockaddr_in clientAddr;

		while (1) {
			INT clientSize = sizeof(clientAddr);
			SOCKET clientSock = accept(sock, (sockaddr*)&clientAddr, &clientSize);
			
			if (clientSock == INVALID_SOCKET) {
				display_latest_err(_T("Accept failed"));
				continue;
			}

			//DWORD dwTimeout = TIMEOUT_MS;
			//setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwTimeout, sizeof(dwTimeout));
			CreateIoCompletionPort((HANDLE)clientSock, hIocp, 0, 0);

			PER_IO_OPERATION_DATA* pIoData = new PER_IO_OPERATION_DATA();

			//ZeroMemory(pIoData, sizeof(PER_IO_OPERATION_DATA));
			INT one = 1;
			setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));
			pIoData->server = this;
			pIoData->sock = clientSock;
			pIoData->wsaBuf.buf = pIoData->buffer;
			pIoData->wsaBuf.len = sizeof(pIoData->buffer);
			pIoData->dwLastActivityTick = GetTickCount();
			pIoData->bClosed = FALSE;
			pIoData->ProtocolType = SNSRV_PROTOCOL_UNSPECIFIED;

		#ifdef ALLOW_HTTP2
			pIoData->http2Client = NULL;
		#endif

		#ifdef _USE_TLS
			pIoData->bTlsHandshakeCompleted = FALSE;
			pIoData->bFirstHandshakeReceivement = TRUE;
			pIoData->hContext = { };
		#endif

			ZeroMemory(&pIoData->overlapped, sizeof(OVERLAPPED));

			{
				std::lock_guard<std::mutex> lock(g_connectionsMutex);
				g_activeConnections.push_back(pIoData);
			}

			DWORD dwFlags = 0;
			WSARecv(clientSock, &pIoData->wsaBuf, 1, NULL, &dwFlags, &pIoData->overlapped, NULL);
		}

		closesocket(sock);
	}

	SnServer(WORD Port=80) : wPort(Port) {
		WSADATA wsa;
		if (INT e = WSAStartup(MAKEWORD(2, 2), &wsa)) {
			display_latest_err(_T("Failed to initialize WSA"), e);
			return;
		}

		std::snprintf(keep_alive_val, sizeof(keep_alive_val), 
					  "timeout=%u, max=%u", TIMEOUT_MS / 1000, KEEP_ALIVE_MAX_CONNECTIONS);
		hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

		ZeroMemory(hWorkerThreads, sizeof(hWorkerThreads));

	#ifdef ALLOW_HTTP2
		SnHPackSetup();
	#endif

		if (!hIocp)
			display_latest_err(_T("Failed to create IOCP"));
	}

	~SnServer() {
		WSACleanup();

		if ( hIocp )
			CloseHandle(hIocp);

		if ( hTimeoutThread ) {
			TerminateThread(hTimeoutThread, 0);
			CloseHandle(hTimeoutThread);
		}

		for (DWORD i = 0; i < WORKER_THREADS; i++) {
			if (hWorkerThreads[i]) {
				TerminateThread(hWorkerThreads[i], 0);
				CloseHandle(hWorkerThreads[i]);
			}
		}

	#ifdef _USE_TLS
		CleanupCrypt( );
	#endif
	}
};