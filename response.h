#pragma once
#include "SnServer.h"

class Response {
public:
	SOCKET clientSock;

#ifdef _USE_TLS
	PER_IO_OPERATION_DATA* pIo = NULL;
	BOOL bCryptReady = FALSE;
#endif
	BOOL bRawMode = FALSE;

	BOOL send_content(const BYTE* content, DWORD dwContentSize) {

		DWORD dwSz = dwContentSize;

	#ifdef _USE_TLS
		//std::vector<BYTE> vEncryptedContent;

		if (pIo && bCryptReady) {
			// Update: Must respect TLS_MAX_RECORD_SIZE

			DWORD dwRemaining = dwContentSize;
			std::vector<BYTE> vEncryptedContentChunk;

			while (dwRemaining) {
				DWORD dwSizeToEncrypt = min(dwRemaining, TLS_MAX_RECORD_SIZE);
				dwSz = dwSizeToEncrypt;
				BOOL bRes = CryptEncrypt(pIo, content, &dwSz, &vEncryptedContentChunk);

				if (bRes == -1) {
					printf("[SnServer] CryptEncrypt failed\n");
					return FALSE;
				}

				DWORD dwTotalSent = 0;
				while (dwTotalSent < dwSz) {
					INT sent = send(clientSock, (const char*)vEncryptedContentChunk.data(), (INT)dwSz, 0);
					if (sent == SOCKET_ERROR) {
						printf("[SnServer] send failed, %d\n", WSAGetLastError());
						return FALSE;
					}
					dwTotalSent += sent;
				}

				dwRemaining -= dwSizeToEncrypt;
				content += dwSizeToEncrypt;
				vEncryptedContentChunk.clear();
				//vEncryptedContent.insert(vEncryptedContent.end(), vEncryptedContentChunk.begin(), vEncryptedContentChunk.end());
			}

			//content = vEncryptedContent.data();
			return TRUE;
		}
	#endif

		DWORD dwTotalSent = 0;
		while (dwTotalSent < dwSz) {
			int sent = send(clientSock, (const char*)content + dwTotalSent,
							static_cast<int>(dwSz - dwTotalSent), 0);
			if (sent == SOCKET_ERROR) {
				printf("[SnServer] send failed, %d\n", WSAGetLastError());
				return FALSE;
			}
			dwTotalSent += sent;
		}
		return TRUE;
	}

	struct {
		BOOL bUseFileSend = FALSE;
		SN_RANGE range = { 0, 0 };
		HANDLE hFile = INVALID_HANDLE_VALUE;
		DWORD dwFileSize = 0;
	} FileSendInfo;

	WORD wStatus;
	HeaderMap headers;
	std::vector<BYTE> body;
	std::vector<std::string> allowedMethods = {
		"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE"
	};

	Response set_client_socket(SOCKET sock) {
		clientSock = sock;
		return *this;
	}

	std::vector<BYTE> construct_headers(ULONGLONG contentLength) {
		/*
		* const headers
		*/
		SYSTEMTIME st;
		GetSystemTime(&st);

		headers["Date"] = systemtime_to_str(st);
		headers["Server"] = "SnServer";
		//headers["Connection"] = "close";

		if ( !body.size() && wStatus == 200 )
			wStatus = 204; // No Content

		std::string http_reply;
		std::ostringstream oss;
		oss << "HTTP/1.1 " << wStatus << " OK\r\n";

		for (const auto& header : headers) {
			oss << header.first << ": " << header.second << "\r\n";
		}

		if ( body.size() )
			oss << "Content-Length: " << contentLength << "\r\n";
		oss << "\r\n";

		std::vector<BYTE> reply;
		std::string header_str = oss.str();
		reply.insert(reply.end(), header_str.begin(), header_str.end());
		return reply;
	}

	std::vector<BYTE> construct_http_reply() {
		std::vector<BYTE> headers = construct_headers(body.size());
		std::vector<BYTE> reply;

		reply.insert(reply.end(), headers.begin(), headers.end());
		reply.insert(reply.end(), body.begin(), body.end());

		return reply;
	}

	BOOL send_headers(ULONGLONG contentLength) {
		std::vector<BYTE> headers = construct_headers(contentLength);
		return send_content(headers.data(), (DWORD)headers.size());
	}

	Response(WORD status, HeaderMap Headers, LPCVOID pContent, DWORD dwContentSize, SOCKET sock=NULL) : wStatus(status), headers(Headers), clientSock(sock) {
		if (pContent && dwContentSize > 0) {
			const BYTE* content_bytes = static_cast<const BYTE*>(pContent);
			body.insert(body.end(), content_bytes, content_bytes + dwContentSize);
		}
	}

	Response(WORD status, LPCSTR lpczErrorText, SOCKET sock=NULL) : wStatus(status), clientSock(sock) {
		headers["Content-Type"] = "text/html; charset=UTF-8";

		std::string html = \
			"<!DOCTYPE html>" \
			"<html>" \
			"<head><title>Error - SnServer</title></head>" \
			"<body>" \
			"<center>" \
			"<h1>Error " + std::to_string(status) + "</h1>" \
			"<h2>" + std::string(lpczErrorText) + "</h2>" \
			"<hr>" \
			"<p>SnServer</p>" \
			"</center>" \
			"</body>" \
			"</html>";

		headers["Content-Length"] = std::to_string(html.size());
		headers["Connection"] = "close";
		body.insert(body.end(), html.begin(), html.end());
	}

	Response(WORD status, HeaderMap Headers, LPCSTR lpcszContent, SOCKET sock=NULL) : Response(status, Headers, lpcszContent, (DWORD)strlen(lpcszContent), sock) {
		if (!headers.contains("Content-Type"))
			headers["Content-Type"] = "text/plain; charset=UTF-8";
		else if (headers["Content-Type"].find("charset=") == std::string::npos)
			headers["Content-Type"] += "; charset=UTF-8";
	}

	Response(WORD Status, HeaderMap _Headers, SOCKET sock=NULL) : wStatus(Status), headers(_Headers), clientSock(sock) {
		headers.erase("Content-Type");
		headers.erase("Content-Length");
	}

	Response(WORD status, HeaderMap Headers, LPCWSTR lpcszContent, SOCKET sock=NULL) : Response(status, Headers, lpcszContent, (DWORD)wcslen(lpcszContent) * 2, sock) {
		if (!headers.contains("Content-Type"))
			headers["Content-Type"] = "text/plain; charset=UTF-16";
		else if (headers["Content-Type"].find("charset=") == std::string::npos)
			headers["Content-Type"] += "; charset=UTF-16";
	}

	Response(WORD _wStatus, HeaderMap Headers, const Request& rq, HANDLE hFile, SOCKET sock) : wStatus(_wStatus), headers(Headers), clientSock(sock) {
		if (hFile != INVALID_HANDLE_VALUE) {
			headers["Accept-Ranges"] = "bytes";

			if (rq.method == "OPTIONS") {
				std::string result;

				for (size_t i = 0; i < allowedMethods.size(); ++i) {
					result += allowedMethods[i];
					if (i != allowedMethods.size() - 1)
						result += ", ";
				}

				headers["Allow"] = result;
				return;
			}

			DWORD dwFileSize = GetFileSize(hFile, NULL);
			std::wstring extension;
			WCHAR wcPath[MAX_PATH];
			BOOL bRange = FALSE;

			if (dwFileSize == INVALID_FILE_SIZE)
				goto err;

			FILETIME ftWrite, ftClient, ftCreate;
			SYSTEMTIME stWrite;
			if (GetFileTime(hFile, &ftCreate, NULL, &ftWrite)) {
				FileTimeToSystemTime(&ftWrite, &stWrite);
				headers["Last-Modified"] = systemtime_to_str(stWrite);
			}

			headers["ETag"] = gen_etag(ftCreate, ftWrite);

			SN_RANGE range;
			range.uSize = dwFileSize;
			range.uStart = 0;

			if (rq.method == "GET") {
				try {
					bRange = ((HeaderMap*)&rq.headers)->get_range(&range, dwFileSize);
				} catch (std::range_error) {
					CHAR buf[20];
					printf("[SnServer] Error in range '%s'\n", rq.headers["Range"].c_str());
					std::snprintf(buf, 20, "bytes */%u", dwFileSize);
					headers["Content-Range"] = std::string(buf);
				
					wStatus = 416;
					return;
				}
			}

			if (rq.headers.contains("If-Match")) {
				if (rq.headers["If-Match"] != headers["ETag"]) {
					wStatus = 412;
					return;
				}
			}

			if (rq.headers.contains("If-None-Match")) {
				if (rq.headers["If-None-Match"] == headers["ETag"]) {
					wStatus = (rq.method == "GET" || rq.method == "HEAD") ? 304 : 412;
					return;
				}
			}
			
			if (rq.headers.contains("If-Unmodified-Since")) {
				if (http_date_to_filetime(rq.headers["If-Unmodified-Since"], ftClient)) {
					if (CompareFileTime(&ftWrite, &ftClient) > 0) {
						wStatus = 412;
						return;
					}
				}
			}

			if ((rq.method == "GET" || rq.method == "HEAD") && rq.headers.contains("If-Modified-Since")) {
				if (http_date_to_filetime(rq.headers["If-Modified-Since"], ftClient)) {
					if (CompareFileTime(&ftWrite, &ftClient) >= 0) {
						wStatus = 304;
						return;
					}
				}
			}

			body.resize(range.uSize);

			if (rq.method == "HEAD") {
				headers["Content-Length"] = std::to_string(range.uSize);
				return;
			}

			if (bRange) {
				wStatus = 206;
				CHAR buf[64];

				std::snprintf(buf, 64,
							  "bytes %llu-%llu/%u",
							  range.uStart,
							  range.uStart + range.uSize - 1,
							  dwFileSize);

				headers["Content-Range"] = buf;
			}

			GetFinalPathNameByHandleW(hFile, wcPath, MAX_PATH, FILE_NAME_NORMALIZED);
			extension = PathFindExtensionW(wcPath);
			headers["Content-Type"] = get_mime_type(extension);

			FileSendInfo.bUseFileSend = TRUE;
			FileSendInfo.hFile = hFile;
			FileSendInfo.range = range;
			FileSendInfo.dwFileSize = dwFileSize;

			/*CloseHandle(hFile);

			if (range.uStart)
				SetFilePointer(hFile, (DWORD)range.uStart, NULL, FILE_BEGIN);

			if (!ReadFile(hFile, body.data(), (DWORD)range.uSize, &dwRead, NULL))
				goto err;
			*/
			return;

		err:
			CloseHandle(hFile);
			FileSendInfo.bUseFileSend = FALSE;
			*this = Response(500, "Failed to send response file.", clientSock);
			return;
		}
	}

	Response(SOCKET sock) : clientSock(sock) {}

	BOOL send_response(
					#ifdef _USE_TLS
						PER_IO_OPERATION_DATA* io,
						BOOL _bCryptReady
					#endif
	) {

	#ifdef _USE_TLS
		pIo = io;
		bCryptReady = _bCryptReady;
	#endif

		if (FileSendInfo.bUseFileSend) {
			if (MIN_TRANSMIT_FILE_SIZE >= FileSendInfo.range.uSize
					#ifdef _USE_TLS 
						&& !bCryptReady
					#endif
				)
				goto os_transmit;

			{ 
				send_headers(FileSendInfo.range.uSize);
				HANDLE hFile = FileSendInfo.hFile;
				DWORD dwRead;
				BYTE buffer[CHUNK_SIZE];
				ULONGLONG bytesLeft = FileSendInfo.range.uSize;
				LARGE_INTEGER liOffset;
				liOffset.QuadPart = FileSendInfo.range.uStart;

				SetFilePointerEx(hFile, liOffset, NULL, FILE_BEGIN);

				while (bytesLeft > 0) {
					DWORD toRead = (DWORD)min(bytesLeft, sizeof(buffer));
					
					if (!ReadFile(hFile, buffer, toRead, &dwRead, NULL)) {
						CloseHandle(hFile);
						return FALSE;
					}
					if (!send_content(buffer, dwRead)) {
						CloseHandle(hFile);
						return FALSE;
					}
					bytesLeft -= dwRead;
				}

				CloseHandle(hFile);
				return TRUE;
			}

			os_transmit: {
				// Transmit using TransmitFile for better performance on large files
				std::vector<BYTE> header = construct_headers(FileSendInfo.range.uSize);
				TRANSMIT_FILE_BUFFERS tfb = {};
				tfb.Head = header.data();
				tfb.HeadLength = ( DWORD )header.size();

				LARGE_INTEGER li;
				li.QuadPart = FileSendInfo.range.uStart;
				SetFilePointerEx(FileSendInfo.hFile, li, NULL, FILE_BEGIN);

				BOOL result = TransmitFile(clientSock, FileSendInfo.hFile, (DWORD)FileSendInfo.range.uSize, 0, NULL, &tfb, 0);
				
				if (!result)
					display_latest_err(_T("TransmitFile failed"));
	
				CloseHandle(FileSendInfo.hFile);
				return result;
			}
		} else if (bRawMode) {
			return send_content(body.data(), (DWORD)body.size());
		} else {
			std::vector<BYTE> http_reply = construct_http_reply();
			return send_content(http_reply.data(), (DWORD)http_reply.size());
		}
	}

	Response(WORD status, HeaderMap hdrs, std::string  str) : Response(status, hdrs, str.c_str()) { }
	Response(WORD status, HeaderMap hdrs, std::wstring str) : Response(status, hdrs, str.c_str()) { }

	Response(std::vector<BYTE> vbData, SOCKET sock) : wStatus(0), body(vbData), clientSock(sock), bRawMode(TRUE) {

	}
};