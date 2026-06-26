#pragma once
#include "SnServer.h"

class Request {
public:
	std::string method;
	std::string path;
	std::string http_version;
	HeaderMap headers;
	std::vector<char> body;

	Request(std::string method, std::string path, HeaderMap headers) : method(method), path(path), http_version("HTTP/2"), headers(headers) {

	}

	BOOL bHeadersComplete = FALSE;
	DWORD dwContentLength = 0;
	size_t headerEnd = 0;

	Request(const std::vector<char>& requestBuffer) {
		for (size_t i = 0; i < requestBuffer.size(); i++) {
			if (i >= 3 && requestBuffer[i - 3] == '\r' && requestBuffer[i - 2] == '\n' && requestBuffer[i - 1] == '\r' && requestBuffer[i] == '\n') {
				headerEnd = i + 1;
				break;
			} else if (i >= 1 && requestBuffer[i - 1] == '\n' && requestBuffer[i] == '\n') {
				headerEnd = i + 1;
				break;
			}
		}

		if (!headerEnd) return;
		bHeadersComplete = TRUE;

		BYTE bMode = 0;
		BOOLEAN	bFirstHeaderLine = TRUE, bVal = FALSE, bAfterColon = FALSE;
		std::string currentHeaderKey, currentHeaderVal;

		for (size_t i = 0; i < headerEnd; i++) {
			CHAR c = requestBuffer[i];
			if (bMode == 3) {
				if (bFirstHeaderLine) {
					if (c == '\n' || c == '\r')
						continue;

					currentHeaderKey.clear();
					currentHeaderVal.clear();
					bFirstHeaderLine = FALSE;
					bVal = bAfterColon = FALSE;
				}

				if (bAfterColon && c == ' ')
					continue;
				else if (bAfterColon)
					bAfterColon = FALSE;
				
				if (c == ':' && !bVal) {
					bVal = TRUE;
					bAfterColon = TRUE;
					continue;
				}

				if (c == '\r' || c == '\n') {
					bFirstHeaderLine = TRUE;

					if (currentHeaderKey.length() && currentHeaderVal.length()) {
						headers[currentHeaderKey] = currentHeaderVal;
						continue;
					}
				}

				if (!bVal)
					currentHeaderKey += c;
				else
					currentHeaderVal += c;

			} else {
				if (c == ' ') {
					bMode++;
					continue;
				}

				if (!bMode)
					method += c;
				else if (bMode == 1)
					path += c;
				else
					http_version += c;

				if (c == '\r' || c == '\n' || bMode > 2) {
					bMode = 3;
					continue;
				}
			}
		}

		if (headers.contains("Content-Length")) {
			try {
				dwContentLength = std::stoul(headers["Content-Length"]);
			} catch (...) {}
		}

		if (requestBuffer.size() >= headerEnd + dwContentLength) {
			body.assign(requestBuffer.begin() + headerEnd, requestBuffer.begin() + headerEnd + dwContentLength);
		}
	}

	__forceinline BOOL IsComplete(const std::vector<char>& requestBuffer) {
		return bHeadersComplete && requestBuffer.size() >= headerEnd + dwContentLength;
	}
};