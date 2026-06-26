#include "SnServer.h"
#include <unordered_map>
#include <algorithm>
#include <mutex>
#include <shared_mutex>

static LPCSTR ppcszMonths[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static LPCSTR ppcszDaysOfWeek[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

std::string to_utf8(const std::wstring& w) {
    if (w.empty()) 
        return {};

    int size = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), (LPSTR)result.data(), size, NULL, NULL);
    return result;
}

std::string get_mime_type(const std::wstring& wextension) {
    static std::shared_mutex mutex;
    static std::unordered_map<std::string, std::string> cache_mime_map = {
        {".html", "text/html; charset=UTF-8"},
        {".css", "text/css; charset=UTF-8"},
        {".js", "application/javascript; charset=UTF-8"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".json", "application/json; charset=UTF-8"},
        {".txt", "text/plain; charset=UTF-8"},
        {".wasm", "application/wasm"},
		{".svg", "image/svg+xml"},
        {".ico", "image/x-icon"},
		{".pdf", "application/pdf"},
		{".zip", "application/zip"},
		{".gif", "image/gif"},
		{".bmp", "image/bmp"},
		{".xml", "application/xml; charset=UTF-8"},
        {".woff", "font/woff"},
		{".woff2", "font/woff2"},
		{".ttf", "font/ttf"},
		{".eot", "application/vnd.ms-fontobject"},
		{".otf", "font/otf"},
        {".mp3", "audio/mpeg"},
        {".ogg", "audio/ogg"},
        {".wav", "audio/wav"},
		{".flac", "audio/flac"},
        {".mp4", "video/mp4"},
		{".webm", "video/webm"},
        {".avi", "video/x-msvideo"},
		{".mpeg", "video/mpeg"}
    };

    std::string ext = to_utf8(wextension);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](BYTE c) { return (CHAR)std::tolower(c); });

    {
        std::shared_lock<std::shared_mutex> lock(mutex);
        auto it = cache_mime_map.find(ext);

        if (it != cache_mime_map.end())
            return it->second;
    }

    CHAR mime[128];
	DWORD dwSize = sizeof(mime);

    if (SUCCEEDED(AssocQueryStringA(
            0,
            ASSOCSTR_CONTENTTYPE,
            ext.c_str(),
            NULL,
            mime,
            &dwSize))) {

        // add to cache
        std::unique_lock<std::shared_mutex> lock(mutex);
		cache_mime_map[ext] = mime;
        return std::string(mime);
    }

    return "application/octet-stream";
}
std::string systemtime_to_str(const SYSTEMTIME& sysTime) {
    char buffer[32];

    std::snprintf(buffer, sizeof(buffer),
        "%s, %02d %s %04d %02d:%02d:%02d GMT",
        ppcszDaysOfWeek[sysTime.wDayOfWeek],
        sysTime.wDay,
        ppcszMonths[sysTime.wMonth - 1],
        sysTime.wYear,
        sysTime.wHour,
        sysTime.wMinute,
        sysTime.wSecond);

    return buffer;
}

bool http_date_to_filetime(const std::string& str, FILETIME& ft) {
    char wkday[4], month[4];
    int day, year, hour, min, sec;

    if (std::sscanf(str.c_str(), "%3s, %d %3s %d %d:%d:%d GMT",
                    wkday, &day, month, &year, &hour, &min, &sec) != 7) {
        return false;
    }

	month[3] = '\0'; // ensure null-termination

    int monthIndex = -1;
    for (int i = 0; i < 12; ++i) {
        if (std::strncmp(month, ppcszMonths[i], 3) == 0) {
            monthIndex = i + 1;
            break;
        }
    }

    if (monthIndex == -1)
        return false;

    SYSTEMTIME st = {};
    st.wYear   = year;
    st.wMonth  = monthIndex;
    st.wDay    = day;
    st.wHour   = hour;
    st.wMinute = min;
    st.wSecond = sec;

    return SystemTimeToFileTime(&st, &ft);
}

void display_latest_err(LPCTSTR lptczDescription, INT WSAError) {
    LPTSTR err_msg = NULL;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, WSAError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&err_msg, 0, NULL);
    _tprintf(_T("[SnServer] %s %u: %s\n"), lptczDescription, WSAGetLastError(), err_msg);
    LocalFree(err_msg);
}

void display_latest_err(LPCTSTR lptczDescription) {
    display_latest_err(lptczDescription, WSAGetLastError());
}

DWORD handle_single_client(SnServer& server, SOCKET clientSock) {
	std::vector<char> requestBuffer;
	CHAR temp[4096];

	DWORD dwTimeout = TIMEOUT_MS;
	setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwTimeout, sizeof(dwTimeout));

	while (1) {
		requestBuffer.clear();

		INT n = recv(clientSock, temp, sizeof(temp), 0);

		if (!n)
			goto close_and_ret1;

		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() != WSAETIMEDOUT)
				display_latest_err(_T("recv failed"));
			else
				printf("[SnServer] Timed out, closing connection to client\n");
		close_and_ret1:
			closesocket(clientSock);
			return 1;
		}

		requestBuffer.insert(requestBuffer.end(), temp, temp + n);

		Request rq(requestBuffer);

		Response response = server.process_request(rq, clientSock);
		std::vector<BYTE> http_reply = response.construct_http_reply();

		printf("[SnServer] %s %s %hu\n", rq.method.c_str(), rq.path.c_str(), response.wStatus);
			
		BOOL bCloseConnection = rq.headers["Connection"] == "close";

		if (bCloseConnection)
			response.headers["Connection"] = "close";
		else {
			response.headers["Connection"] = "keep-alive";
			response.headers["Keep-Alive"] = server.keep_alive_val;
			printf("[SnServer] Keeping connection alive\n");
		}

		//if (!response.send_response())
		//	printf("[SnServer] Failed to send response to client\n");

		if (bCloseConnection) {
			printf("[SnServer] Closing connection to client on request\n");
			break;
		}
	/*
	size_t totalSent = 0;
	while (totalSent < http_reply.size()) {
		int sent = send(clientSock, (const char*)http_reply.data() + totalSent,
			static_cast<int>(http_reply.size() - totalSent), 0);
		if (sent == SOCKET_ERROR) {
			display_latest_err(_T("Failed to send HTTP reply"));
			break;
		}
		totalSent += sent;
	}*/
	}

	closesocket(clientSock);
	return 0;
}

#ifdef _USE_TLS
BOOL CryptEncrypt(PVOID pvIo, const BYTE* pbContent, DWORD* dwContentSize, std::vector<BYTE>* pvRes) {
    PER_IO_OPERATION_DATA* pIo = (PER_IO_OPERATION_DATA*)pvIo;
    SecPkgContext_StreamSizes scSizes;
    SECURITY_STATUS status;
    SecBufferDesc sbDesc;
    SecBuffer sb[4];

    QueryContextAttributes(&pIo->hContext, SECPKG_ATTR_STREAM_SIZES, &scSizes);

    DWORD dwTotalSz = scSizes.cbHeader + *dwContentSize + scSizes.cbTrailer;
    std::vector<BYTE> vbOut(dwTotalSz);

    sb[0].BufferType = SECBUFFER_STREAM_HEADER;
    sb[0].pvBuffer = vbOut.data();
    sb[0].cbBuffer = scSizes.cbHeader;

    sb[1].BufferType = SECBUFFER_DATA;
    sb[1].pvBuffer = vbOut.data() + scSizes.cbHeader;
    sb[1].cbBuffer = *dwContentSize;
    memcpy(sb[1].pvBuffer, pbContent, *dwContentSize);

    sb[2].BufferType = SECBUFFER_STREAM_TRAILER;
    sb[2].pvBuffer = vbOut.data() + scSizes.cbHeader + *dwContentSize;
    sb[2].cbBuffer = scSizes.cbTrailer;

    sb[3].BufferType = SECBUFFER_EMPTY;
    sb[3].cbBuffer = 0;
    sb[3].pvBuffer = NULL;

    sbDesc.cBuffers = 4;
    sbDesc.pBuffers = sb;
    sbDesc.ulVersion = SECBUFFER_VERSION;

    // 0x80090329
    
    status = EncryptMessage(&pIo->hContext, 0, &sbDesc, 0);
    if (status != SEC_E_OK) {
        printf("[SnServer] EncryptMessage failed: 0x%08lx\n", status);
        return -1;
    }

    *dwContentSize = sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer;

    *pvRes = vbOut;
    return TRUE;
}
#endif

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HANDLE hIocp = (HANDLE)lpParam;
    DWORD bytesTransferred;
    ULONG_PTR key;
    OVERLAPPED* overlapped;
    DWORD dwFlags;
    BOOL bRes;
    BOOL bRequestHasBody;

    while (1) {
        BOOL success = GetQueuedCompletionStatus(
            hIocp, &bytesTransferred, &key, &overlapped, INFINITE
        );

        PER_IO_OPERATION_DATA* ioData = (PER_IO_OPERATION_DATA*)overlapped;
        SOCKET sock = ioData->sock;

        if (!(success && bytesTransferred))
            goto next_close;

		ioData->dwLastActivityTick = GetTickCount();

    #ifdef _USE_TLS
        // Handle TLS handshake
        if (ioData->server->crypt.bReady && !ioData->bTlsHandshakeCompleted) {
            // TLS handshake is pending
            ioData->tlsBuffer.insert(ioData->tlsBuffer.end(), (PCHAR)ioData->buffer,
                                     (PCHAR)ioData->buffer + bytesTransferred);
            bRes = ioData->server->HandleTLSHandshake(ioData);
            if (bRes == 1) {
                ioData->bTlsHandshakeCompleted = TRUE;
                ioData->tlsBuffer.clear();
            } else if (bRes == -1) {
                printf("[SnServer] TLS handshake error, closing\n");
                goto next_close;
            }

            ioData->tlsBuffer.clear();
            goto _next_recv;
        }
    #endif
       
        { 
        #ifdef _USE_TLS
            if ( ioData->server->crypt.bReady ) {
                ioData->tlsBuffer.insert(ioData->tlsBuffer.end(), (PCHAR)ioData->buffer,
                                         (PCHAR)ioData->buffer + bytesTransferred);
                do {
                    bRes = ioData->server->CryptDecrypt(ioData);

                    if (!bRes && ioData->requestBuffer.empty())
                        goto _next_recv;
                    else if (bRes == -1) {
                        printf("[SnServer] Decryption error, closing\n");
                        goto next_close;
                    }

                } while (bRes);
            } else
                ioData->requestBuffer.insert(ioData->requestBuffer.end(), (PCHAR)ioData->buffer,
                                             (PCHAR)ioData->buffer + bytesTransferred);

            #define sendResponse() (response.send_response(ioData, ioData->server->crypt.bReady))
            
        #else
            ioData->requestBuffer.insert(ioData->requestBuffer.end(), (PCHAR)ioData->buffer,
                                         (PCHAR)ioData->buffer + bytesTransferred);
            #define sendResponse() (response.send_response())
        #endif
            BOOL bCloseConnection = FALSE;

            if (ioData->ProtocolType == SNSRV_PROTOCOL_HTTP1_1) {
            process_http1_loop:
                if (ioData->requestBuffer.empty())
                    goto _next_recv;

                Request rq(ioData->requestBuffer);

                if (!rq.bHeadersComplete) {
                    if (ioData->requestBuffer.size() > 8192) {
                        printf("[SnServer] HTTP/1.1 headers too large, closing\n");
                        goto next_close;
                    }
                    goto _next_recv;
                }

                if (!rq.IsComplete(ioData->requestBuffer))
                    goto _next_recv;
                Response response = ioData->server->process_request(rq, sock);
                std::vector<BYTE> http_reply = response.construct_http_reply();
                auto allowedMethods = ioData->server->allowedMethods;

			    if (std::find(allowedMethods.begin(), allowedMethods.end(), rq.method) == allowedMethods.end()) {
				    response = Response(405, "Method Not Allowed", sock);
				    if (!sendResponse()) {
					    printf("[SnServer] Failed to send response to client\n");
					    goto next_close;
				    }
				    printf("[SnServer] %s %s %hu (Method Not Allowed)\n", rq.method.c_str(), rq.path.c_str(), response.wStatus);
				    goto next_close;
			    }

                printf("[SnServer] %s %s %hu\n", rq.method.c_str(), rq.path.c_str(), response.wStatus);

                bCloseConnection = rq.headers["Connection"] == "close";

                if (bCloseConnection)
                    response.headers["Connection"] = "close";
                else {
                    response.headers["Connection"] = "keep-alive";
                    response.headers["Keep-Alive"] = ioData->server->keep_alive_val;
                    printf("[SnServer] Keeping connection alive\n");
                }

                if (!sendResponse()) {
                    printf("[SnServer] Failed to send response to client\n");
                    goto next_close;
                }

                if (bCloseConnection) {
                    printf("[SnServer] Closing connection to client on request\n");
                    goto next_close;
                }

                ioData->requestBuffer.erase(
                    ioData->requestBuffer.begin(),
                    ioData->requestBuffer.begin() + rq.headerEnd + rq.dwContentLength
                );

                if (!ioData->requestBuffer.empty())
                    goto process_http1_loop;
            } 
            else if (ioData->ProtocolType == SNSRV_PROTOCOL_HTTP2) {
                // HTTP2 request

                if (!ioData->http2Client) {
                    printf("[SnServer] [H2] Err ioData->http2Client=NULL\n");
                    goto next_close;
                }

                if ( !ioData->http2Client->bHTTP2FirstRequestAfterHandshake )
                    goto non_first;

                // First HTTP2 receivement after handshake, must be signature
                
                {
                    LPCSTR HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    const DWORD PREFACE_LEN = 24;

                    if (ioData->requestBuffer.size() < PREFACE_LEN)
                        goto _next_recv;

                    ioData->http2Client->bHTTP2FirstRequestAfterHandshake = FALSE;

                    if (memcmp(ioData->requestBuffer.data(), HTTP2_PREFACE, PREFACE_LEN)) {
                        printf("[SnServer] HTTP2 Protocol Error: Invalid Preface\n");
                        goto next_close;
                    }

                    std::map<SnSrvHttp2SettingId, DWORD> settings = SnSrvHTTP2GetDefaultSettings();
                    std::vector<BYTE> vbSettingsFrame = SnSrvHTTP2CreateSettingsFrame(settings, FALSE);
                    Response response(vbSettingsFrame, sock);

                    if (!sendResponse()) {
                        printf("[SnServer] [H2] Failed to send settings to client\n");
                        goto next_close;
                    }

                    printf("[SnServer] Sent SETTINGS to client\n");

                    ioData->requestBuffer.erase(
                        ioData->requestBuffer.begin(),
                        ioData->requestBuffer.begin() + PREFACE_LEN
                    );

                    goto non_first;
                }

                non_first: {
                    DWORD dwBytesToRemove, dwGoAwayErrCode;

                    while (1) {
                        Http2Frame frame(ioData->requestBuffer, 0);

                        if (!frame.bReceivedEnough) {
                            break;
                        }

                        if (frame.dwLength > ioData->http2Client->clientSettings.dwMaxFrameSize) {
                            printf("Too big frame 2 (> %u)\n", ioData->http2Client->clientSettings.dwMaxFrameSize);
                            goto goaway_framesize_error;
                        }

                        if (frame.dwStreamId && ioData->http2Client->GoAway.bReceived &&
                            frame.dwStreamId > ioData->http2Client->GoAway.goAwayFrame.dwLastStreamId) {
							Http2RstStreamFrame responseFrame(frame.dwStreamId, GOAWAY_ERROR_REFUSED_STREAM);
							Response response(responseFrame.to_bytes(), sock);

                            if (!sendResponse()) {
                                printf("[SnServer] [H2] Failed to send RST_STREAM for refused stream\n");
                                goto goaway_internal_error;
                            }

							printf("[SnServer] Refused stream %u as it's higher than last stream ID in GOAWAY\n", frame.dwStreamId);
                            goto next_frame;
                        }

                        if (frame.dwStreamId > ioData->http2Client->dwHighestStreamId)
                            ioData->http2Client->dwHighestStreamId = frame.dwStreamId;

                        if (frame.dwStreamId && frame.dwStreamId % 2 == 0) {
                            printf("[SnServer] [H2] Err: Client initiated stream with even stream ID %u\n", frame.dwStreamId);
                            goto goaway_protocol_error;
						}


                        switch (frame.bType) {
                            case FRAME_TYPE_SETTINGS: { // SETTINGS
                                if (frame.is_ack()) {
                                    if (frame.dwLength) {
										printf("[SnServer] [H2] Err: SETTINGS ACK with non-zero length\n");
                                        goto goaway_framesize_error;
                                    }

                                    printf("[SnServer] Recieved SETTINGS ack\n");
                                    break;
                                }

                                printf("[SnServer] Recieved SETTINGS\n");

                                dwGoAwayErrCode = ioData->http2Client->clientSettings.UpdateFromFrame(frame);

                                if (dwGoAwayErrCode != GOAWAY_ERROR_NO_ERROR) {
                                    printf("[SnServer] [H2] Err: Received faulty SETTINGS (0x%x)\n", dwGoAwayErrCode);
                                    goto _goaway;
                                }

                                printf("[SnServer] Client settings: %s\n", 
                                    ioData->http2Client->clientSettings.to_string().c_str());

                                Response response = SnSrvHTTP2CreateAckMsg(sock);
                                if (!sendResponse()) {
                                    printf("[SnServer] [H2] Failed to send settings ACK to client\n");
                                    goto goaway_internal_error;
                                }
                                break;
                            }

                            case FRAME_TYPE_WINDOW_UPDATE: { // WINDOW_UPDATE
                                printf("[SnServer] Received WINDOW_UPDATE\n");
                                if (frame.dwLength != 4) {
                                    printf("[SnServer] [H2] FRAME_SIZE_ERROR: WINDOW_UPDATE length!=4 (%d)\n", frame.dwLength);
                                    goto goaway_framesize_error;
                                }

                                DWORD dwIncrement = ntohl(*(PDWORD)frame.pvPayload.data());

                                if (!dwIncrement) {
                                    printf("[SnServer] [H2] PROTOCOL_ERROR: WINDOW_UPDATE increment is 0\n");
                                    if (!frame.dwStreamId)
                                        goto goaway_protocol_error;
                                    else
                                        goto rst_protocol_error;
                                }

                                if (!frame.dwStreamId) {
                                    if ((MAXDWORD - ioData->http2Client->clientSettings.server.dwMaxWindowSize) <= dwIncrement) {
                                        printf("[SnServer] [H2] FLOW_CONTROL_ERROR: Connection window size overflow\n");
										goto goaway_flowcontrol_error;
                                    }

                                    ioData->http2Client->clientSettings.server.dwMaxWindowSize += dwIncrement;
                                    printf("[SnServer] Connection window increased by %u, new=%u\n", 
                                            dwIncrement, ioData->http2Client->clientSettings.server.dwMaxWindowSize);
                                } else {
                                    DWORD dwCurrentSize = ioData->http2Client->GetStreamWindowSize(frame.dwStreamId);
                                    if ((MAXDWORD - dwCurrentSize) <= dwIncrement) {
                                        printf("[SnServer] [H2] FLOW_CONTROL_ERROR: Stream window size overflow\n");
                                        goto rst_flowcontrol_error;
                                    }

                                    ioData->http2Client->streamWindowSizes[frame.dwStreamId] = dwCurrentSize + dwIncrement;
                                    printf("[SnServer] Stream %u window increased by %u, new=%u\n", 
                                            frame.dwStreamId, dwIncrement, dwCurrentSize + dwIncrement);
                                }

                                break;
                            }

                            case FRAME_TYPE_PING: { // PING
                                printf("[SnServer] Received PING\n");

                                if (frame.dwStreamId != 0) {
                                    printf("[SnServer] [H2] Err: PING on stream %u\n", frame.dwStreamId);
                                    goto goaway_protocol_error;
                                }

                                if (frame.dwLength != 8) {
                                    printf("[SnServer] [H2] Err: PING length!=8 %u\n", frame.dwLength);
                                    goto goaway_framesize_error;
                                }

                                BOOL bAck = frame.is_ack();
                                if (!bAck) {
                                    Response response(Http2Frame(0, FRAME_TYPE_PING, FRAME_FLAG_ACK, frame.pvPayload).to_bytes(), sock);
                                    if (!sendResponse()) {
                                        printf("[SnServer] [H2] Failed to send ping ACK to client\n");
                                        goto goaway_internal_error;
                                    }
                                    break;
                                } else {
                                   // Ping that we sent
                                    printf("[SnServer] Received PING ACK from client\n");
                                }

                                break;
                            }

                            case FRAME_TYPE_STREAM_RST: {
                                Http2RstStreamFrame rstFrame(frame);

                                if (!rstFrame.dwStreamId) {
									printf("[SnServer] [H2] Err: RST_STREAM with stream ID 0\n");
                                    goto goaway_protocol_error; // RST_STREAM with stream ID 0
                                }

                                if (rstFrame.dwLength % 4) {
                                    printf("[SnServer] [H2] Err: RST_STREAM with invalid length %u\n", frame.dwLength);
									goto rst_framesize_error;
                                }

                                rstFrame.ResetStream(ioData->http2Client);
                                break;
                            }

                            case FRAME_TYPE_DATA: {
                                if (!ioData->http2Client->BodyPendingRequest(frame.dwStreamId, frame.pvPayload)) {
                                    if (std::find(ioData->http2Client->dwIgnoredBodiesStreams.begin(), ioData->http2Client->dwIgnoredBodiesStreams.end(), frame.dwStreamId) 
                                            == ioData->http2Client->dwIgnoredBodiesStreams.end()) {
                                        printf("[SnServer] [H2] Err: Received DATA frame for stream %u with no pending body\n", frame.dwStreamId);
                                        goto goaway_protocol_error;
                                    } else {
                                        printf("[SnServer] [H2] Ignoring DATA frame for stream %u with no pending body\n", frame.dwStreamId);
										goto next_frame;
                                    }
                                }

								RECEIVED_STREAM_DATA* streamData = &ioData->http2Client->receivedHeadersMap[frame.dwStreamId];
                                printf("Received body part at stream %u, EOS=%d\n", frame.dwStreamId, frame.is_end_of_stream());
                                ioData->http2Client->receivedHeadersMap[frame.dwStreamId].dwBodyBytesReceived += frame.dwLength;

                                if (streamData->dwPromisedBodySize &&
                                    streamData->dwBodyBytesReceived > streamData->dwPromisedBodySize) {
                                    printf("[SnServer] [H2] Err: Received more body data than Content-Length specified\n");
                                    goto rst_protocol_error;
								}

                                if (frame.is_end_of_stream()) {
                                    bRequestHasBody = TRUE;

                                    if (streamData->dwPromisedBodySize &&
                                        streamData->dwBodyBytesReceived != streamData->dwPromisedBodySize) {
                                        printf("[SnServer] [H2] Err: End of stream received but body size doesn't match Content-Length\n");
                                        goto rst_protocol_error;
									}
                                    goto handle_request;
                                }

                                ioData->http2Client->dwConsumed += frame.dwLength;
                                ioData->http2Client->streamConsumed[frame.dwStreamId] += frame.dwLength;

                                if (ioData->http2Client->dwConsumed >= (65535 / 2)) {
                                    printf("Sending Connection WINDOW UPDATE\n");
                                    Http2WindowUpdateFrame update0(0, ioData->http2Client->dwConsumed);
                                    Response response(update0.to_bytes(), sock);
                                    if (!sendResponse()) {
                                        printf("[SnServer] [H2] Failed to send Window Frame Update to client\n");
                                        goto goaway_internal_error;
                                    }
                                    ioData->http2Client->dwConsumed = 0;
                                }

                                if (ioData->http2Client->streamConsumed[frame.dwStreamId] >= (65535 / 2)) {
                                    printf("Sending Stream %u WINDOW UPDATE\n", frame.dwStreamId);
                                    Http2WindowUpdateFrame update(frame.dwStreamId, ioData->http2Client->streamConsumed[frame.dwStreamId]);
                                    Response response(update.to_bytes(), sock);
                                    if (!sendResponse()) {
                                        printf("[SnServer] [H2] Failed to send Stream Window Frame Update to client\n");
                                        goto goaway_internal_error;
                                    }
                                    ioData->http2Client->streamConsumed[frame.dwStreamId] = 0;
                                }

                                break;
                            }

                            case FRAME_TYPE_PRIORITY: {
                                printf("[SnServer] Recieved PRIORITY\n");

                                if (ioData->http2Client->dwWaitingForContinuationStreamId) {
                                    printf("[SnServer] [H2] Err: Received PRIORITY frame while waiting for CONTINUATION for stream %u\n",
                                        ioData->http2Client->dwWaitingForContinuationStreamId);
                                    goto goaway_protocol_error;
								}

                                Http2PriorityFrame priorityFrame(frame);

                                if (priorityFrame.bMalformed) {
                                    printf("[SnServer] [H2] Err: Malformed PRIORITY frame\n");
									goto goaway_protocol_error;
                                }

                                if (priorityFrame.dwStreamId == 0) {
									printf("[SnServer] [H2] Err: PRIORITY frame with stream ID 0\n");
                                    goto goaway_protocol_error;
								}

                                if (priorityFrame.dwLength % 5) {
                                    printf("[SnServer] [H2] Err: PRIORITY frame with invalid length %u\n", frame.dwLength);
									goto rst_framesize_error;
                                }

                                if (priorityFrame.bExclusive)
                                    printf("[SnServer] [H2] PRIORITY: Stream %u depends exclusively on stream %u with weight %u\n",
                                        priorityFrame.dwStreamId, priorityFrame.dwStreamDependency, priorityFrame.bWeight);
                                else
                                    printf("[SnServer] [H2] PRIORITY: Stream %u depends on stream %u with weight %u\n",
                                        priorityFrame.dwStreamId, priorityFrame.dwStreamDependency, priorityFrame.bWeight);

                                break;
                            }


                            case FRAME_TYPE_PUSH_PROMISE:
                                printf("[SnServer] [H2] Err: Recieved PUSH_PROMISE\n");
                                goto goaway_protocol_error;

                            case FRAME_TYPE_GOAWAY: {
                                printf("[SnServer] Recieved GOAWAY\n");
                                Http2GoAwayFrame goAway(frame);
                                printf("[SnServer] GOAWAY: Last Stream ID=%u, Error Code=%u\n",
                                    goAway.dwLastStreamId, goAway.dwErrorCode);
                                ioData->http2Client->HandleGoAway(goAway);
                                goto next_close;
                            }
                            
                            case FRAME_TYPE_CONTINUATION:
                                printf("[SnServer] Recieved CONTINUATION\n");

								if (ioData->http2Client->dwWaitingForContinuationStreamId &&
                                    ioData->http2Client->dwWaitingForContinuationStreamId != frame.dwStreamId) {
                                    printf("[SnServer] [H2] Err: CONTINUATION frame for stream %u while waiting for stream %u\n",
                                        frame.dwStreamId, ioData->http2Client->dwWaitingForContinuationStreamId);
                                    goto goaway_protocol_error;
								}

                                if (ioData->http2Client->receivedHeadersMap.find(frame.dwStreamId) 
                                    == ioData->http2Client->receivedHeadersMap.end()) {
									printf("[SnServer] [H2] Err: CONTINUATION frame with no matching stream ID in received headers map\n");
									goto goaway_protocol_error;
                                }

                                goto skip_print;
                            case FRAME_TYPE_HEADERS: { // HEADERS
                                printf("[SnServer] Recieved HEADERS\n");

                                if (ioData->http2Client->dwWaitingForContinuationStreamId &&
                                    ioData->http2Client->dwWaitingForContinuationStreamId != frame.dwStreamId) {
                                    printf("[SnServer] [H2] Err: CONTINUATION frame for stream %u while waiting for stream %u\n",
                                        frame.dwStreamId, ioData->http2Client->dwWaitingForContinuationStreamId);
                                    goto goaway_protocol_error;
                                }

                                if (ioData->http2Client->receivedHeadersMap.find(frame.dwStreamId)
                                    != ioData->http2Client->receivedHeadersMap.end()) {
                                    // Trailers received
                                    
                                    if (!frame.is_end_of_stream()) {
                                        printf("[SnServer] [H2] Err: Received HEADERS frame for trailers without END_STREAM flag\n");
                                        goto goaway_protocol_error;
									}

                                    printf("[SnServer] Received trailers header for stream %u\n", frame.dwStreamId);
                                    Http2HeadersFrame trailers;
									BOOL bRes = trailers.receive_headers_part(frame, ioData->http2Client);
                                    if (!bRes) {
                                        printf("[SnServer] [H2] Err: Malformed headers in trailers HEADERS frame\n");
                                        goto goaway_protocol_error;
                                    }
                                    if (!trailers.is_end_of_stream()) {
                                        printf("[SnServer] [H2] Err: END_STREAM flag not set in trailers HEADERS frame\n");
                                        goto goaway_protocol_error;
                                    }
                                    bRes = ioData->http2Client->receivedHeadersMap[frame.dwStreamId].headers.headers.add_headers(
                                        trailers.headers
                                    );

                                    if (!bRes) {
                                        printf("[SnServer] [H2] Err: Malformed headers in trailers HEADERS frame\n");
                                        ioData->http2Client->receivedHeadersMap.erase(frame.dwStreamId);
                                        goto goaway_protocol_error;
                                    }

									goto handle_request;
                                }

                                if (!frame.dwStreamId)
                                    goto goaway_protocol_error;

                                if (ioData->http2Client->dwBurstActiveStreams >= 100) {
                                    printf("[SnServer] [H2] Err: Client exceeded server's MAX_CONCURRENT_STREAMS limit\n");
                                    goto goaway_protocol_error;
                                }
                                ioData->http2Client->dwBurstActiveStreams++;

                                ioData->http2Client->receivedHeadersMap[frame.dwStreamId] = {
                                    Http2HeadersFrame(),
                                    0, 0
                                };

								ioData->http2Client->receivedHeadersMap[frame.dwStreamId].headers.dwStreamId = frame.dwStreamId;


                            skip_print:

                                if (!frame.dwStreamId)
                                    goto goaway_protocol_error;

								RECEIVED_STREAM_DATA* streamData = &ioData->http2Client->receivedHeadersMap[frame.dwStreamId];

                                BOOL bRes = streamData->headers.receive_headers_part(frame, ioData->http2Client);

                                if (!bRes) {
									ioData->http2Client->dwWaitingForContinuationStreamId = frame.dwStreamId;
                                    goto next_frame;
                                }

                                else if (bRes < 0) {
									dwGoAwayErrCode = -bRes;
									printf("[SnServer] [H2] Err: Malformed headers in HEADERS frame\n");
									ioData->http2Client->receivedHeadersMap.erase(frame.dwStreamId);
                                    goto _goaway;
                                }

                                if (streamData->headers.is_end_of_stream()) {
                                    bRequestHasBody = FALSE;
                                    goto handle_request;
                                }
                                
                                // body is coming
                                // TODO: Check if we need a body for this specific request

								BOOL bNeedBody = ioData->server->has_route(streamData->headers.headers[":method"],
                                                                           streamData->headers.headers[":path"]);

                                if (!bNeedBody) {
                                    ioData->http2Client->dwIgnoredBodiesStreams.insert(
                                        ioData->http2Client->dwIgnoredBodiesStreams.end(), frame.dwStreamId);
									Http2RstStreamFrame rstFrame(frame.dwStreamId, GOAWAY_ERROR_CANCEL);
									Response response(rstFrame.to_bytes(), sock);
									printf("[SnServer] Stream %u doesn't need body, sending RST_STREAM and ignoring body\n", frame.dwStreamId);
                                    if (!sendResponse()) {
                                        printf("[SnServer] [H2] Failed to send RST_STREAM for refused stream\n");
                                        goto goaway_internal_error;
									}
                                    bRequestHasBody = FALSE;
                                    goto handle_request;
								}

                                ioData->http2Client->AddPendingRequest(frame.dwStreamId, streamData->headers.headers);
                                //printf("Waiting for body at %s\n", streamData->headers.headers[":path"].c_str());
                                //printf("Stream: %u\n", frame.dwStreamId);

                                if (streamData->headers.headers.contains("content-length")) {
                                    try {
                                        DWORD dwContentLength = std::stoul(streamData->headers.headers["content-length"]);

                                        streamData->dwPromisedBodySize = dwContentLength;
                                    } catch (const std::exception& e) {
                                        printf("[SnServer] [H2] Err: Invalid Content-Length value\n");
                                        ioData->http2Client->receivedHeadersMap.erase(frame.dwStreamId);
										goto goaway_protocol_error;
                                    }
                                } else
                                    streamData->dwPromisedBodySize = 0;
                                break;
                            }

                            default:
                                printf("[SnServer] Recieved unknown frame type %0x\n", frame.bType);
                                if (ioData->http2Client->dwWaitingForContinuationStreamId) {
                                    printf("[SnServer] [H2] Err: Received unknown frame type %0x while waiting for CONTINUATION for stream %u\n",
                                        frame.bType, ioData->http2Client->dwWaitingForContinuationStreamId);
									goto goaway_protocol_error;
                                }
                                break;

                            handle_request: {
                                std::unique_ptr<Request> rq;
								ioData->http2Client->dwWaitingForContinuationStreamId = 0;

                                if (!bRequestHasBody) {
                                    HeaderMap hdrs = ioData->http2Client->receivedHeadersMap[frame.dwStreamId].headers.headers;
                                    rq = std::make_unique<Request>(hdrs[":method"], hdrs[":path"], hdrs);
									ioData->http2Client->receivedHeadersMap.erase(frame.dwStreamId);
                                } else
                                    rq = std::make_unique<Request>(
                                        ioData->http2Client->PopPendingRequest(frame.dwStreamId)
                                    );
                                printf("Sending response for %s\n", rq.get()->path.c_str());

                                BOOL bCompliant = rq.get()->headers.verify_http2();
                                if (!bCompliant) {
									printf("[SnServer] [H2] Err: Non-compliant HTTP/2 headers received\n");
                                    goto goaway_protocol_error;
                                }

                                Response resp = ioData->server->process_request(*rq.get(), sock);
                                BOOL bNoContent = (resp.body.size() == 0 && !resp.FileSendInfo.bUseFileSend);
                                
                                if (bNoContent && resp.wStatus == 200)
                                    resp.wStatus = 204;

                                resp.headers.make_http2(resp.wStatus);

                                Http2HeadersFrame responseFrame(frame.dwStreamId, resp.headers, bNoContent);
                                std::vector<BYTE> vbResponseBuffer = responseFrame.to_bytes();

                                if (!resp.FileSendInfo.bUseFileSend && !bNoContent) {
                                    ULONG64 ullRemaining = resp.body.size();
                                    DWORD dwMaxFrameSize = ioData->http2Client->clientSettings.dwMaxFrameSize;
                                    ULONG64 szIndex = 0;

                                    while (ullRemaining > 0) {
                                        DWORD dwRemaining = (DWORD)min(dwMaxFrameSize, ullRemaining);
                                        BOOL bEos = (dwRemaining == ullRemaining);
                                        Http2Frame chunkFrame(frame.dwStreamId, FRAME_TYPE_DATA, bEos ? FRAME_FLAG_END_OF_STREAM : 0);
                                        chunkFrame.dwLength = dwRemaining;
                                        chunkFrame.pvPayload = std::vector<BYTE>(resp.body.data() + szIndex, resp.body.data() + szIndex + dwRemaining);
                                        std::vector<BYTE> vbChunk = chunkFrame.to_bytes();
                                        vbResponseBuffer.insert(vbResponseBuffer.end(), vbChunk.begin(), vbChunk.end());

                                        ullRemaining -= dwRemaining;
                                        szIndex += dwRemaining;
                                    }
                                }

                                Response response(vbResponseBuffer, sock);

                                if (!sendResponse()) {
                                    printf("[SnServer] [H2] Failed to send response to client\n");
                                    goto goaway_internal_error; 
                                }

                                if (resp.FileSendInfo.bUseFileSend) {
                                    Http2DataFrame data(ioData->http2Client, frame.dwStreamId, resp.body);
                                    if (!data.send_file_response(resp)) {
                                        printf("[SnServer] [H2] Failed to send file DATA frame(s)\n");
									    goto goaway_internal_error;
                                    }
                                }
                                break;
                            }

                            goaway_flowcontrol_error:
                                dwGoAwayErrCode = GOAWAY_ERROR_FLOW_CONTROL_ERROR;
								goto _goaway;
                            goaway_refused_stream:
                                dwGoAwayErrCode = GOAWAY_ERROR_REFUSED_STREAM;
								goto _goaway;
                            goaway_framesize_error:
                                dwGoAwayErrCode = GOAWAY_ERROR_FRAME_SIZE_ERROR;
								goto _goaway;
                            goaway_protocol_error:
                                dwGoAwayErrCode = GOAWAY_ERROR_PROTOCOL_ERROR;
								goto _goaway;
                            goaway_internal_error: {
                                dwGoAwayErrCode = GOAWAY_ERROR_INTERNAL_ERROR;
                            _goaway: {
                                if (frame.bType == FRAME_TYPE_PING)
                                    goto next_close;

                                printf("[SnServer] [H2] Error 0x%x, sending GOAWAY\n", dwGoAwayErrCode);
                                Http2GoAwayFrame goAway(ioData->http2Client->dwHighestStreamId, dwGoAwayErrCode);
                                Response response(goAway.to_bytes(), sock);
                                if (!sendResponse()) {
                                    printf("[SnServer] [H2] Failed to send GOAWAY to client\n");
                                    goto next_close;
                                }

                                ioData->http2Client->HandleGoAway(goAway);
                                break;
                            }

                            rst_flowcontrol_error:
                                dwGoAwayErrCode = GOAWAY_ERROR_FLOW_CONTROL_ERROR;
                                goto _rst;
                            rst_framesize_error:
								dwGoAwayErrCode = GOAWAY_ERROR_FRAME_SIZE_ERROR;
                                goto _rst;
                            rst_protocol_error:
								dwGoAwayErrCode = GOAWAY_ERROR_PROTOCOL_ERROR;
                            _rst: {
                                Http2RstStreamFrame rst(frame.dwStreamId, dwGoAwayErrCode);
                                Response response(rst.to_bytes(), sock);
                                if (!sendResponse()) {
                                    printf("[SnServer] [H2] Failed to send RST_STREAM\n");
                                    goto goaway_internal_error;
                                }
                                printf("[SnServer] Sent RST_STREAM code 0x%X on stream %u\n", dwGoAwayErrCode, frame.dwStreamId);
                                break;
                              }
                            }
                        }

                    next_frame:
                        dwBytesToRemove = frame.bReceivedEnough ? frame.size() : frame.dwReceivedSize;
                        ioData->requestBuffer.erase(
                            ioData->requestBuffer.begin(),
                            ioData->requestBuffer.begin() + dwBytesToRemove
                        );

                        continue;
                    }
                    if (ioData->http2Client)
                        ioData->http2Client->dwBurstActiveStreams = 0;
                }
                    
            }

        }

    _next_recv:
        dwFlags = 0;
        ZeroMemory(&ioData->overlapped, sizeof(OVERLAPPED));
        
        if (WSARecv(sock, &ioData->wsaBuf, 1, NULL, &dwFlags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                printf("[SnServer] Error in WSARecv, le=%d\n", WSAGetLastError());
                goto next_close;
            }
        }
        continue;

    next_close:
        CancelIoEx((HANDLE)sock, NULL);
        closesocket(sock);

    #ifdef _USE_TLS
        if (ioData->server->crypt.bReady)
            ioData->server->CryptDeallocate(ioData);
    #endif

        if (InterlockedExchange((LONG*)&ioData->bClosed, TRUE) == TRUE)
            continue;
       
        {
            std::lock_guard<std::mutex> lock(ioData->server->g_connectionsMutex);
            auto it = std::find(ioData->server->g_activeConnections.begin(), 
                                ioData->server->g_activeConnections.end(), ioData);
            if (it != ioData->server->g_activeConnections.end())
                ioData->server->g_activeConnections.erase(it);
        }

    #ifdef ALLOW_HTTP2
        if (ioData->http2Client)
            delete ioData->http2Client;
    #endif

        delete ioData;
        continue;
    }
}

DWORD CALLBACK TimeoutHandler(LPVOID lpParam) {
    SnServer* pServer = (SnServer*)lpParam;

    while (1) {
        DWORD dwNow = GetTickCount( );
        {
            std::lock_guard<std::mutex> lock(pServer->g_connectionsMutex);

            for (auto it = pServer->g_activeConnections.begin(); it != pServer->g_activeConnections.end(); ) {
                PER_IO_OPERATION_DATA* ioData = *it;

                DWORD dwTimeout = TIMEOUT_MS;
                switch (ioData->ProtocolType) {
                    case SNSRV_PROTOCOL_HTTP1_1:
                        break;
                    case SNSRV_PROTOCOL_HTTP2:
                        dwTimeout = TIMEOUT_HTTP2_MS;
                        break;
                }


                if (((dwNow - ioData->dwLastActivityTick) > dwTimeout) && (!ioData->bClosed)) {
                    printf("[SnServer] Closing idle connection\n");
					CancelIoEx((HANDLE)ioData->sock, NULL); // this will cause the worker thread to close the socket and clean up the connection
                    closesocket(ioData->sock);
                } 
                
                it++;
            }
        }
        Sleep(1000);
    }
}

std::string gen_etag(FILETIME ftCreate, FILETIME ftWrite) {
	CHAR buf[64];
	std::snprintf(buf, sizeof(buf), "\"%08x-%08x\"", ftCreate.dwLowDateTime ^ ftWrite.dwLowDateTime, ftCreate.dwHighDateTime ^ ftWrite.dwHighDateTime);
	return std::string(buf);
}

std::string gen_etag(HANDLE hFile) {
	FILETIME ftCreate, ftWrite;
	GetFileTime(hFile, &ftCreate, NULL, &ftWrite);

	return gen_etag(ftCreate, ftWrite);
}

void display_latest_win_err(LPCTSTR lptczDescription) {
    LPTSTR err_msg = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&err_msg, 0, NULL);
    _tprintf(_T("[SnServer] %s %u: %s\n"), lptczDescription, GetLastError(), err_msg);
    LocalFree(err_msg);
}