#pragma once
#include "SnServer.h"
#include "hpack.h"
#include <deque>
#include <set>

#define FRAME_TYPE_WINDOW_UPDATE 0x08
#define FRAME_TYPE_PING 0x06
#define FRAME_TYPE_SETTINGS 0x04
#define FRAME_TYPE_HEADERS 0x1
#define FRAME_TYPE_CONTINUATION 0x9
#define FRAME_TYPE_DATA 0x0
#define FRAME_TYPE_STREAM_RST 0x3
#define FRAME_TYPE_PRIORITY 0x02
#define FRAME_TYPE_PUSH_PROMISE 0x05
#define FRAME_TYPE_GOAWAY 0x07

#define FRAME_FLAG_ACK 0x1
#define FRAME_FLAG_END_OF_STREAM 0x1
#define FRAME_FLAG_END_HEADERS 0x4
#define FRAME_FLAG_PADDED 0x08
#define FRAME_FLAG_PRIORITY 0x20

#define GOAWAY_ERROR_NO_ERROR 0x0
#define GOAWAY_ERROR_PROTOCOL_ERROR 0x1
#define GOAWAY_ERROR_INTERNAL_ERROR 0x2
#define GOAWAY_ERROR_FLOW_CONTROL_ERROR 0x3
#define GOAWAY_ERROR_SETTINGS_TIMEOUT 0x4
#define GOAWAY_ERROR_STREAM_CLOSED 0x5
#define GOAWAY_ERROR_FRAME_SIZE_ERROR 0x6
#define GOAWAY_ERROR_REFUSED_STREAM 0x7
#define GOAWAY_ERROR_CANCEL 0x8
#define GOAWAY_ERROR_COMPRESSION_ERROR 0x9
#define GOAWAY_ERROR_CONNECT_ERROR 0xA
#define GOAWAY_ERROR_ENHANCE_YOUR_CALM 0xB
#define GOAWAY_ERROR_INADEQUATE_SECURITY 0xC

enum SnSrvHttp2SettingId : WORD {
    SNSRV_HEADER_TABLE_SIZE = 0x1,
    SNSRV_ENABLE_PUSH = 0x2,
    SNSRV_MAX_CONCURRENT_STREAMS = 0x3,
    SNSRV_INITIAL_WINDOW_SIZE = 0x4,
    SNSRV_MAX_FRAME_SIZE = 0x5,
    SNSRV_MAX_HEADER_LIST_SIZE = 0x6
};

class Http2Frame {
public:
    DWORD dwLength = 0;
    BYTE bType = 0;
    BYTE bFlags = 0;
    DWORD dwStreamId = 0;
    std::vector<BYTE> pvPayload;

    BOOL bReceivedEnough = FALSE;
    DWORD dwReceivedSize = 0;

    DWORD size() {
        return 9 + dwLength;
    }

    __forceinline BOOL is_ack() {
        return bFlags & FRAME_FLAG_ACK;
    }

    __forceinline BOOL is_end_of_stream() {
        return bFlags & FRAME_FLAG_END_OF_STREAM;
    }

    __forceinline BOOL is_padded() {
        return bFlags & FRAME_FLAG_PADDED;
    }

    __forceinline BOOL is_priority() {
        return bFlags & FRAME_FLAG_PRIORITY;
    }

    __forceinline BOOL is_end_hdrs() {
        return bFlags & FRAME_FLAG_END_HEADERS;
    }

    virtual void clear() {
        pvPayload.clear();
        dwLength = 0;
    }

    std::vector<BYTE> to_bytes() {
        std::vector<BYTE> vbFrame(9 + dwLength);

        vbFrame[0] = (dwLength >> 16) & 0xFF;
        vbFrame[1] = (dwLength >> 8) & 0xFF;
        vbFrame[2] = dwLength & 0xFF;

        vbFrame[3] = bType;
        vbFrame[4] = bFlags;

        vbFrame[5] = (dwStreamId >> 24) & 0x7F;
        vbFrame[6] = (dwStreamId >> 16) & 0xFF;
        vbFrame[7] = (dwStreamId >> 8) & 0xFF;
        vbFrame[8] = dwStreamId & 0xFF;

        if (dwLength > 0 && !pvPayload.empty())
            std::copy(pvPayload.begin(), pvPayload.end(), vbFrame.begin() + 9);
        
        return vbFrame;
    }

    Http2Frame(const BYTE* pbData, DWORD dwSize, DWORD dwCursor) {
        dwReceivedSize = dwSize;
        if (dwSize < (dwCursor + 9)) {
            bReceivedEnough = FALSE;
            return;
        }

        dwLength = (pbData[dwCursor + 0] << 16) | (pbData[dwCursor + 1] << 8) | pbData[dwCursor + 2];
        bType = pbData[dwCursor + 3];
        bFlags = pbData[dwCursor + 4];

        dwStreamId = ((pbData[dwCursor + 5] & 0x7F) << 24) | (pbData[dwCursor + 6] << 16)
                        | (pbData[dwCursor + 7] << 8) | (pbData[dwCursor + 8]);

        if (dwLength > 0) {
            if (dwSize >= (dwCursor + 9 + dwLength)) {
                auto start = pbData + dwCursor + 9;
                auto end = start + dwLength;
                pvPayload.assign(start, end);
                bReceivedEnough = TRUE;
            } else {
                bReceivedEnough = FALSE;
                return;
            }
        } else
            bReceivedEnough = TRUE;
    }

    // Response types
    Http2Frame(DWORD _dwStreamId, BYTE _bType, BYTE _bFlags, std::vector<BYTE> _vbPayload)
        : bReceivedEnough(TRUE), dwStreamId(_dwStreamId), bType(_bType), bFlags(_bFlags), pvPayload(_vbPayload),
           dwLength((DWORD)_vbPayload.size()) {
    }

    Http2Frame(DWORD _dwStreamId, BYTE _bType, BYTE _bFlags)
        : bReceivedEnough(TRUE), dwStreamId(_dwStreamId), bType(_bType), bFlags(_bFlags), dwLength(0) {
    }

    Http2Frame(std::vector<CHAR> vcData, DWORD _dwCursor) : Http2Frame((const BYTE*)vcData.data(), (DWORD)vcData.size(), _dwCursor) { }
    Http2Frame(std::vector<BYTE> vcData, DWORD _dwCursor) : Http2Frame((const BYTE*)vcData.data(), (DWORD)vcData.size(), _dwCursor) { }
};

std::vector<BYTE> SnSrvHTTP2CreateSettingsFrame(std::map<SnSrvHttp2SettingId, DWORD>& settings, BOOL isAck);
class Response;
Response SnSrvHTTP2CreateAckMsg(SOCKET sock);
std::map<SnSrvHttp2SettingId, DWORD> SnSrvHTTP2GetDefaultSettings();

struct Http2Settings {
    union {
        struct {
            DWORD dwHeaderTableSize;
            DWORD dwEnablePush;
            DWORD dwMaxConcurrentStreams;
            DWORD dwInitialWindowSize;
            DWORD dwMaxFrameSize;
            DWORD dwMaxHeaderListSize;
        };
        DWORD dwValues[6] = { };
    };

    struct {
        DWORD dwMaxWindowSize = 0xFFFF;
    } server;

    BOOL bFaulty = FALSE;

    std::string to_string() {
        std::string res = "Http2Settings(\n";
        LPCSTR plpcszNames[] = { "HeaderTableSize", "EnablePush", "MaxConcurrentStreams", "InitialWindowSize",
                                 "MaxFrameSize", "MaxHeaderListSize" };

        for (DWORD i = 0; i < 6; i++) {
            res += '\t' + std::string(plpcszNames[i]) + "=" + std::to_string(dwValues[i]);
            if (i != 5)
                res += ',';
            res += '\n';
        }
        res += ");";
        return res;
    }

    DWORD UpdateFromFrame(Http2Frame frame) {
        if (frame.bFlags & FRAME_FLAG_ACK) // ACK
            return GOAWAY_ERROR_NO_ERROR;

        if (frame.dwStreamId) {
            printf("[SnServer] [H2] Err: SETTINGS stream is %u (!= 0)\n", frame.dwStreamId);
            return GOAWAY_ERROR_PROTOCOL_ERROR;
        }

        if (frame.dwLength % 6 != 0) {
            printf("[SnServer] [H2] Err: SETTINGS payload size was %u\n", frame.dwLength);
            return GOAWAY_ERROR_FRAME_SIZE_ERROR; // SETTINGS with length not a multiple of 6 is FRAME_SIZE_ERROR
        }

        for (DWORD i = 0; i < frame.dwLength; i += 6) {
            WORD id = (frame.pvPayload[i] << 8) | frame.pvPayload[i + 1];
            DWORD value = (frame.pvPayload[i + 2] << 24) |
                            (frame.pvPayload[i + 3] << 16) |
                            (frame.pvPayload[i + 4] << 8) |
                            frame.pvPayload[i + 5];

            if (!id || id > 0x06) {
                printf("[SnServer] [H2] Warn: Unknown Setting (0x%02X): %lu\n", id, value);
                continue;
            }

            if (id == SNSRV_ENABLE_PUSH && value > 1) {
                printf("[SnServer] [H2] Err: SETTINGS Enable Push is not 0 or 1\n");
                return GOAWAY_ERROR_PROTOCOL_ERROR;
            }

            if (id == SNSRV_INITIAL_WINDOW_SIZE && value > 0x7FFFFFFF) {
                printf("[SnServer] [H2] Err: SETTINGS initial window size too large\n");
                return GOAWAY_ERROR_FLOW_CONTROL_ERROR;
            }

            if (id == SNSRV_MAX_FRAME_SIZE && (value < 16384 || value > 16777215)) {
                printf("[SnServer] [H2] Err: SETTINGS max frame size out of bounds (%lu)\n", value);
                return GOAWAY_ERROR_PROTOCOL_ERROR;
            }
            
            dwValues[id - 1] = value;
        }

        return GOAWAY_ERROR_NO_ERROR;
    }

    Http2Settings(std::map<SnSrvHttp2SettingId, DWORD> settingsMap) {
        for (auto& kv : settingsMap) {
            dwValues[(DWORD)kv.first - 1] = kv.second;
        }
    }

    Http2Settings() {
        dwHeaderTableSize = 4096;
        dwEnablePush = 1; 
        dwMaxConcurrentStreams = 0; // 0 usually means infinite for us initially, or server handles it
        dwInitialWindowSize = 65535;
        dwMaxFrameSize = 16384;
        dwMaxHeaderListSize = 0; 
    }
};

class Http2WindowUpdateFrame : public Http2Frame {
public:
    BOOL bMalformed = TRUE;
    DWORD dwIncrement = 0;

    Http2WindowUpdateFrame(Http2Frame frame) : Http2Frame(frame) {
        if (!bReceivedEnough || dwLength != 4 && bType != FRAME_TYPE_WINDOW_UPDATE)
            return;

        dwIncrement = ntohl(*(PDWORD)frame.pvPayload.data());
    }

    Http2WindowUpdateFrame(DWORD dwStreamId, DWORD dwIncrement) 
        : Http2Frame(dwStreamId, FRAME_TYPE_WINDOW_UPDATE, 0) {
        dwLength = 4;
        pvPayload.resize(4);
        *(PDWORD)pvPayload.data() = htonl(dwIncrement);
    }
};

class Http2ClientObject;
class Http2HeadersFrame : public Http2Frame {
public:
    HeaderMap headers;
    BOOL bStartedReceivement = FALSE;
    DWORD dwStreamDependency = 0;
    BYTE bWeight = 0;

    Http2HeadersFrame(Http2Frame frame) : Http2Frame(frame) { }

    BOOL parse_headers(Http2ClientObject* pClient) {
        if (!bReceivedEnough)
            return FALSE;

        BYTE bPadLength = 0;
        PBYTE pbData = pvPayload.data( );
        DWORD dwRemaining = (DWORD)pvPayload.size( );

        if (is_padded()) {
            bPadLength = pvPayload[0];
            pbData += 1;
            dwRemaining -= 1;
        }

        if (is_priority()) {
            DWORD dwStreamDependency = ntohl(*(PDWORD)pbData) & 0x7FFFFFFF;
            pbData += 4;

            BYTE bWeight = *pbData;
            pbData++;

            dwRemaining -= 5;
        }

        DWORD dwHPackSize = dwRemaining - bPadLength;
        PBYTE pbHPackData = pbData;

        if (dwHPackSize > dwRemaining) {
            printf("[SnServer] [H2] Err: Headers HPACK size > remaining\n");
            return -GOAWAY_ERROR_COMPRESSION_ERROR;
        }

        //printf("[SnServer] HPACK size=%u bytes, END=%u\n", dwHPackSize, is_end_hdrs());
        return SnHPackDecodeData(pbHPackData, dwHPackSize, headers, pClient);
    }

    // return -X = GOAWAY Error, 0 = Need CONTINUATION, 1 = all headers received
    BOOL receive_headers_part(Http2Frame frame, Http2ClientObject* pClient) {
        if (!frame.bReceivedEnough)
            return FALSE;

        if (!bStartedReceivement && frame.bType != FRAME_TYPE_HEADERS) {
            printf("[SnServer] [H2] Err: First header part is not FRAME_TYPE_HEADERS\n");
            return -GOAWAY_ERROR_PROTOCOL_ERROR;
        } else if (!bStartedReceivement) {
            // First header part

            dwStreamId = frame.dwStreamId;
            bFlags = frame.bFlags;


            BYTE bPadLength = 0;
            PBYTE pbData = frame.pvPayload.data();
            DWORD dwRemaining = (DWORD)frame.pvPayload.size();
            
            if (is_padded()) {
                if (dwRemaining < 1)
                    return -1;

                bPadLength = pbData[0];
                pbData += 1;
                dwRemaining -= 1;
            }

            if (is_priority()) {
                if (dwRemaining < 5) 
                    return -1;

                dwStreamDependency = ntohl(*(PDWORD)pbData) & 0x7FFFFFFF;
                pbData += 4;

                bWeight = *pbData;
                pbData++;

                dwRemaining -= 5;
            }

            if (bPadLength > dwRemaining) 
                return -GOAWAY_ERROR_PROTOCOL_ERROR;

            DWORD dwHPackSize = dwRemaining - bPadLength;
            dwLength += dwHPackSize;
            pvPayload.insert(pvPayload.end(), pbData, pbData + dwHPackSize);

        } else if (frame.bType != FRAME_TYPE_CONTINUATION) {

            if (frame.bType == FRAME_TYPE_HEADERS) {
				// Received trailers
                if (frame.dwStreamId != dwStreamId) {
                    printf("[SnServer] [H2] Err: Different streams across header parts\n");
                    return -GOAWAY_ERROR_PROTOCOL_ERROR;
                }
                if (!frame.is_end_of_stream()) {
                    printf("[SnServer] [H2] Err: Received HEADERS frame for trailers without END_STREAM flag\n");
                    return -GOAWAY_ERROR_PROTOCOL_ERROR;
                }
            } else {
                printf("[SnServer] [H2] Err: Expected continuation\n");
                return -GOAWAY_ERROR_PROTOCOL_ERROR;
            }
        } else {
            // Continuation recieved
            if (frame.dwStreamId != dwStreamId) {
                printf("[SnServer] [H2] Err: Different streams across header parts\n");
                return -GOAWAY_ERROR_PROTOCOL_ERROR;
            }

            pvPayload.insert(pvPayload.end(), frame.pvPayload.begin(), frame.pvPayload.end());
            dwLength += frame.dwLength;
        }

        if (frame.bFlags & FRAME_FLAG_END_HEADERS) {
            bFlags |= FRAME_FLAG_END_HEADERS;
            return SnHPackDecodeData(pvPayload.data(), dwLength, headers, pClient);;
        }

        bStartedReceivement = TRUE; 
        return FALSE;
    }

    void clear() {
        pvPayload.clear();
        dwLength = dwStreamDependency = 0;
        bStartedReceivement = FALSE;
        bWeight = bFlags = 0;
        headers.clear();
    }

    Http2HeadersFrame(DWORD dwStreamID, HeaderMap headers, BOOL bEndOfStream=FALSE) 
            : Http2Frame(dwStreamID, FRAME_TYPE_HEADERS, 
                        (bEndOfStream ? FRAME_FLAG_END_OF_STREAM : 0) | FRAME_FLAG_END_HEADERS) {
        pvPayload = SnHPackEncodeData(headers);
        dwLength = (DWORD)pvPayload.size( );
    }

    Http2HeadersFrame() : Http2Frame(0UL, FRAME_TYPE_HEADERS, 0) { }
};

struct HPackEntry {
    std::string name;
    std::string value;

    DWORD size() const {   // HPACK overhead
        return (DWORD)(name.length() + value.length() + 32); 
    }
};

class Http2PriorityFrame : public Http2Frame {
    void _setup_basic() {
        if (!bReceivedEnough || bType != FRAME_TYPE_PRIORITY)
            return;

        if (dwLength < 5) {
            bReceivedEnough = FALSE;
            return;
        }
        else if (dwLength > 5) {
            printf("[SnServer] [H2] Warn: Priority frame with length > 5, ignoring extra data\n");
            pvPayload.resize(5);
        }

        PBYTE pbData = pvPayload.data();

        bExclusive = (pbData[0] & 0x80) != 0;
        dwStreamDependency =
            ((pbData[0] & 0x7F) << 24) |
            (pbData[1] << 16) |
            (pbData[2] << 8) |
            (pbData[3]);

        bWeight = pbData[4];
        bMalformed = FALSE;
    }

public:
    BOOL bExclusive = FALSE;
    DWORD dwStreamDependency = 0;
    BYTE bWeight = 0; // + 1
	BOOL bMalformed = TRUE;

    Http2PriorityFrame(const BYTE* pbData, DWORD dwSize, DWORD dwCursor)
            : Http2Frame(pbData, dwSize, dwCursor) {
        _setup_basic();
    }

    Http2PriorityFrame(Http2Frame frame) : Http2Frame(frame) {
        _setup_basic();
    }
};

class Http2GoAwayFrame : public Http2Frame {
public:
    DWORD dwLastStreamId = 0;
    DWORD dwErrorCode = 0;
	std::vector<BYTE> pvDebugData;

    Http2GoAwayFrame(Http2Frame frame) : Http2Frame(frame) {
        if (!bReceivedEnough || bType != FRAME_TYPE_GOAWAY || dwLength < 8)
            return;
        dwLastStreamId = ((pvPayload[0] & 0x7F) << 24) | (pvPayload[1] << 16) | (pvPayload[2] << 8) | pvPayload[3];
        dwErrorCode = (pvPayload[4] << 24) | (pvPayload[5] << 16) | (pvPayload[6] << 8) | pvPayload[7];

        if (dwLength > 8)
            pvDebugData.assign(pvPayload.begin() + 8, pvPayload.end());
	}

    Http2GoAwayFrame(DWORD dwLastStreamId, DWORD dwErrorCode, std::vector<BYTE> debugData = {})
            : Http2Frame(0Ui32, (BYTE)FRAME_TYPE_GOAWAY, 0Ui8) {
        dwLength = 8 + (DWORD)debugData.size();
            
        pvPayload.resize(dwLength);
        pvPayload[0] = (dwLastStreamId >> 24) & 0x7F;
        pvPayload[1] = (dwLastStreamId >> 16) & 0xFF;
        pvPayload[2] = (dwLastStreamId >> 8) & 0xFF;
        pvPayload[3] = dwLastStreamId & 0xFF;
        pvPayload[4] = (dwErrorCode >> 24) & 0xFF;
        pvPayload[5] = (dwErrorCode >> 16) & 0xFF;
        pvPayload[6] = (dwErrorCode >> 8) & 0xFF;
        pvPayload[7] = dwErrorCode & 0xFF;

        if (!debugData.empty())
            std::copy(debugData.begin(), debugData.end(), pvPayload.begin() + 8);
	}

	Http2GoAwayFrame() : Http2Frame(0Ui32, (BYTE)FRAME_TYPE_GOAWAY, 0Ui8) {
		bReceivedEnough = FALSE;
    }
};

//struct PER_IO_OPERATION_DATA;
typedef struct {
    Http2HeadersFrame headers;
	DWORD dwBodyBytesReceived;
    DWORD dwPromisedBodySize;
} RECEIVED_STREAM_DATA;

class Http2ClientObject {
public:
    BOOL bHTTP2FirstRequestAfterHandshake;
    Http2Settings clientSettings;
    PER_IO_OPERATION_DATA* pIo;
    SOCKET socket;
	DWORD dwHighestStreamId = 0;
	//DWORD dwBodyBytesReceived = 0;
	//DWORD dwPromisedBodySize = 0;

	std::map<DWORD, RECEIVED_STREAM_DATA> receivedHeadersMap;
    //Http2HeadersFrame receivedHeaders;
    std::deque<HPackEntry> dynamicTable;
    DWORD currentTableSize = 0;

	DWORD dwWaitingForContinuationStreamId = 0;

    std::set<DWORD> abortedStreams;
    std::mutex abortMutex;
    std::map<DWORD, std::unique_ptr<Request>> pendingRequests;
    DWORD dwConsumed = 0;
    std::map<DWORD, DWORD> streamConsumed;
    std::map<DWORD, DWORD> streamWindowSizes;
    DWORD dwBurstActiveStreams = 0;

	std::vector<DWORD> dwIgnoredBodiesStreams;

    DWORD GetStreamWindowSize(DWORD streamId) {
        if (streamWindowSizes.find(streamId) == streamWindowSizes.end())
            return clientSettings.dwInitialWindowSize ? clientSettings.dwInitialWindowSize : 65535;
        return streamWindowSizes[streamId];
    }

    struct {
		BOOL bReceived = FALSE;
		Http2GoAwayFrame goAwayFrame;
    } GoAway;

public:
    void AbortStream(DWORD dwStreamId) {
        std::lock_guard<std::mutex> lock(abortMutex);
        abortedStreams.insert(dwStreamId);
    }

    __forceinline BOOL IsStreamAborted(DWORD dwStreamId) {
        if (GoAway.bReceived && dwStreamId > GoAway.goAwayFrame.dwLastStreamId)
			return TRUE;

        std::lock_guard<std::mutex> lock(abortMutex);
        return abortedStreams.find(dwStreamId) != abortedStreams.end();
    }

    void ClearStream(DWORD dwStreamId) {
        std::lock_guard<std::mutex> lock(abortMutex);
        abortedStreams.erase(dwStreamId);
    }

    __forceinline DWORD dynamicTableMaxSize() {
        //if (clientSettings.dwMaxHeaderListSize)
        return 4096; // TODO
    }

    void AddToDynamicTable(const std::string& name, const std::string& value) {
        size_t entrySize = name.length() + value.length() + 32;

        while (currentTableSize + entrySize > dynamicTableMaxSize() && !dynamicTable.empty()) {
            currentTableSize -= dynamicTable.back().size();
            dynamicTable.pop_back();
        }

        if (entrySize <= dynamicTableMaxSize()) {
            dynamicTable.push_front({ name, value });
            currentTableSize += (DWORD)entrySize;
        }
    }

    void AddPendingRequest(DWORD dwStreamId, HeaderMap hdrs) {
        printf("AddPendingRequest for %u\n", dwStreamId);
        pendingRequests[dwStreamId] = std::make_unique<Request>(Request(hdrs[":method"], hdrs[":path"], hdrs));
    }

    BOOL BodyPendingRequest(DWORD dwStreamId, std::vector<BYTE>& vbBodyPart) {
        if (pendingRequests.find(dwStreamId) == pendingRequests.end()) {
            printf("[SnServer] [h2] Err: Invalid stream ID in data frame\n");
            return FALSE;
        }

        pendingRequests[dwStreamId].get()->body.insert(
            pendingRequests[dwStreamId].get()->body.end(),
            vbBodyPart.data(), vbBodyPart.data() + vbBodyPart.size()
        );
        return TRUE;
    }

    Request PopPendingRequest(DWORD dwStreamId) {
        if (pendingRequests.find(dwStreamId) == pendingRequests.end()) {
            printf("[SnServer] [h2] Err: Invalid stream ID in data frame GPR\n");
            throw "Invalid stream ID in GetPendingRequest";
        }

        Request rq = *pendingRequests[dwStreamId].get();
        pendingRequests.erase(dwStreamId);
        return rq;
    }

    void HandleGoAway(Http2GoAwayFrame frame) {
        GoAway.bReceived = TRUE;
        GoAway.goAwayFrame = frame;
	
        for (auto& kv : pendingRequests) {
            DWORD dwStreamId = kv.first;
            if (dwStreamId > frame.dwLastStreamId)
                ClearStream(dwStreamId);
		}
    }

    Http2ClientObject(SOCKET sock, PER_IO_OPERATION_DATA* _pIo) : socket(sock), pIo(_pIo) {
        clientSettings = { };
        bHTTP2FirstRequestAfterHandshake = TRUE;
    }
};


class Http2DataFrame : public Http2Frame {
    Http2ClientObject* pClient;
    PBYTE pbData = NULL;
    std::vector<BYTE> vbData;
    ULONG64 ullDataSize;

public:
    Http2DataFrame(Http2ClientObject* _pClient, DWORD dwStreamId, PBYTE _pbData, ULONG64 _ullDataSize)
        : Http2Frame(dwStreamId, FRAME_TYPE_DATA, 0), pClient(_pClient), ullDataSize(_ullDataSize) {
        vbData.insert(vbData.end(), _pbData, _pbData + _ullDataSize);
    }

    Http2DataFrame(Http2ClientObject* _pClient, DWORD dwStreamId, std::string response) 
        : Http2DataFrame(_pClient, dwStreamId, (PBYTE)response.c_str(), response.length()) {

    }

    Http2DataFrame(Http2ClientObject* _pClient, DWORD dwStreamId, std::vector<BYTE> respData)
        : Http2Frame(dwStreamId, FRAME_TYPE_DATA, 0),
            pClient(_pClient), vbData(respData), ullDataSize(respData.size()) {

    }

    BOOL send_chunk(DWORD dwChunkIndex, BOOLEAN bEos);

    BOOL send_all() {
        ULONG64 ullRemaining = ullDataSize;
        DWORD dwMaxFrameSize = pClient->clientSettings.dwMaxFrameSize, dwChunk = 0;
        BOOL bRes;

        while (ullRemaining) {
            ullRemaining -= min(ullRemaining, dwMaxFrameSize);

            if (!(bRes = send_chunk(dwChunk, ullRemaining == 0)))
                return bRes;

            dwChunk++;
        }

        return TRUE;
    }

    BOOL send_file_response(Response response, std::vector<BYTE> prependData = std::vector<BYTE>());
};

class Http2RstStreamFrame : public Http2Frame {
public:
    DWORD dwErrorCode = 0;

private:
    void main_init() {
        if (!bReceivedEnough)
            return;

        if (pvPayload.size() >= 4)
            dwErrorCode = (pvPayload[0] << 24) | (pvPayload[1] << 16) | (pvPayload[2] << 8) | pvPayload[3];

        printf("[SnServer] RST_STREAM on stream %u, code=0x%X\n", dwStreamId, dwErrorCode);
    }
public:

    Http2RstStreamFrame(std::vector<BYTE> vbData) : Http2Frame(vbData, 0) {
        main_init();
    }

    Http2RstStreamFrame(Http2Frame frame) : Http2Frame(frame) {
        main_init();
    }

    Http2RstStreamFrame(DWORD dwStreamId, DWORD _dwErrorCode) : Http2Frame(dwStreamId, FRAME_TYPE_STREAM_RST, 0), dwErrorCode(_dwErrorCode) {
        pvPayload.resize(4);
        pvPayload[0] = (_dwErrorCode >> 24) & 0xFF;
        pvPayload[1] = (_dwErrorCode >> 16) & 0xFF;
        pvPayload[2] = (_dwErrorCode >> 8) & 0xFF;
        pvPayload[3] = _dwErrorCode & 0xFF;
        dwLength = 4;
	}

    void ResetStream(Http2ClientObject* pClient) {
        if (dwErrorCode)
            pClient->AbortStream(dwStreamId);
    }
};