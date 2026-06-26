#include "SnServer.h"

std::map<SnSrvHttp2SettingId, DWORD> SnSrvHTTP2GetDefaultSettings() {
    return std::map<SnSrvHttp2SettingId, DWORD> {
        { SNSRV_HEADER_TABLE_SIZE,       4096 },
        { SNSRV_ENABLE_PUSH,             0 },
        { SNSRV_MAX_CONCURRENT_STREAMS,  100 },
        { SNSRV_INITIAL_WINDOW_SIZE,     65535 },
        { SNSRV_MAX_FRAME_SIZE,          16384 },
        { SNSRV_MAX_HEADER_LIST_SIZE,    0 }  
    };
}
std::vector<BYTE> SnSrvHTTP2CreateSettingsFrame(std::map<SnSrvHttp2SettingId, DWORD>& settings, BOOL isAck) {
    DWORD payloadSize = (DWORD)(settings.size() * 6);
    std::vector<BYTE> vbFrame(9 + payloadSize);
    
    vbFrame[0] = (BYTE)(payloadSize >> 16);
    vbFrame[1] = (BYTE)(payloadSize >> 8);
    vbFrame[2] = (BYTE)payloadSize;

    vbFrame[3] = FRAME_TYPE_SETTINGS;

    vbFrame[4] = isAck ? FRAME_FLAG_ACK : 0x00;

    DWORD dwOffset = 9;
    for (const auto& kv : settings) {
        WORD wNetId = htons(kv.first);
        DWORD dwNetVal = htonl(kv.second);

        memcpy(&vbFrame[dwOffset], &wNetId, 2);
        memcpy(&vbFrame[dwOffset + 2], &dwNetVal, 4);
        
        dwOffset += 6;
    }

    return vbFrame;
}

Response SnSrvHTTP2CreateAckMsg(SOCKET sock) {
    std::map<SnSrvHttp2SettingId, DWORD> settings;
    return Response(SnSrvHTTP2CreateSettingsFrame(settings, TRUE), sock);
}


BOOL Http2DataFrame::send_chunk(DWORD dwChunkIndex, BOOLEAN bEos) {
    ULONG64 szIndex = (ULONG64)dwChunkIndex * pClient->clientSettings.dwMaxFrameSize;

    if (pClient->IsStreamAborted(dwStreamId)) {
        printf("[SnServer] Aborted on stream %u\n", dwStreamId);
        pClient->ClearStream(dwStreamId);
        return FALSE;
    }

    if (szIndex >= ullDataSize) {
        printf("[SnServer] [H2] Invalid chunk index in data frame send\n");
        return -1;
    }

    DWORD dwRemaining = (DWORD)min(pClient->clientSettings.dwMaxFrameSize, ullDataSize - szIndex);
    dwLength = dwRemaining;

    bFlags = bEos ? FRAME_FLAG_END_OF_STREAM : 0;
    
    pbData = vbData.data();
    pvPayload = std::vector<BYTE>(pbData + szIndex, pbData + szIndex + dwLength);

    Response resp(to_bytes(), pClient->socket);
    return resp.send_response(pClient->pIo, pClient->pIo->server->crypt.bReady);
}

BOOL Http2DataFrame::send_file_response(Response response, std::vector<BYTE> prependData) {
    if (!response.FileSendInfo.bUseFileSend) {
        printf("[SnServer] [H2] Err: Invalid file send setup.\n");
        return FALSE;
    }

    HANDLE hFile = response.FileSendInfo.hFile;
    DWORD dwClientMaxFrame = pClient->clientSettings.dwMaxFrameSize;
    DWORD dwRead;
    ULONGLONG bytesLeft = response.FileSendInfo.range.uSize;
    
    PBYTE pbBuffer = (PBYTE)malloc(TLS_MAX_RECORD_SIZE + 9);
    LARGE_INTEGER liOffset;

    if (!pbBuffer) {
        printf("[SnServer] [H2] Out of memory during file send\n");
        goto close_ret_false;
    }

    {
        BOOL bFirst = TRUE;
        liOffset.QuadPart = response.FileSendInfo.range.uStart;

        SetFilePointerEx(hFile, liOffset, NULL, FILE_BEGIN);
        Response sender(pClient->socket);
        sender.bCryptReady = pClient->pIo->server->crypt.bReady;
        sender.pIo = pClient->pIo;

        printf("Sending file on stream %u\n", dwStreamId);

        while (bytesLeft > 0 || (bFirst && bytesLeft == 0)) {
            if (pClient->IsStreamAborted(dwStreamId)) {
                printf("[SnServer] File send aborted on stream %u\n", dwStreamId);
                pClient->ClearStream(dwStreamId);
                free(pbBuffer);
                goto close_ret_false;
            }

            DWORD dwMaxPayloadCapacity = dwClientMaxFrame;
            
            if (bFirst) {
                DWORD dwOverhead = 9 + (DWORD)prependData.size();
                if (TLS_MAX_RECORD_SIZE > dwOverhead)
                    dwMaxPayloadCapacity = min(dwMaxPayloadCapacity, TLS_MAX_RECORD_SIZE - dwOverhead);
                else
					dwMaxPayloadCapacity = 0; // overhead size > max TLS record size, cant send any file data in first frame
            } else {
                dwMaxPayloadCapacity = min(dwMaxPayloadCapacity, TLS_MAX_RECORD_SIZE - 9);
            }

            DWORD toRead = (DWORD)min(bytesLeft, dwMaxPayloadCapacity);
            
            Http2Frame frameSetup(dwStreamId, bType, 0);
            frameSetup.dwLength = toRead;
            if (toRead == bytesLeft) {
                frameSetup.bFlags = FRAME_FLAG_END_OF_STREAM;
               //printf("sending EOS\n");
            }
            
            memcpy(pbBuffer, frameSetup.to_bytes().data(), 9);

            if (toRead > 0) {
                if (!ReadFile(hFile, pbBuffer + 9, toRead, &dwRead, NULL)) {
                    free(pbBuffer);
                    printf("[SnServer] [H2] Err: ReadFile=%d\n", GetLastError());
                    goto close_ret_false;
                }
            } else {
                dwRead = 0;
            }

            if (bFirst && !prependData.empty()) {
                std::vector<BYTE> combined;
                combined.reserve(prependData.size() + dwRead + 9);
                combined.insert(combined.end(), prependData.begin(), prependData.end());
                combined.insert(combined.end(), pbBuffer, pbBuffer + dwRead + 9);
                if (!sender.send_content(combined.data(), (DWORD)combined.size())) {
                    //printf("[SnServer] [H2] Failed to send first\n");
                    free(pbBuffer);
                    goto close_ret_false;
                }
            } else {
                if (!sender.send_content(pbBuffer, dwRead + 9)) {
                    printf("[SnServer] [H2] Err: Send content\n");
                    free(pbBuffer);
                    goto close_ret_false;
                }
            }
            
            bFirst = FALSE;
            bytesLeft -= dwRead;
            
            if (!bytesLeft) 
                break;
        }
    }
    free(pbBuffer);
    CloseHandle(response.FileSendInfo.hFile);
    return TRUE;

close_ret_false:
    CloseHandle(response.FileSendInfo.hFile);
    return FALSE;
}