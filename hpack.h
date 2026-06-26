#pragma once
#include "SnServer.h"

class Http2ClientObject;
BOOL SnHPackDecodeData(PBYTE pbData, DWORD dwLen, HeaderMap& headers, Http2ClientObject* pHttp);
std::vector<BYTE> SnHPackEncodeData(const HeaderMap& headers);
void SnHPackSetup();