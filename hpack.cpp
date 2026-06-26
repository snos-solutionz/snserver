#pragma once
#include "SnServer.h"
#include "hpack_static_table.h"
#include <unordered_map>

struct pair_hash {
public:
	template <typename T, typename U>
	std::size_t operator()(const std::pair<T, U>& x) const {
		return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
	}
};

static std::unordered_map<std::string, DWORD> staticNameIndex;
static std::unordered_map<std::string, DWORD> staticKVIndex;

void SnHPackSetup() {
	for (DWORD i = 1; i < 62; i++) {
		staticNameIndex[hPackStaticTable[i][0]] = i;

		if (hPackStaticTable[i][1])
			staticKVIndex[std::string(hPackStaticTable[i][0]) + ":" + hPackStaticTable[i][1]] = i;
	}
}

/*
* Decoding
*/

DWORD SnHPackDecodeDword(
	PBYTE pbData, 
	PBYTE pbEnd, 
	BYTE bPrefixBits, 
	PDWORD pdwBytesRead
) {
	DWORD dwMask = (1UL << bPrefixBits) - 1;
	DWORD dwRes = *pbData & dwMask;
	*pdwBytesRead = 1;

	if (dwRes < dwMask)
		return dwRes;

	DWORD dwShift = 0;
	while ((pbData + (*pdwBytesRead)) < pbEnd) {
		BYTE b = pbData[(*pdwBytesRead)++];
		dwRes += (b & 0x7F) << dwShift;

		if (!(b & (1 << 7))) // Bit 7=0 => last byte
			return dwRes;

		dwShift += 7;

		if (dwShift > 28)
			break;
	}

	return dwRes;
}

std::string SnHPackHuffmanDecode(
	PBYTE pbData,
	DWORD dwLen,
	PBOOL pbError
) {
	std::string strOut;
	FAST_HUFFMAN_TABLE hpData = { }, hpNext;
	PBYTE pbEnd = pbData + dwLen;

	strOut.reserve(dwLen * 2);
	auto pTable = fhManTable;

	while (pbData != pbEnd) {
		BYTE b = *pbData++;
		hpData = pTable[hpData.wNode][b >> 4];
		hpNext = pTable[hpData.wNode][b & 0xF];

		if (hpData.bFlags & 0x4)
			goto err;

		if (hpData.bFlags & 0x2)
			strOut += hpData.bSymbol;

		if (hpNext.bFlags & 0x4)
			goto err;

		if (hpNext.bFlags & 0x2)
			strOut += hpNext.bSymbol;

		if (hpData.wNode == 0xFF)
			goto err;

		hpData = hpNext;
	}

	if (hpData.wNode == 0xFF)
		goto err;

	return strOut;

	err: {
		*pbError = -GOAWAY_ERROR_COMPRESSION_ERROR;
		return "";
	}
}

std::string SnHPackDecodeString(
	PBYTE* ppbData,
	PBYTE pbEnd,
	PBOOL pbErr
) {
	if (*ppbData >= pbEnd) 
		return "";

	BYTE b = **ppbData;
	BOOL bHuffman = b & 0x80;

	DWORD dwConsumedBytes = 0;
	DWORD dwStrLen = SnHPackDecodeDword(*ppbData, pbEnd, 7, &dwConsumedBytes);
	*ppbData += dwConsumedBytes;

	if ((*ppbData + dwStrLen) > pbEnd) {
		printf("[SnHPACK] Buffer overflow in string decoding, line %u\n", __LINE__);
		return "";
	}

	std::string res;
	if (bHuffman) {
		//res = "\"Huffman string, len=";
		//res += std::to_string(dwStrLen);
		//res += '"';
		res = SnHPackHuffmanDecode(*ppbData, dwStrLen, pbErr);
	}
	else
		res = std::string((PCHAR)*ppbData, dwStrLen);

	*ppbData += dwStrLen;
	return res;
}

__forceinline std::string SnHPackGetIndexedHeader(
	DWORD dwIndex,
	BOOLEAN bKeyOrValue, // 1 = VALUE
	Http2ClientObject* pClient,
	PBOOL pbErr
) {
	if (dwIndex < 62) {
		if (!hPackStaticTable[dwIndex][bKeyOrValue]) {
			//printf("[SnHPACK] Static table index %u has no %s\n", dwIndex, bKeyOrValue ? "value" : "name");
			//*pbErr = -GOAWAY_ERROR_COMPRESSION_ERROR;
			return "";
		}

		return hPackStaticTable[dwIndex][bKeyOrValue];
	}

	DWORD dynamicIndex = dwIndex - 62;
	if (dynamicIndex < pClient->dynamicTable.size()) {
		return bKeyOrValue ? pClient->dynamicTable[dynamicIndex].value
				: pClient->dynamicTable[dynamicIndex].name;
	}
	
	printf("[SnHPACK] Out of bounds in dynamic header (%u/%u)\n", dynamicIndex, (DWORD)pClient->dynamicTable.size());
	*pbErr = -GOAWAY_ERROR_COMPRESSION_ERROR;
	return "";
}

#define SnHPackSetHeader(/*HeaderMap&*/ hdrs, /*std::string*/ key, /*std::string*/ val) { \
	if (!hdrs.contains(key)) \
		hdrs[key] = val; \
	else {\
\
		if (key[0] == ':') { \
			printf("[SnHPACK] Unallowed duplicate header %s\n", key.c_str()); \
			return -GOAWAY_ERROR_PROTOCOL_ERROR; \
		} \
\
		hdrs[key] += "; " + val; \
	} \
}

BOOL SnHPackDecodeData(
	PBYTE pbData, 
	DWORD dwLen,
	HeaderMap& headers,
	Http2ClientObject* pHttp
) {
	PBYTE pbEnd = pbData + dwLen;
	BOOL bAddToDynamicTable, bErr = 0;
	BYTE bBits;

	while (pbData < pbEnd) {
		BYTE b = *pbData;

		if (b & (1 << 7)) {
			DWORD dwConsumed = 0;
			DWORD dwIndex = SnHPackDecodeDword(pbData, pbEnd, 7, &dwConsumed);

			if (!dwIndex) {
				printf("[SnHPACK] Index=0 is forbidden\n");
				return -GOAWAY_ERROR_COMPRESSION_ERROR;
			}

			std::string key = SnHPackGetIndexedHeader(dwIndex, 0, pHttp, &bErr);
			if (bErr)
				return bErr;
			std::string val = SnHPackGetIndexedHeader(dwIndex, 1, pHttp, &bErr);
			if (bErr)
				return bErr;
			SnHPackSetHeader(headers, key, val);

			pbData += dwConsumed;

		} else if ((b & 0xC0) == 0x40) { // 01xxxxxx
			bBits = 6;
			bAddToDynamicTable = TRUE;
			goto lit_header_field;

		} else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
			bBits = 4;
			bAddToDynamicTable = FALSE;
			goto lit_header_field;

		} else if ((b & 0xE0) == 0x20) { // Dynamic Table Size Update
			DWORD dwConsumed = 0;
			DWORD dwNewMaxSize = SnHPackDecodeDword(pbData, pbEnd, 5, &dwConsumed);

			if (dwNewMaxSize > pHttp->dynamicTableMaxSize()) {
				printf("[SnHPACK] Invalid dynamic table size update: %u\n", dwNewMaxSize);
				return -GOAWAY_ERROR_COMPRESSION_ERROR;
			}

			pbData += dwConsumed;
            
			printf("[SnHPACK] Dynamic Table Size Update: %u bytes\n", dwNewMaxSize);
            continue;

        } else {
			printf("[SnHPACK] Unsupported bit pattern: 0x%02X\n", b);
			return -GOAWAY_ERROR_COMPRESSION_ERROR;
		}

		continue;

		lit_header_field: {
			DWORD dwConsumed = 0;
			DWORD dwIndex = SnHPackDecodeDword(pbData, pbEnd, bBits, &dwConsumed);
			pbData += dwConsumed;

			std::string strName, strVal;

			if (dwIndex > 0) {
				strName = SnHPackGetIndexedHeader(dwIndex, 0, pHttp, &bErr);
			} else
				strName = SnHPackDecodeString(&pbData, pbEnd, &bErr);

			if (bErr)
				return bErr;
			
			strVal = SnHPackDecodeString(&pbData, pbEnd, &bErr);

			if (bErr)
				return bErr;

			SnHPackSetHeader(headers, strName, strVal);

			if (bAddToDynamicTable)
				pHttp->AddToDynamicTable(strName, strVal);
		}

	}

	return TRUE;
}

/*
* Encoding
*/

void SnHPackEncodeDword(
	std::vector<BYTE>& vbOut,
	BYTE bPrefix, BYTE bPrefixBits,
	DWORD dwValue
) {
	DWORD dwMask = (1 << bPrefixBits) - 1;

	if (dwValue < dwMask) {
		vbOut.push_back(bPrefix | (BYTE)dwValue);
		return;
	}

	vbOut.push_back(bPrefix | (BYTE)dwMask);
	dwValue -= dwMask;

	while (dwValue >= 128) {
		vbOut.push_back((BYTE)(0x80 | (dwValue & 0x7F)));
		dwValue >>= 7;
	}
	vbOut.push_back((BYTE)dwValue);
}

void SnHPackEncodeString(std::vector<BYTE>& out, const std::string& str) {
	SnHPackEncodeDword(out, 0x00, 7, (DWORD)str.length());
	// TODO: Huffman encoding?
	for (CHAR c : str) {
		out.push_back((BYTE)c);
	}
}

std::vector<BYTE> SnHPackEncodeData(const HeaderMap& headers) {
	std::vector<BYTE> out;

	for (auto kv : headers) {
		std::string key = kv.first;
		std::string val = kv.second;

		auto itKV = staticKVIndex.find(key + ":" + val);

		if (itKV != staticKVIndex.end()) {
			SnHPackEncodeDword(out, 0x80, 7, itKV->second);
			continue;
		}

		auto itName = staticNameIndex.find(key);
		if (itName != staticNameIndex.end()) {
			SnHPackEncodeDword(out, 0x10, 4, itName->second);
			SnHPackEncodeString(out, val);
			continue;
		}

		out.push_back(0x10);
		SnHPackEncodeString(out, key);
		SnHPackEncodeString(out, val);
	}

	return out;
}