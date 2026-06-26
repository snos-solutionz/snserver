#pragma once
#include "SnServer.h"
#include <schannel.h>

#ifdef ALLOW_HTTP2
#define PROTOCOLS_SPECIFIER_LENGTH 2
#else
#define PROTOCOLS_SPECIFIER_LENGTH 1
#endif

struct {
	HCERTSTORE hStore = NULL;
	PCCERT_CONTEXT pCert = NULL;
	CredHandle hCred = { 0, 0 };
	TimeStamp tsExpiry = { 0 }; // ts does NOT mean this btw
	BOOLEAN bReady = FALSE;
	PSEC_APPLICATION_PROTOCOLS pAlpn = NULL;
	DWORD alpnSize = 0;
} crypt;


_PRIVATE
	void CleanupCrypt() {
		if (crypt.hCred.dwLower || crypt.hCred.dwUpper) {
			FreeCredentialsHandle(&crypt.hCred);
			crypt.hCred = { 0, 0 };
		}
		if (crypt.pCert) {
			CertFreeCertificateContext(crypt.pCert);
			crypt.pCert = NULL;
		}
		if (crypt.hStore) {
			CertCloseStore(crypt.hStore, 0);
			crypt.hStore = NULL;
		}

		if (crypt.pAlpn)
			free(crypt.pAlpn);
		crypt.bReady = FALSE;
	}
_PUBLIC

BOOL LoadPfx(LPCTSTR pfxPath, LPCWSTR password) {
	CRYPT_DATA_BLOB pfxBlob;
	DWORD dwFileSize, dwRead;

	HANDLE hFile = CreateFile(pfxPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if ( hFile == INVALID_HANDLE_VALUE ) {
		display_latest_win_err(_T("Failed to open PFX file"));
		return FALSE;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	std::vector<BYTE> pfxData(dwFileSize);

	if ( !ReadFile(hFile, pfxData.data(), dwFileSize, &dwRead, NULL) || dwRead != dwFileSize ) {
		display_latest_win_err(_T("Failed to read PFX file"));
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);

	pfxBlob.cbData = dwFileSize;
	pfxBlob.pbData = pfxData.data();

	crypt.hStore = PFXImportCertStore(&pfxBlob, password, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);

	if ( !crypt.hStore ) {
		display_latest_win_err(_T("Failed to import PFX certificate store"));
		return FALSE;
	}

	crypt.pCert = CertFindCertificateInStore(crypt.hStore, 
											 X509_ASN_ENCODING, 
											 0, CERT_FIND_ANY, NULL, NULL);

	if (!crypt.pCert) {
		display_latest_win_err(_T("Failed to find certificate in store"));
		CertCloseStore(crypt.hStore, 0);
		return FALSE;
	}

	DWORD size = 0;
	if (!CertGetCertificateContextProperty(
			crypt.pCert, CERT_KEY_PROV_INFO_PROP_ID,
			NULL, &size)) {
		printf("[SnServer] Certificate has NO private key!\n");
	} else {
		printf("[SnServer] Certificate has private key\n");
	}

//#undef PROTOCOLS_SPECIFIER_LENGTH
//#define PROTOCOLS_SPECIFIER_LENGTH 1
	BYTE alpnProtocols[] = {
	#ifdef ALLOW_HTTP2
		0x02, 'h', '2',								 // HTTP/2
	#endif
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' // HTTP/1.1
	};
	WORD alpnIdsSize = sizeof(alpnProtocols);

	DWORD totalSize = sizeof(SEC_APPLICATION_PROTOCOLS) + 
                   sizeof(SEC_APPLICATION_PROTOCOL_LIST) + 
                   alpnIdsSize - (PROTOCOLS_SPECIFIER_LENGTH * ANYSIZE_ARRAY);

	PSEC_APPLICATION_PROTOCOLS pAlpn = (PSEC_APPLICATION_PROTOCOLS)malloc(totalSize);

	crypt.alpnSize = totalSize;
	crypt.pAlpn = pAlpn;

	if (!pAlpn) {
		printf("[SnServer] Out of memory\n");
		CleanupCrypt( );
		return FALSE;
	}

	RtlZeroMemory(pAlpn, totalSize);
	pAlpn->ProtocolListsSize = sizeof(SEC_APPLICATION_PROTOCOL_LIST) + alpnIdsSize - ANYSIZE_ARRAY;

	PSEC_APPLICATION_PROTOCOL_LIST pList = &pAlpn->ProtocolLists[0];
	pList->ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
	pList->ProtocolListSize = alpnIdsSize;
	memcpy(pList->ProtocolList, alpnProtocols, alpnIdsSize);

	SCH_CREDENTIALS sc = {};
	sc.dwVersion = SCH_CREDENTIALS_VERSION;
	sc.cCreds = 1;
	sc.paCred = &crypt.pCert;

	sc.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;

	SECURITY_STATUS status = AcquireCredentialsHandle(
		NULL, (LPWSTR)UNISP_NAME, SECPKG_CRED_INBOUND, NULL,
		&sc, NULL, NULL, &crypt.hCred, &crypt.tsExpiry
	);

	//free( pAlpn );

	if (status != SEC_E_OK) {
		display_latest_win_err(_T("Failed to acquire credentials handle"));
		CleanupCrypt( );
		return FALSE;
	}

	return crypt.bReady = TRUE;
}

BOOL HandleTLSHandshake(PER_IO_OPERATION_DATA* pIo) {
	SecBuffer sbInBuff[3] = {};
	SecBuffer sbOutBuff[2] = {};
	SecBufferDesc sbDescIn = {};
	SecBufferDesc sbDescOut = {};
	SECURITY_STATUS status;
	ULONG pfContextAttr;

	sbInBuff[0].pvBuffer = (PVOID)pIo->tlsBuffer.data();
	sbInBuff[0].cbBuffer = (DWORD)pIo->tlsBuffer.size();
	sbInBuff[0].BufferType = SECBUFFER_TOKEN;
	
	sbInBuff[1].pvBuffer = crypt.pAlpn;
	sbInBuff[1].cbBuffer = crypt.alpnSize;
	sbInBuff[1].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;

	sbInBuff[2].pvBuffer = NULL;
	sbInBuff[2].cbBuffer = 0;
	sbInBuff[2].BufferType = SECBUFFER_EMPTY;

	sbOutBuff[0].pvBuffer = NULL;
	sbOutBuff[0].cbBuffer = 0;
	sbOutBuff[0].BufferType = SECBUFFER_TOKEN;
	sbOutBuff[1].pvBuffer = NULL;
	sbOutBuff[1].cbBuffer = 0;
	sbOutBuff[1].BufferType = SECBUFFER_EMPTY;

	sbDescIn.ulVersion = SECBUFFER_VERSION;
	sbDescIn.cBuffers = 3;
	sbDescIn.pBuffers = sbInBuff;

	sbDescOut.ulVersion = SECBUFFER_VERSION;
	sbDescOut.cBuffers = 2;
	sbDescOut.pBuffers = sbOutBuff;

	status = AcceptSecurityContext(
		&crypt.hCred, pIo->bFirstHandshakeReceivement ? NULL : &pIo->hContext, &sbDescIn,
		ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY,
		SECURITY_NATIVE_DREP,
		&pIo->hContext, &sbDescOut, &pfContextAttr, NULL
	);
	pIo->bFirstHandshakeReceivement = FALSE;

	DWORD dwFound = (DWORD)-1;
	for (DWORD i = 0; i < 3; i++) {
		if (sbInBuff[i].BufferType == SECBUFFER_EXTRA) {
			dwFound = i;
			break;
		}
	}

	if (dwFound != (DWORD)-1) {
		size_t extraLen = sbInBuff[dwFound].cbBuffer;
		BYTE* extraPtr = (BYTE*)sbInBuff[dwFound].pvBuffer;
		pIo->tlsBuffer.assign(extraPtr, extraPtr + extraLen);
	} else
		pIo->tlsBuffer.clear();

	if (sbOutBuff[0].pvBuffer != NULL && sbOutBuff[0].cbBuffer > 0) {
		send(pIo->sock, (PCHAR)sbOutBuff[0].pvBuffer, sbOutBuff[0].cbBuffer, 0);
		FreeContextBuffer(sbOutBuff[0].pvBuffer);
	}

	if (status == SEC_E_OK)
		goto post_handshake;
	else if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE)
		return FALSE;
	else {
		printf("[SnServer] Handshake error: AcceptSecurityContext=0x%08lx\n", (ULONG)status);
		return -1;
	}

post_handshake:
	SecPkgContext_ApplicationProtocol alpn;
	status = QueryContextAttributes(
		&pIo->hContext,
		SECPKG_ATTR_APPLICATION_PROTOCOL,
		&alpn
	);

	if (status == SEC_E_OK) {
		if (alpn.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
			if (alpn.ProtocolIdSize == 8 && memcmp(alpn.ProtocolId, "http/1.1", 8) == 0) {
				// HTTP/1.1 selected
				printf("[SnServer] HTTP/1.1 requested\n");
				pIo->ProtocolType = SNSRV_PROTOCOL_HTTP1_1;
			} 
		#ifdef ALLOW_HTTP2
			else if (alpn.ProtocolIdSize == 2 && memcmp(alpn.ProtocolId, "h2", 2) == 0) {
				// HTTP/2 selected
				printf("[SnServer] HTTP/2 requested\n");
				pIo->http2Client = new Http2ClientObject(pIo->sock, pIo);
				pIo->http2Client->bHTTP2FirstRequestAfterHandshake = TRUE;
				pIo->ProtocolType = SNSRV_PROTOCOL_HTTP2;
				pIo->http2Client->clientSettings = Http2Settings(SnSrvHTTP2GetDefaultSettings());
			}
		#endif
			else {
				printf("[SnServer] Unsupported protocol requested during handshake: \"%.*s\"\n",
					   alpn.ProtocolIdSize, alpn.ProtocolId);
				return -1;
			}
		}
		else
			printf("[SnServer] [DBG] alpn.ProtoNegoStatus=%u\n", (DWORD)alpn.ProtoNegoStatus);
	} else
		printf("[SnServer] QueryContextAttributes=0x%08lx\n", (ULONG)status);

	return TRUE;
}

void CryptDeallocate(PER_IO_OPERATION_DATA* pIo) {
	if (!crypt.bReady)
		return;

	if (pIo->hContext.dwLower || pIo->hContext.dwUpper)
		DeleteSecurityContext(&pIo->hContext);
}

BOOL CryptDecrypt(PER_IO_OPERATION_DATA* pIo) {
	if (!crypt.bReady)
		return -1;
	
	ULONG pfQOP;
	SECURITY_STATUS status;
	SecBufferDesc scDescMsg;
	SecBuffer sbBuffers[4] = {};

	// Encrypted data recieved
	sbBuffers[0].pvBuffer = pIo->tlsBuffer.data( );
	sbBuffers[0].cbBuffer = (DWORD)pIo->tlsBuffer.size( );
	sbBuffers[0].BufferType = SECBUFFER_DATA;
	
	// Buffer for extra data
	sbBuffers[1].pvBuffer = NULL;
	sbBuffers[1].cbBuffer = 0;
	sbBuffers[1].BufferType = SECBUFFER_EMPTY;
	
	// Padding
	sbBuffers[2].pvBuffer = NULL; 
	sbBuffers[2].cbBuffer = 0;
	sbBuffers[2].BufferType = SECBUFFER_EMPTY;

	// Trailing
	sbBuffers[3].pvBuffer = NULL;
	sbBuffers[3].cbBuffer = 0;
	sbBuffers[3].BufferType = SECBUFFER_EMPTY;
	
	scDescMsg.ulVersion = SECBUFFER_VERSION;
	scDescMsg.cBuffers = 4;
	scDescMsg.pBuffers = sbBuffers;

	status = DecryptMessage(&pIo->hContext, &scDescMsg, 0, &pfQOP);

	if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED) {
		PSecBuffer pDataBuffer = nullptr;
		PSecBuffer pExtraBuffer = nullptr;

		for (int i = 0; i < 4; i++) {
			if (sbBuffers[i].BufferType == SECBUFFER_DATA) pDataBuffer = &sbBuffers[i];
			if (sbBuffers[i].BufferType == SECBUFFER_EXTRA) pExtraBuffer = &sbBuffers[i];
		}

		std::vector<CHAR> plaintext(
			(PCHAR)pDataBuffer->pvBuffer,
			(PCHAR)pDataBuffer->pvBuffer + pDataBuffer->cbBuffer
		);

		pIo->requestBuffer.insert(
			pIo->requestBuffer.end(),
			(PCHAR)pDataBuffer->pvBuffer,
			(PCHAR)pDataBuffer->pvBuffer + pDataBuffer->cbBuffer
		);

		if (pExtraBuffer) {
			std::vector<CHAR> extra(
				(PCHAR)pExtraBuffer->pvBuffer,
				(PCHAR)pExtraBuffer->pvBuffer + pExtraBuffer->cbBuffer
			);
			pIo->tlsBuffer = std::move(extra);
		} else
			pIo->tlsBuffer.clear();

		return TRUE;
	} else if (status == SEC_E_INCOMPLETE_MESSAGE) {
		//printf("[SnServer] Decryption: more recv needed\n");
		return FALSE; // more recv needed
	} else {
		printf("[SnServer] Decryption error: DecryptMessage=0x%08lx\n", (ULONG)status);
		return -1;
	}
}