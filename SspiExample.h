#pragma once
#pragma once
//  SspiExample.h
#include <sspi.h>
#include <windows.h>

BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead);
BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead);
void cleanup();

BOOL GenClientContext(
    BYTE* pIn,
    DWORD cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    const CHAR* pszTarget,
    CredHandle* hCred,
    struct _SecHandle* hcText
);

BOOL GenServerContext(
    BYTE* pIn,
    DWORD cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    BOOL  fNewCredential
);

BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    ULONG* pcbOutput,
    ULONG cbSecurityTrailer,
    PCtxtHandle hctxt);

PBYTE DecryptThis(
    PBYTE achData,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbSecurityTrailer
);

BOOL
SignThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    LPDWORD pcbOutput
);

PBYTE VerifyThis(
    PBYTE pBuffer,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbMaxSignature
);

void PrintHexDump(DWORD length, PBYTE buffer);

BOOL ConnectAuthSocket(
    SOCKET* s,
    CredHandle* hCred,
    struct _SecHandle* hcText
);

BOOL CloseAuthSocket(SOCKET s);

BOOL DoAuthentication(SOCKET s, PSecHandle hCred, PSecHandle hCtxt);

void MyHandleError(const char* s);