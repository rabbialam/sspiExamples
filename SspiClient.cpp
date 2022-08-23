//--------------------------------------------------------------------
//  Client-side program to establish an SSPI socket connection
//  with a server and exchange messages.

//--------------------------------------------------------------------
//  Define macros and constants.

#define SECURITY_WIN32
#define BIG_BUFF   2048
#define SEC_SUCCESS(Status) ((Status) >= 0)
#define g_usPort 2000

#define cbMaxMessage 12000
#define MessageAttribute ISC_REQ_CONFIDENTIALITY 

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include "SspiExample.h"
#include <tchar.h>
#include<fstream>
#include<iostream>
#include <Lmcons.h>
using namespace std;


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Secur32.lib")


//  The following #define statement must be changed. ServerName must
//  be defined as the name of the computer running the server sample.
//  TargetName must be defined as the logon name of the user running 
//  the server program.
#define ServerName  "localhost"
//#define ServerName  "WinDev2108Eval"
//#define TargetName  "malam5"
char* TargetName;
void wireToFile(BYTE* data, char* fileName) {
    std::ofstream wf(fileName, ios::out | ios::binary);

  //  wf.write()

}
void sockCheck(SOCKET sockets) {
    struct sockaddr_in sin;
    int addrlen = sizeof(sin);
    getsockname(sockets, (struct sockaddr*)&sin, &addrlen);
    int local_port1 = ntohs(sin.sin_port);
    cout << "Sock 0 port " << std::dec << local_port1 << endl;
   
}
void main()
{

    SOCKET            Client_Socket;
    BYTE              Data[BIG_BUFF];
    PCHAR             pMessage;
    WSADATA           wsaData;
    PBYTE pDataToClient = NULL;
    DWORD cbDataToClient = 0;
    //CredHandle        hCred;
    //struct _SecHandle hCtxt;
    DWORD cbMessage;

    SECURITY_STATUS   ss;
    DWORD             cbRead;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;
    SecPkgContext_NegotiationInfo  SecPkgNegInfo;
    //BOOL DoAuthentication(SOCKET s);
    int dummy;
    CredHandle hCred;
    struct _SecHandle  hCtxt;
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    TargetName = username;
   
    //-------------------------------------------------------------------
    //  Initialize the socket and the SSP security package.

    if (WSAStartup(0x0101, &wsaData))
    {
        MyHandleError("Could not initialize winsock ");
    }

    //--------------------------------------------------------------------
    //  Connect to a server.

    if (!ConnectAuthSocket(
        &Client_Socket,
        &hCred,
        &hCtxt))
    {
        MyHandleError("Authenticated server connection ");
    }
    sockCheck(Client_Socket);
    //--------------------------------------------------------------------
    //   An authenticated session with a server has been established.
    //   Receive and manage a message from the server.
    //   First, find and display the name of the negotiated
    //   SSP and the size of the signature and the encryption 
    //   trailer blocks for this SSP.


    ss = QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_NEGOTIATION_INFO,
        &SecPkgNegInfo);

    if (!SEC_SUCCESS(ss))
    {
        MyHandleError("QueryContextAttributes failed ");
    }
    else
    {
        printf("Package Name: %s\n", SecPkgNegInfo.PackageInfo->Name);
    }

    SecPkgContext_SessionKey sessionKey;
    ss = QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_SESSION_KEY,
        &sessionKey);

    if (!SEC_SUCCESS(ss))
    {
        MyHandleError("QueryContextAttributes failed ");
    }
    else
    {
        printf("Package Name: %s\n", sessionKey.SessionKey);
        PrintHexDump(sessionKey.SessionKeyLength, sessionKey.SessionKey);
    }
    printf("hCtxt: dwLower = 0x%llx dwUpper = 0x%llx\n",hCtxt.dwLower,hCtxt.dwUpper);


    printf("hCred: dwLower = 0x%llx dwUpper = 0x%llx\n", hCred.dwLower, hCred.dwUpper);


    SecBuffer  packedContext;
    BYTE* pHeader_test = NULL;
    BYTE* pMessage_test;
    BYTE* pTrailer_test;
    packedContext.cbBuffer = sizeof(pHeader_test);
    packedContext.BufferType = SECBUFFER_EMPTY;
    packedContext.pvBuffer = pHeader_test;
    HANDLE pToken;

  //  scanf_s("%d", &dummy);
/*    SECURITY_STATUS se= ExportSecurityContext(&hCtxt, SECPKG_CONTEXT_EXPORT_DELETE_OLD, &packedContext, &pToken);

    if (se == SEC_E_INSUFFICIENT_MEMORY) {
        printf("There is not enough memory available to complete the requested action.%d", se);

    }else if (se == SEC_E_INVALID_HANDLE) {
        printf("The phContext parameter does not point to a valid handle.%d", se);

    }else if (se == SEC_E_OK) {
        PrintHexDump(packedContext.cbBuffer,(PBYTE)packedContext.pvBuffer);
    }

    struct _SecHandle  hCtxt_copy;
  
    SECURITY_STATUS se2 = ImportSecurityContextA(SecPkgNegInfo.PackageInfo->Name, &packedContext, &pToken,&hCtxt_copy);
    printf("hCtxt_new: dwLower = 0x%llx dwUpper = 0x%llx\n", hCtxt_copy.dwLower, hCtxt_copy.dwUpper);

    printf("hCred_old: dwLower = 0x%llx dwUpper = 0x%llx\n", hCtxt.dwLower, hCtxt.dwUpper);
    hCtxt = hCtxt_copy;*/
   // scanf_s("%d", &dummy);
   /* for (int i = 0; i < 5; i++) {


        CredHandle hCred2;
        struct _SecHandle  hCtxt2;
        SOCKET            Client_Socket2;

        if (!ConnectAuthSocket(
            &Client_Socket2,
            &hCred2,
            &hCtxt2))
        {
            MyHandleError("Authenticated server connection ");
        }
        printf("Number %d hCtxt : dwLower = 0x%llx dwUpper = 0x%llx\n", i, hCtxt2.dwLower, hCtxt2.dwUpper);


        printf("Number %d hCred: dwLower = 0x%llx dwUpper = 0x%llx\n", i, hCred2.dwLower, hCred2.dwUpper);
        SecPkgContext_SessionKey sessionKey2;
        ss = QueryContextAttributes(
            &hCtxt2,
            SECPKG_ATTR_SESSION_KEY,
            &sessionKey2);

        if (!SEC_SUCCESS(ss))
        {
            MyHandleError("QueryContextAttributes failed ");
        }
        else
        {
            printf("Package Name: %s\n", sessionKey2.SessionKey);
            PrintHexDump(sessionKey2.SessionKeyLength, sessionKey2.SessionKey);
        }
   
    }*/
    ss = QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        MyHandleError("Query context ");
    }

    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    printf("InitializeSecurityContext result = 0x%08x\n", ss);

    //--------------------------------------------------------------------
    //   Decrypt and display the message from the server.
   
    //scanf_s("%d", &dummy);
    
        if (!ReceiveMsg(
            Client_Socket,
            Data,
            BIG_BUFF,
            &cbRead))
        {
            MyHandleError("No response from server ");
        }

        if (0 == cbRead)
        {
            MyHandleError("Zero bytes received ");
        }

        pMessage = (PCHAR)DecryptThis(
            Data,
            &cbRead,
            &hCtxt,
            cbSecurityTrailer);

        printf("The message from the server is \n ->  %.*s \n",
            cbRead, pMessage);
    while (1) {
        printf("Type message to send: \n");
        // strcpy_s(pMessage, sizeof(pMessage),   "This is your server speaking Echo:");
        char send[100];
        scanf_s("%s", send,sizeof(send));

        cbMessage = strlen(send);
        int flag = 0;
        if (!strcmp("Quit", send)) {
            flag = 1;
        }
        EncryptThis(
            (PBYTE)send,
            cbMessage,
            &pDataToClient,
            &cbDataToClient,
            cbSecurityTrailer,
            &hCtxt);

        //-----------------------------------------------------------------   
        //  Send the encrypted data to client.

        int dummy;
        // scanf_s("%d", &dummy);
        if (!SendMsg(
            Client_Socket,
            pDataToClient,
            cbDataToClient))
        {
            printf("send message failed. \n");
            cleanup();
        }
        if (flag) break;
    }
   

    //--------------------------------------------------------------------
    //  Terminate socket and security package.
    //scanf_s("%d", &dummy);
    DeleteSecurityContext(&hCtxt);
    FreeCredentialHandle(&hCred);
    shutdown(Client_Socket, 2);
    closesocket(Client_Socket);
    if (SOCKET_ERROR == WSACleanup())
    {
        MyHandleError("Problem with socket cleanup ");
    }

    exit(EXIT_SUCCESS);
}  // end main

//--------------------------------------------------------------------
//  ConnectAuthSocket establishes an authenticated socket connection 
//  with a server and initializes needed security package resources.

BOOL ConnectAuthSocket(
    SOCKET* s,
    CredHandle* hCred,
    struct _SecHandle* hcText)
{
    unsigned long  ulAddress;
    struct hostent* pHost;
    SOCKADDR_IN    sin;

    //--------------------------------------------------------------------
    //  Lookup the server's address.

    ulAddress = inet_addr(ServerName);

    if (INADDR_NONE == ulAddress)
    {
        pHost = gethostbyname(ServerName);
        if (NULL == pHost)
        {
            MyHandleError("Unable to resolve host name ");
        }
        memcpy((char FAR*) & ulAddress, pHost->h_addr, pHost->h_length);
    }

    //--------------------------------------------------------------------
    //  Create the socket.

    *s = socket(
        PF_INET,
        SOCK_STREAM,
        0);

    if (INVALID_SOCKET == *s)
    {
        MyHandleError("Unable to create socket");
    }
    else
    {
        printf("Socket created.\n");
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ulAddress;
    sin.sin_port = htons(g_usPort);

    //--------------------------------------------------------------------
    //  Connect to the server.

    if (connect(*s, (LPSOCKADDR)&sin, sizeof(sin)))
    {
        closesocket(*s);
        MyHandleError("Connect failed ");
    }

    //--------------------------------------------------------------------
    //  Authenticate the connection. 
  
    if (!DoAuthentication(*s,hCred,hcText))
    {
        closesocket(*s);
        MyHandleError("Authentication ");
    }

    return(TRUE);
}  // end ConnectAuthSocket 
void cleanup()
{

    WSACleanup();
    exit(0);
}
BOOL DoAuthentication(SOCKET s,PSecHandle hCred,PSecHandle hCtxt)

{
    BOOL        fDone = FALSE;
    DWORD       cbOut = 0;
    DWORD       cbIn = 0;
    PBYTE       pInBuf;
    PBYTE       pOutBuf;


    if (!(pInBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        MyHandleError("Memory allocation ");
    }

    if (!(pOutBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        MyHandleError("Memory allocation ");
    }

    cbOut = cbMaxMessage;
    if (!GenClientContext(
        NULL,
        0,
        pOutBuf,
        &cbOut,
        &fDone,
        TargetName,
        hCred,
        hCtxt
    ))
    {
        return(FALSE);
    }

    if (!SendMsg(s, pOutBuf, cbOut))
    {
        MyHandleError("Send message failed ");
    }

    while (!fDone)
    {
        if (!ReceiveMsg(
            s,
            pInBuf,
            cbMaxMessage,
            &cbIn))
        {
            MyHandleError("Receive message failed ");
        }

        cbOut = cbMaxMessage;

        if (!GenClientContext(
            pInBuf,
            cbIn,
            pOutBuf,
            &cbOut,
            &fDone,
            TargetName,
            hCred,
            hCtxt))
        {
            MyHandleError("GenClientContext failed");
        }
        if (!SendMsg(
            s,
            pOutBuf,
            cbOut))
        {
            MyHandleError("Send message 2  failed ");
        }
    }

    free(pInBuf);
    free(pOutBuf);
    return(TRUE);
}

BOOL GenClientContext(
    BYTE* pIn,
    DWORD       cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    const CHAR* pszTarget,
    CredHandle* hCred,
    struct _SecHandle* hcText)
{
    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    SecBufferDesc     OutBuffDesc;
    SecBuffer         OutSecBuff;
    SecBufferDesc     InBuffDesc;
    SecBuffer         InSecBuff;
    ULONG             ContextAttributes;
    static TCHAR      lpPackageName[1024];
    int dummy;
   // scanf_s("%d", &dummy);

    if (NULL == pIn)
    {
        _tcscpy_s(lpPackageName, 1024 * sizeof(TCHAR), _T("Negotiate"));
        LPSTR lpstr = const_cast<LPSTR>(TargetName);
        ss = AcquireCredentialsHandle(
            lpstr,
            lpPackageName,
            SECPKG_CRED_OUTBOUND,
            NULL,
            NULL,
            NULL,
            NULL,
            hCred,
            &Lifetime);

        if (!(SEC_SUCCESS(ss)))
        {
            MyHandleError("AcquireCreds failed ");
        }
    }

    //--------------------------------------------------------------------
    //  Prepare the buffers.

    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.cbBuffer = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = pOut;

    //-------------------------------------------------------------------
    //  The input buffer is created only if a message has been received 
    //  from the server.

    if (pIn)
    {
        InBuffDesc.ulVersion = 0;
        InBuffDesc.cBuffers = 1;
        InBuffDesc.pBuffers = &InSecBuff;

        InSecBuff.cbBuffer = cbIn;
        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.pvBuffer = pIn;

        ss = InitializeSecurityContext(
            hCred,
            hcText,
            (SEC_CHAR *)pszTarget,
            MessageAttribute,
            0,
            SECURITY_NATIVE_DREP,
            &InBuffDesc,
            0,
            hcText,
            &OutBuffDesc,
            &ContextAttributes,
            &Lifetime);
    }
    else
    {
        ss = InitializeSecurityContext(
            hCred,
            NULL,
            (SEC_CHAR *)pszTarget,
            MessageAttribute,
            0,
            SECURITY_NATIVE_DREP,
            NULL,
            0,
            hcText,
            &OutBuffDesc,
            &ContextAttributes,
            &Lifetime);
    }

    if (!SEC_SUCCESS(ss))
    {
        MyHandleError("InitializeSecurityContext failed ");
    }

    //-------------------------------------------------------------------
    //  If necessary, complete the token.

    if ((SEC_I_COMPLETE_NEEDED == ss)
        || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
        ss = CompleteAuthToken(hcText, &OutBuffDesc);
        if (!SEC_SUCCESS(ss))
        {
            fprintf(stderr, "complete failed: 0x%08x\n", ss);
            return FALSE;
        }
    }

    *pcbOut = OutSecBuff.cbBuffer;

    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||
        (SEC_I_COMPLETE_AND_CONTINUE == ss));

    printf("Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
    PrintHexDump(OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);
    return TRUE;

}

PBYTE DecryptThis(
    PBYTE              pBuffer,
    LPDWORD            pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG              cbSecurityTrailer)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    PBYTE             pSigBuffer;
    PBYTE             pDataBuffer;
    DWORD             SigBufferSize;

    //-------------------------------------------------------------------
    //  By agreement, the server encrypted the message and set the size
    //  of the trailer block to be just what it needed. DecryptMessage 
    //  needs the size of the trailer block. 
    //  The size of the trailer is in the first DWORD of the
    //  message received. 

    SigBufferSize = *((DWORD*)pBuffer);
    printf("data before decryption including trailer (%lu bytes):\n",
        *pcbMessage);
    PrintHexDump(*pcbMessage, (PBYTE)pBuffer);

    //--------------------------------------------------------------------
    //  By agreement, the server placed the trailer at the beginning 
    //  of the message that was sent immediately following the trailer 
    //  size DWORD.

    pSigBuffer = pBuffer + sizeof(DWORD);

    //--------------------------------------------------------------------
    //  The data comes after the trailer.

    pDataBuffer = pSigBuffer + SigBufferSize;

    //--------------------------------------------------------------------
    //  *pcbMessage is reset to the size of just the encrypted bytes.

    *pcbMessage = *pcbMessage - SigBufferSize - sizeof(DWORD);

    //--------------------------------------------------------------------
    //  Prepare the buffers to be passed to the DecryptMessage function.

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].cbBuffer = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer = pSigBuffer;

    SecBuff[1].cbBuffer = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer = pDataBuffer;

    ss = DecryptMessage(
        hCtxt,
        &BuffDesc,
        0,
        &ulQop);

    if (!SEC_SUCCESS(ss))
    {
        fprintf(stderr, "DecryptMessage failed");
    }

    //-------------------------------------------------------------------
    //  Return a pointer to the decrypted data. The trailer data
    //  is discarded.

    return pDataBuffer;

}

PBYTE VerifyThis(
    PBYTE   pBuffer,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbMaxSignature)
{

    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    PBYTE             pSigBuffer;
    PBYTE             pDataBuffer;

    //-------------------------------------------------------------------
    //  The global cbMaxSignature is the size of the signature
    //  in the message received.

    printf("data before verifying (including signature):\n");
    PrintHexDump(*pcbMessage, pBuffer);

    //--------------------------------------------------------------------
    //  By agreement with the server, 
    //  the signature is at the beginning of the message received,
    //  and the data that was signed comes after the signature.

    pSigBuffer = pBuffer;
    pDataBuffer = pBuffer + cbMaxSignature;

    //-------------------------------------------------------------------
    //  The size of the message is reset to the size of the data only.

    *pcbMessage = *pcbMessage - (cbMaxSignature);

    //--------------------------------------------------------------------
    //  Prepare the buffers to be passed to the signature verification 
    //  function.

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].cbBuffer = cbMaxSignature;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer = pSigBuffer;

    SecBuff[1].cbBuffer = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer = pDataBuffer;

    ss = VerifySignature(
        hCtxt,
        &BuffDesc,
        0,
        &ulQop
    );

    if (!SEC_SUCCESS(ss))
    {
        fprintf(stderr, "VerifyMessage failed");
    }
    else
    {
        printf("Message was properly signed.\n");
    }

    return pDataBuffer;

}  // end VerifyThis
BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    ULONG* pcbOutput,
    ULONG cbSecurityTrailer,
    PCtxtHandle hctxt)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    ULONG             SigBufferSize;

    //-----------------------------------------------------------------
    //  The size of the trailer (signature + padding) block is 
    //  determined from the global cbSecurityTrailer.

    SigBufferSize = cbSecurityTrailer;

    printf("Data before encryption: %s\n", pMessage);
    printf("Length of data before encryption: %d \n", cbMessage);

    //-----------------------------------------------------------------
    //  Allocate a buffer to hold the signature,
    //  encrypted data, and a DWORD  
    //  that specifies the size of the trailer block.

    *ppOutput = (PBYTE)malloc(
        SigBufferSize + cbMessage + sizeof(DWORD));

    //------------------------------------------------------------------
    //  Prepare buffers.

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].cbBuffer = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer = *ppOutput + sizeof(DWORD);

    SecBuff[1].cbBuffer = cbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer = pMessage;

    ss = EncryptMessage(
        hctxt,
        ulQop,
        &BuffDesc,
        0);

    if (!SEC_SUCCESS(ss))
    {
        fprintf(stderr, "EncryptMessage failed: 0x%08x\n", ss);
        return(FALSE);
    }
    else
    {
        printf("The message has been encrypted. \n");
    }

    //------------------------------------------------------------------
    //  Indicate the size of the buffer in the first DWORD. 

    *((DWORD*)*ppOutput) = SecBuff[0].cbBuffer;

    //-----------------------------------------------------------------
    //  Append the encrypted data to our trailer block
    //  to form a single block. 
    //  Putting trailer at the beginning of the buffer works out 
    //  better. 

    memcpy(*ppOutput + SecBuff[0].cbBuffer + sizeof(DWORD), pMessage,
        cbMessage);

    *pcbOutput = cbMessage + SecBuff[0].cbBuffer + sizeof(DWORD);

    printf("data after encryption including trailer (%lu bytes):\n",
        *pcbOutput);
    PrintHexDump(*pcbOutput, *ppOutput);

    return TRUE;

}  // end EncryptThis


void PrintHexDump(
    DWORD length,
    PBYTE buffer)
{
    DWORD i, count, index;
    CHAR rgbDigits[] = "0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;

    for (index = 0; length;
        length -= count, buffer += count, index += count)
    {
        count = (length > 16) ? 16 : length;

        sprintf_s(rgbLine, 100, "%4.4x  ", index);
        cbLine = 6;

        for (i = 0; i < count; i++)
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if (i == 7)
            {
                rgbLine[cbLine++] = ':';
            }
            else
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for (; i < 16; i++)
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for (i = 0; i < count; i++)
        {
            if (buffer[i] < 32 || buffer[i] > 126)
            {
                rgbLine[cbLine++] = '.';
            }
            else
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        printf("%s\n", rgbLine);
    }
}

BOOL SendMsg(
    SOCKET  s,
    PBYTE   pBuf,
    DWORD   cbBuf)
{
    if (0 == cbBuf)
        return(TRUE);

    //----------------------------------------------------------
    //  Send the size of the message.

    if (!SendBytes(s, (PBYTE)&cbBuf, sizeof(cbBuf)))
        return(FALSE);

    //----------------------------------------------------------
    //  Send the body of the message.

    if (!SendBytes(
        s,
        pBuf,
        cbBuf))
    {
        return(FALSE);
    }

    return(TRUE);
}

BOOL ReceiveMsg(
    SOCKET  s,
    PBYTE   pBuf,
    DWORD   cbBuf,
    DWORD* pcbRead)

{
    DWORD cbRead;
    DWORD cbData;

    //----------------------------------------------------------
    //  Receive the number of bytes in the message.

    if (!ReceiveBytes(
        s,
        (PBYTE)&cbData,
        sizeof(cbData),
        &cbRead))
    {
        return(FALSE);
    }

    if (sizeof(cbData) != cbRead)
        return(FALSE);
    //----------------------------------------------------------
    //  Read the full message.

    if (!ReceiveBytes(
        s,
        pBuf,
        cbData,
        &cbRead))
    {
        return(FALSE);
    }

    if (cbRead != cbData)
        return(FALSE);

    *pcbRead = cbRead;
    return(TRUE);
}  // end ReceiveMessage    

BOOL SendBytes(
    SOCKET  s,
    PBYTE   pBuf,
    DWORD   cbBuf)
{
    PBYTE pTemp = pBuf;
    int   cbSent;
    int   cbRemaining = cbBuf;

    if (0 == cbBuf)
        return(TRUE);

    while (cbRemaining)
    {
        cbSent = send(
            s,
            (const char*)pTemp,
            cbRemaining,
            0);
        if (SOCKET_ERROR == cbSent)
        {
            fprintf(stderr, "send failed: %u\n", GetLastError());
            return FALSE;
        }

        pTemp += cbSent;
        cbRemaining -= cbSent;
    }

    return TRUE;
}

BOOL ReceiveBytes(
    SOCKET  s,
    PBYTE   pBuf,
    DWORD   cbBuf,
    DWORD* pcbRead)
{
    PBYTE pTemp = pBuf;
    int cbRead, cbRemaining = cbBuf;

    while (cbRemaining)
    {
        cbRead = recv(
            s,
            (char*)pTemp,
            cbRemaining,
            0);
        if (0 == cbRead)
            break;
        if (SOCKET_ERROR == cbRead)
        {
            fprintf(stderr, "recv failed: %u\n", GetLastError());
            return FALSE;
        }

        cbRemaining -= cbRead;
        pTemp += cbRead;
    }

    *pcbRead = cbBuf - cbRemaining;

    return TRUE;
}  // end ReceiveBytes


void MyHandleError(const char* s)
{

    fprintf(stderr, "%s error. Exiting.\n", s);
    exit(EXIT_FAILURE);
}