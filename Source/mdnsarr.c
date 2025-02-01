/*
    mdnsarr - mDNS A Record Responder
    (c) 2025 Ricci Adams

    Heavily based on Mattias Jansson's mDNS/DNS-SD library
    https://github.com/mjansson/mdns

    Public Domain
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


typedef struct mDNSString {
    void *bytes;
    size_t length;
} mDNSString;


typedef struct mDNSRecord {
    mDNSString domain;
    in_addr_t addr;
    struct mDNSRecord *next;
} mDNSRecord;


static uint16_t sPort = 5353;


static int sStringsEqual(mDNSString aString, mDNSString bString)
{
    if (aString.length != bString.length) {
        return 0;
    }
    
    uint8_t *a = aString.bytes;
    uint8_t *b = bString.bytes;
    uint8_t *aEnd = aString.bytes + aString.length;
    
    uint8_t labelCount = 0;

    while (a < aEnd) {
        if (labelCount > 0) {
            if (tolower(*a) != tolower(*b)) {
                return 0;
            }

            labelCount--;

        } else {
            if (*a != *b) {
                return 0;
            }
            
            labelCount = *a;
        }

        a++;
        b++;
    }

    return 1;
}


static int sSendBytes(int sock, const void *buffer, size_t size)
{
	struct sockaddr_storage addr_storage;
	struct sockaddr_in addr = {0};

	struct sockaddr* saddr = (struct sockaddr*)&addr_storage;
	socklen_t saddrlen = sizeof(struct sockaddr_storage);
	if (getsockname(sock, saddr, &saddrlen))
		return -1;

    addr.sin_family = AF_INET;
    addr.sin_len = sizeof(addr);
    addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
    addr.sin_port = htons((unsigned short)sPort);
    saddr = (struct sockaddr*)&addr;
    saddrlen = sizeof(addr);

	if (sendto(sock, buffer, size, 0, saddr, saddrlen) < 0)
		return -1;
	return 0;
}


static void sSendRecord(int sock, uint16_t queryID, mDNSRecord *record)
{
    void *output = alloca(1024);
    __block void *o = output;
 
    __auto_type writeInt16 = ^(uint16_t n) {
        *(uint16_t *)o = htons(n);
        o += 2;
    };

    __auto_type writeBytes = ^(const void *bytes, size_t length) {
        memcpy(o, bytes, length);
        o += length;
    };

    writeInt16(queryID);
    writeInt16(0x8400);    // flags. QR=1, AA=1
    writeInt16(0);         // question count
    writeInt16(1);         // answer count
    writeInt16(0);         // authority count
    writeInt16(0);         // additional count
    
    writeBytes(record->domain.bytes, record->domain.length);
    
	writeInt16(1);  // record type = A
    writeInt16(1);  // record class = IN
    writeInt16(0);  // TTL, top two bytes
    writeInt16(60); // TTL = 60 seconds
    writeInt16(4);  // RD length = 4
    
    writeBytes(&record->addr, 4);

    sSendBytes(sock, output, o - output);
}


static void sHandleMessage(
    int sock,
    void *message, size_t messageLength,
    mDNSRecord *records
) {
    __block void *m = message;
    
    __auto_type readInt16 = ^{
        uint16_t result = ntohs(*(uint16_t *)m);
        m += 2;
        return result;
    };

    if (messageLength < 13) return;

	uint16_t queryID         = readInt16();
    uint16_t flags           = readInt16();
	uint16_t questionCount   = readInt16();
    uint16_t answerCount     = readInt16();
    uint16_t authorityCount  = readInt16();
    uint16_t additionalCount = readInt16();

    // Check that QR=0 and Opcode=0
    if ((flags & 0xf800) != 0) {
        return;
    }

    if (
        questionCount   != 1 ||
        answerCount     != 0 ||
        authorityCount  != 0 ||
        additionalCount != 0
    ) {
        return;
    }

    //
    mDNSString messageDomain = {0};
    {
        messageDomain.bytes = m;
        
        while (m < (message + messageLength)) {
            messageDomain.length++;
            if (*(uint8_t *)m++ == 0) break;
        }
    }

    mDNSRecord *foundRecord = NULL;
    mDNSRecord *currentRecord = records;

    while (currentRecord) {
        if (sStringsEqual(currentRecord->domain, messageDomain)) {
            foundRecord = currentRecord;
            break;
        }
        
        currentRecord = currentRecord->next;
    }
    
    if (!foundRecord) return;
    
    size_t bytesRemaining = messageLength - (m - message);
    if (bytesRemaining < 4) return;

    uint16_t recordType  = readInt16();
    uint16_t recordClass = readInt16();

    // 1 = A record, 255 = Any
    if ((recordType != 1) && (recordType != 255)) {
        return;
    }
    
    // Remove mDNS flush bit
    recordClass = recordClass & ~0x8000U;

    // 1 = IN class, 255 = Any
    if ((recordClass != 1) && (recordClass != 255)) {
        return;
    }

    sSendRecord(sock, queryID, foundRecord);
}


// Open sockets to listen to incoming mDNS queries on port 5353
static int sMakeSocket(void)
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) goto fail;

	unsigned char true8 = 1;
	unsigned int  true32 = 1;
    struct in_addr any = { .s_addr = INADDR_ANY };

    struct sockaddr_in sockAddr = {0};

    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr = any;
    sockAddr.sin_port = htons(sPort);
    sockAddr.sin_len = sizeof(struct sockaddr_in);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true32, sizeof(true32));
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &true32, sizeof(true32));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,  &true8, sizeof(true8));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &true8, sizeof(true8));

	struct ip_mreq req = {0};
	req.imr_multiaddr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
    req.imr_interface = any;
	
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req)) != 0) {
        goto fail;
    }

    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &any, sizeof(any));

	if (bind(sock, (struct sockaddr *)&sockAddr, sizeof(struct sockaddr_in)) != 0) {
        goto fail;
    }

	const int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	return sock;

fail:
    if (sock) close(sock);

	return 0;
}


static mDNSRecord *sParseConfigurationC(const char *path)
{
    __block mDNSRecord *result = NULL;

    // Converts standard host string to special DNS label format
    // Input:  "moo.oink.local"
    // Output: "<0x03>moo<0x04>oink<0x05>local"
    __auto_type parseDomain = ^(const char *input) {
        size_t outputLength = strlen(input) + 2;
        char *output = malloc(outputLength);

        mDNSString result;
        result.bytes = output;
        result.length = outputLength;

        while (1) {
            char *sizeByte = output;
            output++;
            
            char currentByte = 0;
            char currentSize = 0;
            
            while (1) {
                currentByte = *input++;
                
                if (currentByte == '.' || currentByte == 0) {
                    break;
                }
                
                *output++ = currentByte;
                currentSize++;
            }
            
            *sizeByte = currentSize;
            
            if (currentByte == 0) break;
        }
        
        return result;
    };

    __auto_type parseLine = ^(const char *line) {
        char *lineCopy = malloc(strlen(line));
        strcpy(lineCopy, line);
        
        char *ipAddress = strtok(lineCopy, " \t\r\n");
        char *domain    = ipAddress ? strtok(NULL, " \t\r\n") : NULL;

        if (ipAddress && domain) {
            mDNSRecord *record = malloc(sizeof(mDNSRecord));

            record->domain = parseDomain(domain);
            record->addr = inet_addr(ipAddress);
            record->next = result;
            
            result = record;
        }
        
        free(lineCopy);
    };

    __auto_type parseFile = ^(const char *path) {
        FILE *file = fopen(path, "r");

        char *currentLine = NULL;
        size_t currentLength = 0;

        while (getline(&currentLine, &currentLength, file) != -1) {
            parseLine(currentLine);
        }
        
        free(currentLine);
        fclose(file);
    };
    
    parseFile(path);

    return result;
}


int main(int argc, const char* const* argv)
{
    mDNSRecord *records = sParseConfigurationC("/etc/mdnsarrr");
        
    int socket = sMakeSocket();

	if (!socket) {
		printf("Failed to make socket\n");
		exit(1);
	}

	size_t inputCapacity = 2048;
	void *inputBuffer = malloc(inputCapacity);
 
	while (1) {
		fd_set fdset;
		FD_ZERO(&fdset);
        FD_SET(socket, &fdset);

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		if (select(socket + 1, &fdset, 0, 0, &timeout) >= 0) {
            if (FD_ISSET(socket, &fdset)) {
                ssize_t bytesRead = recvfrom(socket, inputBuffer, inputCapacity, 0, NULL, 0);

                if (bytesRead > 0) {
                    sHandleMessage(socket, inputBuffer, bytesRead, records);
                }
            }

            FD_SET(socket, &fdset);
		} else {
			break;
		}
	}

	free(inputBuffer);

    if (socket) close(socket);

    exit(0);

	return 0;
}
