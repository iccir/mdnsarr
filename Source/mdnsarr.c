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
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>


typedef struct mDNSString {
    uint8_t *bytes;
    size_t length;
} mDNSString;


typedef struct mDNSRecord {
    mDNSString domain;
    in_addr_t addr;
    struct mDNSRecord *next;
} mDNSRecord;


static const char *sConfigPath = "/etc/mdnsarr";
static uint16_t sPort = 5353;


static bool sStringsEqual(mDNSString aString, mDNSString bString)
{
    if (aString.length != bString.length) {
        return false;
    }
    
    uint8_t *a = aString.bytes;
    uint8_t *b = bString.bytes;
    uint8_t *aEnd = aString.bytes + aString.length;
    
    uint8_t labelCount = 0;

    while (a < aEnd) {
        if (labelCount > 0) {
            if (tolower(*a) != tolower(*b)) {
                return false;
            }

            labelCount--;

        } else {
            if (*a != *b) {
                return false;
            }
            
            labelCount = *a;
        }

        a++;
        b++;
    }

    return true;
}


static void sSendBytes(int sock, const void *buffer, size_t size)
{
	struct sockaddr_storage storage;
	struct sockaddr_in addr = {0};

	struct sockaddr *saddr = (struct sockaddr *)&storage;
	socklen_t saddrlen = sizeof(struct sockaddr_storage);

	if (getsockname(sock, saddr, &saddrlen) != 0) {
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_len = sizeof(addr);
    addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
    addr.sin_port = htons((unsigned short)sPort);
    saddr = (struct sockaddr *)&addr;
    saddrlen = sizeof(addr);

	sendto(sock, buffer, size, 0, saddr, saddrlen);
}


static void sSendAnswers(int sock, uint16_t queryID, mDNSRecord **toAnswer, size_t toAnswerCount)
{
    size_t outputLength = 2048;
    void *output = alloca(outputLength);
    __block void *o = output;
 
    __auto_type ensure = ^(size_t length) {
        return (o + length) < (output + outputLength);
    };
 
    __auto_type writeInt16 = ^(uint16_t n) {
        if (!ensure(2)) return;
        *(uint16_t *)o = htons(n);
        o += 2;
    };

    __auto_type writeBytes = ^(const void *bytes, size_t length) {
        if (!ensure(length)) return;
        memcpy(o, bytes, length);
        o += length;
    };

    writeInt16(queryID);
    writeInt16(0x8400);        // flags. QR=1, AA=1
    writeInt16(0);             // question count
    writeInt16(toAnswerCount); // answer count
    writeInt16(0);             // authority count
    writeInt16(0);             // additional count
    
    for (size_t i = 0; i < toAnswerCount; i++) {
        mDNSRecord *record = toAnswer[i];

        writeBytes(record->domain.bytes, record->domain.length);
    
        writeInt16(1);  // record type = A
        writeInt16(1);  // record class = IN
        writeInt16(0);  // TTL, top two bytes
        writeInt16(60); // TTL = 60 seconds
        writeInt16(4);  // RD length = 4
    
        writeBytes(&record->addr, 4);
    }

    if (ensure(0)) {
        sSendBytes(sock, output, o - output);
    }
}


static void sHandleMessage(
    int sock,
    void *message, size_t messageLength,
    mDNSRecord *records
) {
    __block bool invalid = false;

    __block void *m = message;
    
    __block mDNSString domain;
    size_t domainCapacity = 512;
    domain.bytes  = alloca(domainCapacity);
    domain.length = 0;
    
    __auto_type writeDomainByte = ^(uint8_t c) {
        if (domain.length < domainCapacity) {
            domain.bytes[domain.length] = c;
            domain.length++;
        } else {
            invalid = true;
        }
    };

    __auto_type readByte = ^{
        uint8_t result = 0;

        if (m < (message + messageLength)) {
            result = *(uint8_t *)m;
            m += 1;
        } else {
            invalid = true;
        }

        return result;
    };

    __auto_type readInt16 = ^{
        return (readByte() << 8) | readByte();
    };

    __block void (^readDomain)(size_t) = ^(size_t recursionCount) {
        while (1) {
            uint8_t labelLength = readByte();
            
            // This is a reference
            if ((labelLength & 0xc0) == 0xc0) {
                uint16_t offset = ((labelLength & 0x3f) << 8) + readByte();

                if (recursionCount < 8) {
                    void *oldM = m;
                    m = message + offset;
                    readDomain(recursionCount + 1);
                    m = oldM;

                } else {
                    invalid = true;
                }

                break;

            } else if (labelLength > 0) {
                writeDomainByte(labelLength);

                for (uint8_t i = 0; i < labelLength; i++) {
                    writeDomainByte(readByte());
                }

            } else {
                writeDomainByte(0);
                break;
            }
        }
    };

    __auto_type readQuestion = ^{
        mDNSRecord *foundRecord = NULL;

        domain.length = 0;
        readDomain(0);
        
        uint16_t recordType  = readInt16();
        uint16_t recordClass = readInt16();

        // 1 = A record, 255 = Any
        if ((recordType != 1) && (recordType != 255)) {
            return foundRecord;
        }
        
        // Remove mDNS flush bit
        recordClass = recordClass & ~0x8000U;

        // 1 = IN class, 255 = Any
        if ((recordClass != 1) && (recordClass != 255)) {
            return foundRecord;
        }

        mDNSRecord *currentRecord = records;

        while (currentRecord) {
            if (sStringsEqual(currentRecord->domain, domain)) {
                foundRecord = currentRecord;
                break;
            }
            
            currentRecord = currentRecord->next;
        }

        return foundRecord;
    };

	uint16_t queryID         = readInt16();
    uint16_t flags           = readInt16();
	uint16_t questionCount   = readInt16();

    // Check that QR=0 and Opcode=0
    if ((flags & 0xf800) != 0) {
        return;
    }

    if (!questionCount) return;
    
    readInt16(); // answer count
    readInt16(); // authority count
    readInt16(); // additional count

    mDNSRecord **toAnswer = alloca(questionCount * sizeof(mDNSRecord *));
    memset(toAnswer, 0, questionCount * sizeof(mDNSRecord *));

    size_t toAnswerCount = 0;
    
    for (size_t i = 0; i < questionCount; i++) {
        mDNSRecord *record = readQuestion();
        
        if (invalid) return;
        
        if (record) {
            toAnswer[toAnswerCount] = record;
            toAnswerCount++;
        }
    }

    if (toAnswerCount == 0) return;
    
    sSendAnswers(sock, queryID, toAnswer, toAnswerCount);
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


static mDNSRecord *sParseConfiguration(const char *path)
{
    __block mDNSRecord *result = NULL;

    // Converts standard host string to special DNS label format
    // Input:  "moo.oink.local"
    // Output: "<0x03>moo<0x04>oink<0x05>local"
    __auto_type parseDomain = ^(const char *input) {
        size_t outputLength = strlen(input) + 2;
        uint8_t *output = malloc(outputLength);

        mDNSString result;
        result.bytes = output;
        result.length = outputLength;

        while (1) {
            uint8_t *sizeByte = output;
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
            
            if (currentByte == 0 || currentSize == 0) break;
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
    mDNSRecord *records = sParseConfiguration(sConfigPath);
        
    int socket = sMakeSocket();

	if (!socket) {
		fprintf(stderr, "Failed to make socket\n");
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
            exit(1);
		}
	}

    // Unreachable
	return 0;
}
