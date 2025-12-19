#ifndef LESS_H
#define LESS_H

// Function specifiers in case library is build/used as a shared library (Windows)
// NOTE: Microsoft specifiers to tell compiler that symbols are imported/exported from a .dll
#if defined(_WIN32)
    #if defined(BUILD_LIBTYPE_SHARED)
        #define LESSAPI __declspec(dllexport)     // We are building the library as a Win32 shared library (.dll)
    #elif defined(USE_LIBTYPE_SHARED)
        #define LESSAPI __declspec(dllimport)     // We are using the library as a Win32 shared library (.dll)
    #endif
#endif

// Function specifiers definition
#ifndef LESSAPI
    #define LESSAPI       // Functions defined as 'extern' by default (implicit specifiers)
#endif

//----------------------------------------------------------------------------------
// Defines and Macros
//----------------------------------------------------------------------------------

// Allow custom memory allocators
#ifndef LESS_MALLOC
    #define LESS_MALLOC(sz)         malloc(sz)
#endif
#ifndef LESS_CALLOC
    #define LESS_CALLOC(ptr,sz)     calloc(ptr,sz)
#endif
#ifndef LESS_REALLOC
    #define LESS_REALLOC(ptr,sz)    realloc(ptr,sz)
#endif
#ifndef LESS_FREE
    #define LESS_FREE(ptr)          free(ptr)
#endif

// Simple log system to avoid printf() calls if required
// NOTE: Avoiding those calls, also avoids const strings memory usage
#define LESS_SUPPORT_LOG_INFO
#if defined(LESS_SUPPORT_LOG_INFO)
    #define LESS_LOG(...) printf(__VA_ARGS__)
#else
    #define LESS_LOG(...)
#endif

// On Windows, MAX_PATH is limited to 256 by default,
// on Linux, it could go up to 4096
#define LESS_MAX_FILENAME_SIZE      1024

//----------------------------------------------------------------------------------
// Types and Structures Definition
//----------------------------------------------------------------------------------
// less file header (16 bytes)
typedef struct lessFileHeader {
    unsigned char id[4];            // File identifier: less
    unsigned short version;         // File version: 100 for version 1.0
    unsigned short chunkCount;      // Number of resource chunks in the file (MAX: 65535)
    unsigned int cdOffset;          // Central Directory offset in file (0 if not available)
    unsigned int reserved;          // <reserved>
} lessFileHeader;

// less resource chunk info header (32 bytes)
typedef struct lessResourceChunkInfo {
    unsigned char type[4];          // Resource chunk type (FourCC)
    unsigned int id;                // Resource chunk identifier (generated from filename CRC32 hash)
    unsigned char compType;         // Data compression algorithm
    unsigned char cipherType;       // Data encription algorithm
    unsigned short flags;           // Data flags (if required)
    unsigned int packedSize;        // Data chunk size (compressed/encrypted + custom data appended)
    unsigned int baseSize;          // Data base size (uncompressed/unencrypted)
    unsigned int nextOffset;        // Next resource chunk global offset (if resource has multiple chunks)
    unsigned int reserved;          // <reserved>
    unsigned int crc32;             // Data chunk CRC32 (propCount + props[] + data)
} lessResourceChunkInfo;

// less resource chunk data
typedef struct lessResourceChunkData {
    void *raw;                      // Resource chunk raw data
} lessResourceChunkData;

// less resource chunk
typedef struct lessResourceChunk {
    lessResourceChunkInfo info;     // Resource chunk info
    lessResourceChunkData data;     // Resource chunk packed data, contains propCount, props[] and raw data
} lessResourceChunk;

// less resource multi
// NOTE: It supports multiple resource chunks
typedef struct lessResourceMulti {
    unsigned int count;             // Resource chunks count
    lessResourceChunk *chunks;      // Resource chunks
} lessResourceMulti;

// Useful data types for specific chunk types
//----------------------------------------------------------------------
// CDIR: less central directory entry
typedef struct lessDirEntry {
    unsigned int id;                // Resource id
    unsigned int offset;            // Resource global offset in file
    unsigned int reserved;          // reserved
    unsigned int fileNameSize;      // Resource fileName size (NULL terminator and 4-byte alignment padding considered)
    char fileName[LESS_MAX_FILENAME_SIZE];  // Resource original fileName (NULL terminated and padded to 4-byte alignment)
} lessDirEntry;

// CDIR: less central directory
// NOTE: This data conforms the lessResourceChunkData
typedef struct lessCentralDir {
    unsigned int count;             // Central directory entries count
    lessDirEntry *entries;          // Central directory entries
} lessCentralDir;

typedef enum lessResourceDataType {
    LESS_DATA_NULL         = 0,             // FourCC: NULL - Reserved for empty chunks, no props/data
    LESS_DATA_RAW          = 1,             // FourCC: RAWD - Raw file data, 4 properties
    LESS_DATA_DIRECTORY    = 100,           // FourCC: CDIR - Central directory for input files
                                            //    props[0]:entryCount, 1 property
                                            //    data: lessDirEntry[0..entryCount]
} lessResourceDataType;

// Compression algorithms
// Value required by lessResourceChunkInfo.compType
// NOTE 1: This enum just list some common data compression algorithms for convenience,
// The less packer tool and the engine-specific library are responsible to implement the desired ones,
// NOTE 2: lessResourceChunkInfo.compType is a byte-size value, limited to [0..255]
typedef enum lessCompressionType {
    LESS_COMP_NONE          = 0,            // No data compression
    LESS_COMP_LZ4           = 20,           // LZ4 compression
} lessCompressionType;


// TODO: less error codes (not used at this moment)
// NOTE: Error codes when processing less files
typedef enum lessErrorType {
    LESS_SUCCESS = 0,                       // less file loaded/saved successfully
    LESS_ERROR_FILE_NOT_FOUND,              // less file can not be opened (spelling issues, file actually does not exist...)
    LESS_ERROR_FILE_FORMAT,                 // less file format not a supported (wrong header, wrong identifier)
    LESS_ERROR_MEMORY_ALLOC,                // Memory could not be allocated for operation
} lessErrorType;


//----------------------------------------------------------------------------------
// Module Functions Declaration
//----------------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {            // Prevents name mangling of functions
#endif

// Load only one resource chunk (first resource id found)
LESSAPI lessResourceChunk lessLoadResourceChunk(const char *fileName, unsigned int lessId);  // Load one resource chunk for provided id
LESSAPI void lessUnloadResourceChunk(lessResourceChunk chunk);                      // Unload resource chunk from memory

// Load multi resource chunks for a specified lessId
LESSAPI lessResourceMulti lessLoadResourceMulti(const char *fileName, unsigned int lessId);  // Load resource for provided id (multiple resource chunks)
LESSAPI void lessUnloadResourceMulti(lessResourceMulti multi);                      // Unload resource from memory (multiple resource chunks)

// Load resource(s) chunk info from file
LESSAPI lessResourceChunkInfo lessLoadResourceChunkInfo(const char *fileName, unsigned int lessId);  // Load resource chunk info for provided id
LESSAPI lessResourceChunkInfo *lessLoadResourceChunkInfoAll(const char *fileName, unsigned int *chunkCount); // Load all resource chunks info

LESSAPI lessCentralDir lessLoadCentralDirectory(const char *fileName);              // Load central directory resource chunk from file
LESSAPI void lessUnloadCentralDirectory(lessCentralDir dir);                        // Unload central directory resource chunk

LESSAPI unsigned int lessGetDataType(const unsigned char *fourCC);                  // Get lessResourceDataType from FourCC code
LESSAPI int lessGetResourceId(lessCentralDir dir, const char *fileName);            // Get resource id for a provided filename
                                                                                    // NOTE: It requires CDIR available in the file (it's optinal by design)
LESSAPI unsigned int lessComputeCRC32(const unsigned char *data, int len);          // Compute CRC32 for provided data

// Manage password for data encryption/decryption
// NOTE: The cipher password is kept as an internal pointer to provided string, it's up to the user to manage that sensible data properly
// Password should be to allocate and set before loading an encrypted resource and it should be cleaned/wiped after the encrypted resource has been loaded
// TODO: Move this functionality to engine-library, after all less.h does not manage data decryption
LESSAPI void lessSetCipherPassword(const char *pass);                 // Set password to be used on data decryption
LESSAPI const char *lessGetCipherPassword(void);                      // Get password to be used on data decryption

#ifdef __cplusplus
}
#endif

#endif // LESS_H

/***********************************************************************************
*
*   LESS IMPLEMENTATION
*
************************************************************************************/

#if defined(LESS_IMPLEMENTATION)

// Boolean type
#if (defined(__STDC__) && __STDC_VERSION__ >= 199901L) || (defined(_MSC_VER) && _MSC_VER >= 1800)
    #include <stdbool.h>
#elif !defined(__cplusplus) && !defined(bool)
    typedef enum bool { false = 0, true = !false } bool;
    #define RL_BOOL_TYPE
#endif

#include <stdlib.h>                 // Required for: malloc(), calloc(), free()
#include <stdio.h>                  // Required for: FILE, fopen(), fseek(), fread(), fclose()
#include <string.h>                 // Required for: memcpy(), memcmp()

//----------------------------------------------------------------------------------
// Module Internal Functions Declaration
//----------------------------------------------------------------------------------
// Load resource chunk packed data into our data struct
static lessResourceChunkData lessLoadResourceChunkData(lessResourceChunkInfo info, void *packedData);

// verify that less file header is valid
static bool lessVerifyFileHeader(lessFileHeader header);

//----------------------------------------------------------------------------------
// Module Functions Definition
//----------------------------------------------------------------------------------
bool lessVerifyFileHeader(lessFileHeader header)
{
 return (header.id[0] == 'l') 
     && (header.id[1] == 'e') 
     && (header.id[2] == 's') 
     && (header.id[3] == 's')
     && (header.version == 120);
}


// Load one resource chunk for provided id
lessResourceChunk lessLoadResourceChunk(const char *fileName, unsigned int lessId)
{
    lessResourceChunk chunk = { 0 };
    FILE *lessFile = fopen(fileName, "rb");

    if (lessFile == NULL) LESS_LOG("LESS: WARNING: [%s] less file could not be opened\n", fileName);
    else
    {
        LESS_LOG("LESS: INFO: Loading resource from file: %s\n", fileName);

        lessFileHeader header = { 0 };

        // Read less file header
        fread(&header, sizeof(lessFileHeader), 1, lessFile);

        if ( lessVerifyFileHeader(header) ) {

            bool found = false;
            // Check all available chunks looking for the requested id
            for (int i = 0; i < header.chunkCount; i++)
            {
                lessResourceChunkInfo info = { 0 };

                // Read resource info header
                fread(&info, sizeof(lessResourceChunkInfo), 1, lessFile);

                // Check if resource id is the requested one
                if ( info.id == lessId ) {

                    found = true;
                    LESS_LOG("LESS: INFO: Found requested resource id: 0x%08x\n", info.id);
                    LESS_LOG("LESS: %c%c%c%c: Id: 0x%08x | Base size: %i | Packed size: %i\n", info.type[0], info.type[1], info.type[2], info.type[3], info.id, info.baseSize, info.packedSize);

                    if ( info.nextOffset != 0 )
                       LESS_LOG("LESS: WARNING: Multiple linked resource chunks available for the provided id");


                    void *data = LESS_CALLOC(info.packedSize, 1); 
                    fread(data, info.packedSize, 1, lessFile);    

                    chunk.data.raw = data;
                    chunk.info = info;

                    break;      // Resource id found and loaded, stop checking the file
                }
                else
                {
                    // Skip required data size to read next resource info header
                    fseek(lessFile, info.packedSize, SEEK_CUR);
                }
            }

            if (!found) LESS_LOG("LESS: WARNING: Requested resource not found: 0x%08x\n", lessId);
        }
        else LESS_LOG("LESS: WARNING: The provided file is not a valid less file, file signature or version not valid\n");

        fclose(lessFile);
    }

    return chunk;
}

// Unload resource chunk from memory
void lessUnloadResourceChunk(lessResourceChunk chunk)
{
    LESS_FREE(chunk.data.raw);    // Resource chunk raw data
}

// Load resource from file by id
// NOTE: All resources conected to base id are loaded
lessResourceMulti lessLoadResourceMulti(const char *fileName, unsigned int lessId)
{
    lessResourceMulti less = { 0 };
    FILE *lessFile = fopen(fileName, "rb");

    if (lessFile == NULL) LESS_LOG("LESS: WARNING: [%s] less file could not be opened\n", fileName);
    else
    {
        lessFileHeader header = { 0 };
        fread(&header, sizeof(lessFileHeader), 1, lessFile);

        if ( lessVerifyFileHeader(header) )
        {
            bool found = false;

            // Check all available chunks looking for the requested id
            for (int i = 0; i < header.chunkCount; i++)
            {
                lessResourceChunkInfo info = { 0 };

                // Read resource info header
                fread(&info, sizeof(lessResourceChunkInfo), 1, lessFile);

                // Check if resource id is the requested one
                if (info.id == lessId)
                {
                    found = true;

                    LESS_LOG("LESS: INFO: Found requested resource id: 0x%08x\n", info.id);
                    LESS_LOG("LESS: %c%c%c%c: Id: 0x%08x | Base size: %i | Packed size: %i\n", info.type[0], info.type[1], info.type[2], info.type[3], info.id, info.baseSize, info.packedSize);

                    less.count = 1;

                    long currentFileOffset = ftell(lessFile);               // Store current file position
                    lessResourceChunkInfo temp = info;                      // Temp info header to scan resource chunks

                    // Count all linked resource chunks checking temp.nextOffset
                    while (temp.nextOffset != 0)
                    {
                        fseek(lessFile, temp.nextOffset, SEEK_SET);         // Jump to next linked resource
                        fread(&temp, sizeof(lessResourceChunkInfo), 1, lessFile); // Read next resource info header
                        less.count++;
                    }

                    less.chunks = (lessResourceChunk *)LESS_CALLOC(less.count, sizeof(lessResourceChunk)); // Load as many less slots as required
                    fseek(lessFile, currentFileOffset, SEEK_SET);           // Return to first resource chunk position

                    // Read and load data chunk from file data
                    // NOTE: Read data can be compressed,
                    // it's up to the user library to manage decompression/decryption
                    void *data = LESS_CALLOC(info.packedSize, 1);           // Allocate enough memory to store resource data chunk
                    fread(data, info.packedSize, 1, lessFile);              // Read data: propsCount + props[] + data (+additional_data)

                    // Get chunk.data properly organized (only if uncompressed/unencrypted)
                    less.chunks[0].data.raw = data;
                    less.chunks[0].info = info;
                    int i = 1;

                    // Load all linked resource chunks
                    while (info.nextOffset != 0)
                    {
                        fseek(lessFile, info.nextOffset, SEEK_SET);         // Jump to next resource chunk
                        fread(&info, sizeof(lessResourceChunkInfo), 1, lessFile); // Read next resource info header

                        LESS_LOG("LESS: %c%c%c%c: Id: 0x%08x | Base size: %i | Packed size: %i\n", info.type[0], info.type[1], info.type[2], info.type[3], info.id, info.baseSize, info.packedSize);

                        void *data = LESS_CALLOC(info.packedSize, 1);       // Allocate enough memory to store resource data chunk
                        fread(data, info.packedSize, 1, lessFile);          // Read data: propsCount + props[] + data (+additional_data)

                        // Get chunk.data properly organized (only if uncompressed/unencrypted)
                        less.chunks[i].data.raw = data;
                        less.chunks[i].info = info;
                        i++;
                    }

                    break;      // Resource id found and loaded, stop checking the file
                }
                else
                {
                    // Skip required data size to read next resource info header
                    fseek(lessFile, info.packedSize, SEEK_CUR);
                }
            }

            if (!found) LESS_LOG("LESS: WARNING: Requested resource not found: 0x%08x\n", lessId);
        }
        else LESS_LOG("LESS: WARNING: The provided file is not a valid less file, file signature or version not valid\n");

        fclose(lessFile);
    }

    return less;
}

// Unload resource data
void lessUnloadResourceMulti(lessResourceMulti multi)
{
    for (unsigned int i = 0; i < multi.count; i++) lessUnloadResourceChunk(multi.chunks[i]);
    LESS_FREE(multi.chunks);
}

// Load resource chunk info for provided id
LESSAPI lessResourceChunkInfo lessLoadResourceChunkInfo(const char *fileName, unsigned int lessId)
{
    lessResourceChunkInfo info = { 0 };
    FILE *lessFile = fopen(fileName, "rb");

    if (lessFile != NULL)
    {
        lessFileHeader header = { 0 };
        fread(&header, sizeof(lessFileHeader), 1, lessFile);

        if ( lessVerifyFileHeader(header) )
        {
            // Try to find provided resource chunk id and read info chunk
            for (int i = 0; i < header.chunkCount; i++)
            {
                // Read resource chunk info
                fread(&info, sizeof(lessResourceChunkInfo), 1, lessFile);

                if (info.id == lessId)
                {
                    // TODO: Jump to next resource chunk for provided id
                    //if (info.nextOffset > 0) fseek(lessFile, info.nextOffset, SEEK_SET);

                    break; // If requested lessId is found, we return the read lessResourceChunkInfo
                }
                else fseek(lessFile, info.packedSize, SEEK_CUR); // Jump to next resource
            }
        }
        else LESS_LOG("LESS: WARNING: The provided file is not a valid less file, file signature or version not valid\n");

        fclose(lessFile);
    }

    return info;
}

// Load all resource chunks info
LESSAPI lessResourceChunkInfo *lessLoadResourceChunkInfoAll(const char *fileName, unsigned int *chunkCount)
{
    lessResourceChunkInfo *infos = { 0 };
    unsigned int count = 0;

    FILE *lessFile = fopen(fileName, "rb");

    if (lessFile != NULL)
    {
        lessFileHeader header = { 0 };
        fread(&header, sizeof(lessFileHeader), 1, lessFile);

        if ( lessVerifyFileHeader(header) )
        {
            // Load all resource chunks info
            infos = (lessResourceChunkInfo *)LESS_CALLOC(header.chunkCount, sizeof(lessResourceChunkInfo));
            count = header.chunkCount;

            for (unsigned int i = 0; i < count; i++)
            {
                fread(&infos[i], sizeof(lessResourceChunkInfo), 1, lessFile); // Read resource chunk info

                if (infos[i].nextOffset > 0) fseek(lessFile, infos[i].nextOffset, SEEK_SET); // Jump to next resource
                else fseek(lessFile, infos[i].packedSize, SEEK_CUR); // Jump to next resource
            }
        }
        else LESS_LOG("LESS: WARNING: The provided file is not a valid less file, file signature or version not valid\n");

        fclose(lessFile);
    }

    *chunkCount = count;
    return infos;
}

// Load central directory data
lessCentralDir lessLoadCentralDirectory(const char *fileName)
{
    lessCentralDir dir = { 0 };
    FILE *lessFile = fopen(fileName, "rb");

    if (lessFile != NULL)
    {
        lessFileHeader header = { 0 };
        fread(&header, sizeof(lessFileHeader), 1, lessFile);

        if ( lessVerifyFileHeader(header) )
        {
            // Check if there is a Central Directory available
            if (header.cdOffset == 0) LESS_LOG("LESS: WARNING: CDIR: No central directory found\n");
            else
            {
                lessResourceChunkInfo info = { 0 };

                fseek(lessFile, header.cdOffset, SEEK_SET); // Move to central directory position
                fread(&info, sizeof(lessResourceChunkInfo), 1, lessFile); // Read resource info

                // Verify resource type is CDIR
                if ((info.type[0] == 'C') && (info.type[1] == 'D') && (info.type[2] == 'I') && (info.type[3] == 'R'))
                {
                    LESS_LOG("LESS: CDIR: Central Directory found at offset: 0x%08x\n", header.cdOffset);

                    void *data = LESS_CALLOC(info.packedSize, 1);
                    fread(data, info.packedSize, 1, lessFile);

                    lessResourceChunkData chunkData = { 0 };
                    chunkData.raw = data;

                    dir.count = *(unsigned int*)chunkData.raw;
                    LESS_LOG("LESS: CDIR: Central Directory file entries count: %i\n", dir.count);

                    unsigned char *ptr = (unsigned char *)chunkData.raw + sizeof(int);
                    dir.entries = (lessDirEntry *)LESS_CALLOC(dir.count, sizeof(lessDirEntry));

                    for (unsigned int i = 0; i < dir.count; i++)
                    {
                        dir.entries[i].id = ((int *)ptr)[0];            // Resource id
                        dir.entries[i].offset = ((int *)ptr)[1];        // Resource offset in file
                        // NOTE: There is a reserved integer value before fileNameSize
                        dir.entries[i].fileNameSize = ((int *)ptr)[3];  // Resource fileName size

                        // Resource fileName, NULL terminated and 0-padded to 4-byte,
                        // fileNameSize considers NULL and padding
                        memcpy(dir.entries[i].fileName, ptr + 16, dir.entries[i].fileNameSize);

                        ptr += (16 + dir.entries[i].fileNameSize);      // Move pointer for next entry
                    }

                    LESS_FREE(chunkData.raw);
                }
            }
        }
        else LESS_LOG("LESS: WARNING: The provided file is not a valid less file, file signature or version not valid\n");

        fclose(lessFile);
    }

    return dir;
}

// Unload central directory data
void lessUnloadCentralDirectory(lessCentralDir dir)
{
    LESS_FREE(dir.entries);
}

// Get lessResourceDataType from FourCC code
// NOTE: Function expects to receive a char[4] array
unsigned int lessGetDataType(const unsigned char *fourCC)
{
    unsigned int type = 0;

    if ( fourCC != NULL ) {
        if (memcmp(fourCC, "NULL", 4) == 0) type = LESS_DATA_NULL;              
        else if (memcmp(fourCC, "RAWD", 4) == 0) type = LESS_DATA_RAW;          
        else if (memcmp(fourCC, "CDIR", 4) == 0) type = LESS_DATA_DIRECTORY;    
    }

    return type;
}


// Compute CRC32 hash
// NOTE: CRC32 is used as less id, generated from original filename
unsigned int lessComputeCRC32(const unsigned char *data, int len)
{
    static unsigned int crcTable[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };

    unsigned int crc = ~0u;
    for (int i = 0; i < len; i++) crc = (crc >> 8)^crcTable[data[i]^(crc&0xff)];

    return ~crc;
}


// Load user resource chunk from resource packed data (as contained in .less file)
// WARNING: Data can be compressed in those cases is up to the user to process it,
// and chunk.data.propCount = 0, chunk.data.props = NULL and chunk.data.raw contains all resource packed data
lessResourceChunkData lessLoadResourceChunkData(lessResourceChunkInfo info, void *data)
{
    lessResourceChunkData chunkData = { 0 };

    // CRC32 data validation, verify packed data is not corrupted
    unsigned int crc32 = lessComputeCRC32((const unsigned char *)data, info.packedSize);

    if ((lessGetDataType(info.type) != LESS_DATA_NULL) && (crc32 == info.crc32) ) chunkData.raw = data;
    if (crc32 != info.crc32) LESS_LOG("LESS: WARNING: [ID %i] CRC32 does not match, data can be corrupted\n", info.id);

    return chunkData;
}

#endif // LESS_IMPLEMENTATION
