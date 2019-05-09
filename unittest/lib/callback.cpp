//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//
// callback.cpp: Callback functions for SymCrypt and MsBignum
//

#include "precomp.h"


//
// Format of checked allocation:
// 8 bytes, SIZE_T of original allocation
// 8 bytes magic
// <inner buffer>
// 8 bytes magic
//

volatile INT64 g_nOutstandingCheckedAllocs = 0;
volatile INT64 g_nAllocs = 0;

volatile INT64 g_nOutstandingCheckedAllocsMsBignum = 0;
volatile INT64 g_nAllocsMsBignum = 0;

BYTE g_bAllocFill= 0;

UINT64 g_magic;

VOID
SYMCRYPT_CALL
AllocWithChecksInit()
{
    while( (g_bAllocFill = g_rng.byte()) == 0 );

    BCryptGenRandom( NULL, (PBYTE) &g_magic, sizeof( g_magic ), BCRYPT_USE_SYSTEM_PREFERRED_RNG );
}

PVOID
SYMCRYPT_CALL
AllocWithChecks( SIZE_T nBytes, volatile INT64 * pOutstandingAllocs, volatile INT64 * pAllocs )
{
    PBYTE p;
    PBYTE res;
    ULONG offset;
    SIZE_T nAllocated;

    CHECK( g_bAllocFill != 0, "AllocFill not initialized" );

    nAllocated = nBytes + SYMCRYPT_ASYM_ALIGN_VALUE + 16 + 8;   // alignment + 16 byte prefix + 8 byte postfix
    CHECK( (ULONG) nAllocated == nAllocated, "?" );

    p = new BYTE[ nAllocated ];

    // We randomize the fill value a bit to ensure that unused space isn't fully predictable.
    // (We had a bug where ModElementIsEqual tested equality of uninitialized space, and it worked...)
    memset( p, (BYTE)(g_bAllocFill ^ (g_rng.byte() & 1)), nAllocated );

    // Result is first aligned value at least 16 bytes into the buffer
    res = (PBYTE) (((ULONG_PTR)p + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~(SYMCRYPT_ASYM_ALIGN_VALUE-1) );

    offset = (ULONG)(res - p);
    CHECK( offset >= 16 && offset < 256, "?" );

    *(ULONGLONG *) &res[-8] = g_magic ^ (SIZE_T) res ^ 'strt';
    *(ULONGLONG *) &res[nBytes ] = g_magic ^ (SIZE_T) res ^ 'end.'; 
    *(ULONG *) &res[-12] = (UINT32) nBytes;
    *(ULONG *) &res[-16] = offset;

    InterlockedIncrement64( pOutstandingAllocs );
    InterlockedIncrement64( pAllocs );
    return res;
}

PVOID
SYMCRYPT_CALL
AllocWithChecksSc( SIZE_T nBytes )
{
    return AllocWithChecks( nBytes, &g_nOutstandingCheckedAllocs, &g_nAllocs );
}

PVOID
SYMCRYPT_CALL
AllocWithChecksMsBignum( SIZE_T nBytes )
{
    return AllocWithChecks( nBytes, &g_nOutstandingCheckedAllocsMsBignum, &g_nAllocsMsBignum );
}

VOID
FreeWithChecks( PVOID ptr, volatile INT64 * pOutstandingAllocs )
{
    PBYTE p;
    SIZE_T nBytes;

    p = (PBYTE) ptr;
    nBytes = *(ULONG *) &p[-12];

    if (!g_perfTestsRunning)
    {
        for( SIZE_T i=0; i<nBytes; i++ )
        {
            CHECK( p[i] == 0 || p[i] == g_bAllocFill, "Free called with nonzero remenant data" );
        }
    }

    CHECK( *(ULONGLONG *)&p[-8] == (g_magic ^ (SIZE_T) p ^ 'strt'), "Left magic corrupted" );
    CHECK( *(ULONGLONG *)&p[nBytes] == (g_magic ^ (SIZE_T) p ^ 'end.'), "Right magic corrupted" );
    CHECK( InterlockedDecrement64( pOutstandingAllocs ) != -1, "?" );
    delete[] ( p - *(ULONG *)&p[-16] );
}

VOID
FreeWithChecksSc( PVOID ptr )
{
    FreeWithChecks( ptr, &g_nOutstandingCheckedAllocs );
}

VOID
FreeWithChecksMsBignum( PVOID ptr )
{
    FreeWithChecks( ptr, &g_nOutstandingCheckedAllocsMsBignum );
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    return AllocWithChecksSc( nBytes );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree( PVOID ptr )
{
    FreeWithChecksSc( ptr );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = STATUS_SUCCESS;

    CHECK( cbBuffer < 0xffffffff, "Random buffer too large" );

    status = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, pbBuffer, (UINT32) cbBuffer, 0 );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

//
// Callback functions for MsBignum
//



#if defined(__cplusplus)
extern "C" {
#endif



#if defined(__cplusplus)
}
#endif