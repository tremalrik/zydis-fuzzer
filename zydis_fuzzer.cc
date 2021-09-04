/*************************************************

  Fuzzer for the Zydis x86 disassembly library.

  Copyright (C) 2021  Dr. Tremalrik

  Distributed under the MIT licence.

*************************************************/


#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <csignal>



// recorded data for last instruction
uint8_t instr_buf[16];
int machine_mode_int;
const char *machine_mode_str;


// ---------------------------------------------------
//  Install a handler for SIGABRT, SIGSEGV, SIGBUS
//  that will print out the byte sequence of the
//  last instruction submitted to the decoder before
//  any of these signals are issued.
// ---------------------------------------------------

void sigabrt_handler( int signal_type )
    {
    int i;
    printf("\n");
    const char *sigstr;
    switch( signal_type ) {
        case SIGABRT: sigstr = "SIGABRT"; break;
        case SIGSEGV: sigstr = "SIGSEGV"; break;
        case SIGBUS:  sigstr = "SIGBUS";  break;
        default:      sigstr = "n/a";     break;
    }
    printf("Machine mode: %d (%s)\n", machine_mode_int, machine_mode_str);
    printf("Opcode at time of %s:\n", sigstr );
    for(i=0;i<16;i++)
        printf("%02X ", instr_buf[i] );
    printf("\n");
    fflush(stdout);
    exit( EXIT_FAILURE );
    }


int install_sigabrt_handler(void)
    {
    struct sigaction sa;
    sigemptyset( &(sa.sa_mask) );
    sa.sa_handler = sigabrt_handler;
    sa.sa_flags = 0;
    sigaction( SIGABRT, &sa, NULL );
    sigaction( SIGSEGV, &sa, NULL );
    sigaction( SIGBUS,  &sa, NULL );
    return 0;
    }


// ---------------------------------------------------
//   Random byte sequence generator, biased strongly
//   in favor of generating encodings that have many
//   x86 single-byte prefixes followed by x86
//   multi-byte escape sequences.
// ---------------------------------------------------

// Helper function to scribble a sequence of
// randomized x86 instruction prefix bytes.

void generate_prefix_bytes(
    uint8_t *dst,
    int bytecount,
    bool is_64bit ) {
    static const uint8_t prefix_collection[] = {
        0x66, 0x67, 0xF2, 0xF3,
        0x66, 0x67, 0xF2, 0xF3,
        0x66, 0x67, 0xF2, 0xF3,
        0x66, 0x67, 0xF2, 0xF3,

        0x26, 0x2E, 0x36, 0x3E,
        0x26, 0x2E, 0x36, 0x3E,
        0x64, 0x65, 0x66, 0xF0,

        // The last 16 prefixes in this table must be REX.
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F
    };

    int i;
    if( is_64bit ) {
        for( i=0; i<bytecount; i++ ) {
            dst[i] = prefix_collection[ rand() % sizeof(prefix_collection) ];
        }
    } else {
        for( i=0; i<bytecount; i++ ) {
            dst[i] = prefix_collection[ rand() % (sizeof(prefix_collection)-16u) ];
        }
    }
}



// Generate 64 bytes of psuedo-random instruction content.
// The "instruction" is generated as a 3-part randomized sequence:
//  * First, a sequence of 0 to 15 prefixes, with length
//     moderately biased towards lower lengths.
//  * Next, a randomly-selected x86 instruction escape sequence
//     (none, 0F, 0F38, 0F3A, VEX, EVEX, XOP)
//  * Finally, a bunch of unbiased-random bytes.
//
// The VEX, EVEX and XOP instruction escape sequence generation
// is biased: the opcode map selection is, with a probability of 75%,
// masked to avoid known-invalid opcode maps, and the vvvv field is,
// with a probability of 25%, forced to 1111.

void generate_rand_instr(
    uint8_t buf[64],
    bool is_64bit ) {
    // 0 to 15 prefixes, biased towards smaller numbers
    int r2 = rand() % 254;  // 0 to 253
    int num_prefixes = (r2*r2*r2) >> 20;

    // output the required number of instruction prefixes
    generate_prefix_bytes( buf, num_prefixes, is_64bit );

    // output a randomized escape sequence
    uint8_t *bufptr = buf + num_prefixes;

    switch( rand() % 50 ) {
        case 0: break;  // regular intructions without escapes
        case 1: *bufptr++ = 0x0F; *bufptr++ = 0x0F; break; // 3dnow
        case 2: *bufptr++ = 0x0F; *bufptr++ = 0x38; break; // 0F 38 escape
        case 3: *bufptr++ = 0x0F; *bufptr++ = 0x3A; break; // 0F 3A escape
        case 4: *bufptr++ = 0x0F; break; // 0F escape
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10: {  // EVEX sequence
            uint32_t rv = rand();
            *bufptr++ = 0x62;
            *bufptr++ = rv & ((rv & 0x300) ? 0xF7 : 0xFF);
            rv = rand();
            *bufptr++ = rv | ((rv & 0x300) ? 0 : 0x78);
            break;
        }
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16: {  // VEX3 sequence
            uint32_t rv = rand();
            *bufptr++ = 0xC4;
            *bufptr++ = rv & ((rv & 0x300) ? 0xE3 : 0xFF);
            rv = rand();
            *bufptr++ = rv | ((rv & 0x300) ? 0 : 0x78 );
            break;
        }
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22: {  // VEX2 sequence
            uint32_t rv = rand();
            *bufptr++ = 0xC5;
            *bufptr++ = rv | ((rv & 0x300) ? 0 : 0x78 );
            break;
        }
        default: { // 23 to 49: XOP sequence
            uint32_t rv = rand();
            *bufptr++ = 0x8F;
            *bufptr++ = (rv & ((rv & 0x300) ? 0xE3 : 0xFF)) ^ 8;
            rv = rand();
            *bufptr++ = rv | ((rv & 0x300) ? 0 : 0x78 );
            break;
        }
    }


    // Fill the remainder of the buffer with uniform-random data
    int remain_offset = bufptr - buf;
    int i;
    for( i=remain_offset; i<64; i++) {
        buf[i] = rand() & 0xFF;
    }
}



// ---------------------------------------------
//   start of Zydis-specific portion of fuzzer
// ---------------------------------------------

#include <Zydis/Zydis.h>

// wrapped version of the Zydis decoder function
// that records an instruction byte sequence
// before calling the decoder itself.
ZyanStatus wrapped_ZydisDecoderDecodeBuffer(
    const  ZydisDecoder* decoder,
    const void* buffer,
    ZyanUSize length,
    ZydisDecodedInstruction* instruction) {

    memcpy( instr_buf, buffer, 16 );
    machine_mode_int = decoder->machine_mode;
    switch( machine_mode_int ) {
        case ZYDIS_MACHINE_MODE_LONG_64:   machine_mode_str = "long64";      break;
        case ZYDIS_MACHINE_MODE_LEGACY_32: machine_mode_str = "protected32"; break;
        case ZYDIS_MACHINE_MODE_LEGACY_16: machine_mode_str = "protected16"; break;
        case ZYDIS_MACHINE_MODE_REAL_16:   machine_mode_str = "real16";      break;
        default:                           machine_mode_str = "(n/a)";       break;
    }
    return ZydisDecoderDecodeBuffer(
        decoder,
        buffer,
        length,
        instruction );
}



// --------------------------
//   Fuzzer main function
// --------------------------

int main( int argc, char *argv[] ) {

    int i;
    srand( argc > 1 ? atoi( argv[1] ) : 0);
    install_sigabrt_handler();


    // --------------------------------------
    //   Prepare Zydis instruction decoders
    // --------------------------------------

    ZydisDecoder decoder_x86_16;
    ZydisDecoder decoder_x86_32;
    ZydisDecoder decoder_x86_64_intel; // x86-64 with Intel branch behavior
    ZydisDecoder decoder_x86_64_amd;   // x86-64 with AMD branch behavior

    ZydisDecoderInit( &decoder_x86_16,       ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_ADDRESS_WIDTH_16 );
    ZydisDecoderInit( &decoder_x86_32,       ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32 );
    ZydisDecoderInit( &decoder_x86_64_intel, ZYDIS_MACHINE_MODE_LONG_64,   ZYDIS_ADDRESS_WIDTH_64 );
    ZydisDecoderInit( &decoder_x86_64_amd,   ZYDIS_MACHINE_MODE_LONG_64,   ZYDIS_ADDRESS_WIDTH_64 );

    ZydisDecoderEnableMode( &decoder_x86_16,       ZYDIS_DECODER_MODE_KNC, true );
    ZydisDecoderEnableMode( &decoder_x86_32,       ZYDIS_DECODER_MODE_KNC, true );
    ZydisDecoderEnableMode( &decoder_x86_64_intel, ZYDIS_DECODER_MODE_KNC, true );
    ZydisDecoderEnableMode( &decoder_x86_64_amd,   ZYDIS_DECODER_MODE_KNC, true );

    ZydisDecoderEnableMode( &decoder_x86_64_amd, ZYDIS_DECODER_MODE_AMD_BRANCHES, true );


    // ---------------------------------------
    //   Main loop runs 2 billion iterations
    // ---------------------------------------

    for(i=0;i<2000000000;i++) {
        uint8_t buf[64];
        int bits;
        ZydisDecoder *decoder_to_use;
        switch( rand() & 3 ) {
            case 0: bits = 16; decoder_to_use = &decoder_x86_16;       break;
            case 1: bits = 32; decoder_to_use = &decoder_x86_32;       break;
            case 2: bits = 64; decoder_to_use = &decoder_x86_64_intel; break;
            case 3: bits = 64; decoder_to_use = &decoder_x86_64_amd;   break;
        }
        
        generate_rand_instr( buf, bits==64 );
        
        ZydisDecodedInstruction instr1;
        wrapped_ZydisDecoderDecodeBuffer(
            decoder_to_use,
            buf,
            64,
            &instr1 );
        
        // Print breadcrumbs for passed tests - one crumb per 1 million
        // tests passed, additional daya per 10 million tests.
        int passed_tests = i+1;
        if( !(passed_tests % 1000000) ) {
            printf(".");
            if( !(passed_tests % 10000000) ) {
                printf("[ %4dM tests passed ]\n", passed_tests/1000000 );
            }
            fflush(stdout);
        }
    }
    return 0;
}

