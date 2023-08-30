// Copyright(C) 2022 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_FW_IMAGE_H
#define SEV_FW_IMAGE_H

// -----------------------------------------------------------------------------
// SEV FW Image Header Format
// -----------------------------------------------------------------------------
typedef struct SEV_FW_IMAGE_HEADER_T
{
    uint8_t    Nonce[16];          // [0x00] Unique image id
    uint32_t   Cookie;             // [0x10] Cookie for sanity checks
    uint32_t   SizeFWSigned;       // [0x14] Size of the FW to be included in signature in bytes
    uint32_t   EncOption;          // [0x18] 0 - Not encrypted, 1 - encrypted
    uint8_t    IkekType;           // [0x1C] 0 - iKEK-AMD is be used, non-zero - iKEK-OEM is used
    uint8_t    Reserved0[3];       // [0x1D] *** RESERVED ***
    uint8_t    EncParameters[16];  // [0x20] Encryption Parameters
    uint32_t   SigOption;          // [0x30] 0 - not signed, 1 - signed
    uint32_t   SigAlgID;           // [0x34] Signature algorithm ID
    uint8_t    SigParameters[16];  // [0x38] Signature parameter
    uint32_t   CompOption;         // [0x48] 0 - Not compressed, 1 - compressed
    uint32_t   SecPatchLevel;      // [0x4C] Security patch level
    uint32_t   UnCompImageSize;    // [0x50] Uncompressed Image Size (only valid when comp enabled)
    uint32_t   CompImageSize;      // [0x54] Compressed Image Size (only valid when comp enabled)
    uint16_t   FwType;             // [0x58] SOC FW ID
    uint8_t    HeaderVersion;      // [0x5A] Header version
    uint8_t    MeasurementOption;  // [0x5B] Measurement Flag. 0 - not available, 1 - available
    uint8_t    Reserved[4];        // [0x5C] Reserved. Must be 0
    uint32_t   FWVersion;          // [0x60] Off Chip Firmware Version
    uint32_t   APUFamilyID;        // [0x64] APU Family ID or SoC ID
    uint32_t   FirmwareLoadAddr;   // [0x68] Firmware Load address (default 0)
    uint32_t   SizeImage;          // [0x6C] Size of entire signed image including key tokens
    uint32_t   SizeFWUnSigned;     // [0x70] Size of Un-signed portion of the FW (usually 0)
    uint32_t   FirmwareSplitAddr;  // [0x74] Joining point of combined FWs (e.g. Nwd/Swd split address)
    uint32_t   SigFlags;           // [0x78] Flags for FW signing options, app permissions etc.
    uint8_t    FwTypeLegacy;       // [0x7C] Module Fw Type. Must match Directory Table Entry Type
    uint8_t    FwSubType;          // [0x7D] FwSubType (must match the value in Unified FW table for specific FW)
    uint8_t    SubProgram;         // [0x7E] indicates sub-program for which FW is applied
    uint8_t    SigLevel;           // [0x7F] signature level (0 - level 0 (normal) header, 1 - level 1 etc.)
    uint8_t    EncKey[16];         // [0x80] Encryption Key (Wrapped MEK)
    uint8_t    SigningInfo[16];    // [0x90] Signing tool specific information
    uint32_t   BlFirmwareVersion;  // [0xA0] Required BL Firmware Version
    uint8_t    FwSpecificData[28]; // [0xA4-0xBF] (rest of) FW specific information
    uint8_t    DebugEncKey[16];    // [0xC0] MEK wrapped with tKEK
    uint8_t    Measurement[32];    // [0xD0] SHA256 of FW binary (without header and signature)
    uint8_t    Reserved2[16];      // [0xF0] *** RESERVED ***
} SEV_FW_IMAGE_HEADER;

#endif /* SEV_FW_IMAGE_H */

