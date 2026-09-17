#ifndef SNOLC_H
#define SNOLC_H

#include <stddef.h>
#include <stdint.h>

#define SNOLC_WIRE_VERSION 1u
#define SNOLC_CLASS_ADAPTER (1u << 0)
#define SNOLC_CLASS_PROTECTION (1u << 1)
#define SNOLC_CLASS_CARRIER (1u << 2)
#define SNOLC_CLASS_POLICY (1u << 3)

typedef uint64_t SnolHandle;
typedef uint32_t SnolStatus;

typedef struct {
    const uint8_t *pointer;
    size_t length;
} SnolBytes;

typedef struct {
    uint8_t *pointer;
    size_t length;
} SnolBytesMut;

typedef struct {
    uint32_t tag;
    uint32_t code;
    size_t count;
} SnolIoResult;

typedef struct {
    void *context;
    void (*wake)(void *context);
    SnolStatus (*retain)(void *context);
    void (*release)(void *context);
} SnolWakeHandle;

typedef struct SnolHostApiV1 SnolHostApiV1;
typedef struct SnolByteIoV1 SnolByteIoV1;
typedef struct SnolDatagramIoV1 SnolDatagramIoV1;
typedef struct SnolAdapterApiV1 SnolAdapterApiV1;
typedef struct SnolProtectionApiV1 SnolProtectionApiV1;
typedef struct SnolCarrierApiV1 SnolCarrierApiV1;
typedef struct SnolPolicyApiV1 SnolPolicyApiV1;

typedef struct SnolModuleDescriptor {
    uint32_t struct_size;
    uint32_t wire_version;
    uint32_t class_mask;
    uint32_t reserved;
    const char *name;
    SnolStatus (*describe)(SnolBytesMut output, size_t *written);
    SnolStatus (*validate_config)(SnolBytes config, SnolBytes base_directory,
                                  SnolBytesMut error, size_t *written);
    SnolStatus (*create)(SnolBytes config, const SnolHostApiV1 *host,
                         SnolHandle *instance);
    SnolStatus (*poll)(SnolHandle instance, SnolWakeHandle wake);
    SnolStatus (*control)(SnolHandle instance, SnolBytes request,
                          SnolBytesMut response, size_t *written);
    SnolStatus (*shutdown)(SnolHandle instance);
    void (*destroy)(SnolHandle instance);
    const SnolByteIoV1 *byte_io;
    const SnolDatagramIoV1 *datagram_io;
    const SnolAdapterApiV1 *adapter;
    const SnolProtectionApiV1 *protection;
    const SnolCarrierApiV1 *carrier;
    const SnolPolicyApiV1 *policy;
} SnolModuleDescriptor;

const SnolModuleDescriptor *snolc_module_entry(void);

#endif
