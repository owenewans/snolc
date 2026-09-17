#ifndef SNOLC_H
#define SNOLC_H

#include <stddef.h>
#include <stdint.h>

#define SNOLC_WIRE_VERSION 1u
#define SNOLC_CLASS_ADAPTER (1u << 0)
#define SNOLC_CLASS_PROTECTION (1u << 1)
#define SNOLC_CLASS_CARRIER (1u << 2)
#define SNOLC_CLASS_POLICY (1u << 3)
#define SNOLC_STATUS_OK 0u
#define SNOLC_STATUS_UNSUPPORTED 1u
#define SNOLC_STATUS_INVALID 2u
#define SNOLC_STATUS_RESOURCE 3u
#define SNOLC_STATUS_IO 4u
#define SNOLC_STATUS_INTERNAL 5u
#define SNOLC_STATUS_PENDING 6u
#define SNOLC_STATUS_DENIED 7u
#define SNOLC_IO_PROGRESS 0u
#define SNOLC_IO_PENDING 1u
#define SNOLC_IO_EOF 2u
#define SNOLC_IO_ERROR 3u
#define SNOLC_IO_BUFFER_TOO_SMALL 4u

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

struct SnolByteIoV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolIoResult (*read)(SnolHandle io, SnolBytesMut output, SnolWakeHandle wake);
    SnolIoResult (*write)(SnolHandle io, SnolBytes input, SnolWakeHandle wake);
    SnolIoResult (*flush)(SnolHandle io, SnolWakeHandle wake);
    SnolIoResult (*shutdown_write)(SnolHandle io, SnolWakeHandle wake);
    SnolStatus (*close)(SnolHandle io);
};

struct SnolDatagramIoV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolIoResult (*recv_datagram)(SnolHandle io, SnolBytesMut output,
                                  SnolWakeHandle wake);
    SnolIoResult (*send_datagram)(SnolHandle io, SnolBytes input,
                                  SnolWakeHandle wake);
    SnolStatus (*close)(SnolHandle io);
};

struct SnolAdapterApiV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolStatus (*open)(SnolHandle instance, SnolBytes request,
                       SnolWakeHandle wake, SnolHandle *flow);
    SnolStatus (*accept)(SnolHandle instance, SnolBytesMut request,
                         size_t *written, SnolWakeHandle wake,
                         SnolHandle *flow);
    SnolStatus (*attach)(SnolHandle instance, SnolHandle flow,
                         SnolHandle stack_socket,
                         const SnolByteIoV1 *stack_socket_io);
    SnolStatus (*complete)(SnolHandle instance, SnolHandle flow,
                           uint32_t status, SnolBytes reason);
    SnolStatus (*close_flow)(SnolHandle instance, SnolHandle flow);
};

struct SnolProtectionApiV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolStatus (*wrap)(SnolHandle instance, SnolHandle lower,
                       const SnolByteIoV1 *lower_io, SnolBytes context,
                       SnolWakeHandle wake, SnolHandle *wrapped);
};

struct SnolCarrierApiV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolStatus (*connect)(SnolHandle instance, SnolBytes endpoint,
                          SnolWakeHandle wake, SnolHandle *stream);
    SnolStatus (*accept)(SnolHandle instance, SnolWakeHandle wake,
                         SnolHandle *stream);
};

struct SnolPolicyApiV1 {
    uint32_t struct_size;
    uint32_t reserved;
    SnolStatus (*attach_session)(SnolHandle instance, SnolHandle policy_stream,
                                  const SnolByteIoV1 *policy_stream_io,
                                  SnolBytes context, SnolWakeHandle wake,
                                  SnolHandle *session);
    SnolStatus (*admit_flow)(SnolHandle instance, SnolHandle session,
                             SnolBytes metadata, SnolWakeHandle wake);
    SnolStatus (*attach_flow)(SnolHandle instance, SnolHandle session,
                               SnolHandle stack_socket,
                               const SnolByteIoV1 *stack_socket_io,
                               SnolHandle mux_stream,
                               const SnolByteIoV1 *mux_stream_io);
};

struct SnolHostApiV1 {
    uint32_t struct_size;
    uint32_t reserved;
    void *context;
    uint64_t (*now_monotonic_nanos)(void *context);
    SnolStatus (*set_timer)(void *context, SnolHandle handle,
                            uint64_t deadline_nanos);
    SnolStatus (*emit_event)(void *context, SnolBytes event);
    SnolStatus (*context_get)(void *context, SnolHandle session, SnolBytes name,
                              SnolBytesMut output, size_t *written);
    SnolStatus (*context_set)(void *context, SnolHandle session, SnolBytes name,
                              SnolBytes value);
};

typedef struct SnolModuleDescriptor {
    uint32_t struct_size;
    uint32_t wire_version;
    uint32_t class_mask;
    uint32_t reserved;
    const char *name;
    SnolStatus (*describe)(SnolBytesMut output, size_t *written);
    SnolStatus (*validate_config)(SnolBytes config, SnolBytes base_directory,
                                  SnolBytesMut error, size_t *written);
    SnolStatus (*create)(SnolBytes config, SnolBytes base_directory,
                         const SnolHostApiV1 *host, SnolHandle *instance);
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
