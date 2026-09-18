#include <stddef.h>
#include <stdio.h>

#include "snolc.h"

#define FIELD(type, field) printf(" %zu", offsetof(type, field))

int main(void) {
    printf("SnolBytes %zu", sizeof(SnolBytes));
    FIELD(SnolBytes, pointer);
    FIELD(SnolBytes, length);
    putchar('\n');

    printf("SnolBytesMut %zu", sizeof(SnolBytesMut));
    FIELD(SnolBytesMut, pointer);
    FIELD(SnolBytesMut, length);
    putchar('\n');

    printf("SnolIoResult %zu", sizeof(SnolIoResult));
    FIELD(SnolIoResult, tag);
    FIELD(SnolIoResult, code);
    FIELD(SnolIoResult, count);
    putchar('\n');

    printf("SnolWakeHandle %zu", sizeof(SnolWakeHandle));
    FIELD(SnolWakeHandle, context);
    FIELD(SnolWakeHandle, wake);
    FIELD(SnolWakeHandle, retain);
    FIELD(SnolWakeHandle, release);
    putchar('\n');

    printf("SnolFlowMetadataV1 %zu", sizeof(SnolFlowMetadataV1));
    FIELD(SnolFlowMetadataV1, struct_size);
    FIELD(SnolFlowMetadataV1, kind);
    FIELD(SnolFlowMetadataV1, address_type);
    FIELD(SnolFlowMetadataV1, reserved);
    FIELD(SnolFlowMetadataV1, address);
    FIELD(SnolFlowMetadataV1, port);
    FIELD(SnolFlowMetadataV1, reserved2);
    FIELD(SnolFlowMetadataV1, metadata);
    putchar('\n');

    printf("SnolByteIoV1 %zu", sizeof(SnolByteIoV1));
    FIELD(SnolByteIoV1, struct_size);
    FIELD(SnolByteIoV1, reserved);
    FIELD(SnolByteIoV1, read);
    FIELD(SnolByteIoV1, write);
    FIELD(SnolByteIoV1, flush);
    FIELD(SnolByteIoV1, shutdown_write);
    FIELD(SnolByteIoV1, close);
    putchar('\n');

    printf("SnolDatagramIoV1 %zu", sizeof(SnolDatagramIoV1));
    FIELD(SnolDatagramIoV1, struct_size);
    FIELD(SnolDatagramIoV1, reserved);
    FIELD(SnolDatagramIoV1, recv_datagram);
    FIELD(SnolDatagramIoV1, send_datagram);
    FIELD(SnolDatagramIoV1, close);
    putchar('\n');

    printf("SnolAdapterApiV1 %zu", sizeof(SnolAdapterApiV1));
    FIELD(SnolAdapterApiV1, struct_size);
    FIELD(SnolAdapterApiV1, reserved);
    FIELD(SnolAdapterApiV1, open);
    FIELD(SnolAdapterApiV1, accept);
    FIELD(SnolAdapterApiV1, attach);
    FIELD(SnolAdapterApiV1, complete);
    FIELD(SnolAdapterApiV1, close_flow);
    FIELD(SnolAdapterApiV1, attach_datagram);
    FIELD(SnolAdapterApiV1, attach_packet_port);
    FIELD(SnolAdapterApiV1, resolve);
    putchar('\n');

    printf("SnolProtectionApiV1 %zu", sizeof(SnolProtectionApiV1));
    FIELD(SnolProtectionApiV1, struct_size);
    FIELD(SnolProtectionApiV1, flags);
    FIELD(SnolProtectionApiV1, wrap);
    putchar('\n');

    printf("SnolCarrierApiV1 %zu", sizeof(SnolCarrierApiV1));
    FIELD(SnolCarrierApiV1, struct_size);
    FIELD(SnolCarrierApiV1, reserved);
    FIELD(SnolCarrierApiV1, connect);
    FIELD(SnolCarrierApiV1, accept);
    putchar('\n');

    printf("SnolPolicyApiV1 %zu", sizeof(SnolPolicyApiV1));
    FIELD(SnolPolicyApiV1, struct_size);
    FIELD(SnolPolicyApiV1, flags);
    FIELD(SnolPolicyApiV1, attach_session);
    FIELD(SnolPolicyApiV1, admit_flow);
    FIELD(SnolPolicyApiV1, attach_flow);
    FIELD(SnolPolicyApiV1, attach_datagram_flow);
    FIELD(SnolPolicyApiV1, admit_resolved);
    putchar('\n');

    printf("SnolHostApiV1 %zu", sizeof(SnolHostApiV1));
    FIELD(SnolHostApiV1, struct_size);
    FIELD(SnolHostApiV1, reserved);
    FIELD(SnolHostApiV1, context);
    FIELD(SnolHostApiV1, now_monotonic_nanos);
    FIELD(SnolHostApiV1, set_timer);
    FIELD(SnolHostApiV1, emit_event);
    FIELD(SnolHostApiV1, context_get);
    FIELD(SnolHostApiV1, context_set);
    FIELD(SnolHostApiV1, protect_socket);
    putchar('\n');

    printf("SnolModuleDescriptor %zu", sizeof(SnolModuleDescriptor));
    FIELD(SnolModuleDescriptor, struct_size);
    FIELD(SnolModuleDescriptor, wire_version);
    FIELD(SnolModuleDescriptor, class_mask);
    FIELD(SnolModuleDescriptor, reserved);
    FIELD(SnolModuleDescriptor, name);
    FIELD(SnolModuleDescriptor, describe);
    FIELD(SnolModuleDescriptor, validate_config);
    FIELD(SnolModuleDescriptor, create);
    FIELD(SnolModuleDescriptor, poll);
    FIELD(SnolModuleDescriptor, control);
    FIELD(SnolModuleDescriptor, shutdown);
    FIELD(SnolModuleDescriptor, destroy);
    FIELD(SnolModuleDescriptor, byte_io);
    FIELD(SnolModuleDescriptor, datagram_io);
    FIELD(SnolModuleDescriptor, adapter);
    FIELD(SnolModuleDescriptor, protection);
    FIELD(SnolModuleDescriptor, carrier);
    FIELD(SnolModuleDescriptor, policy);
    putchar('\n');
    return 0;
}
