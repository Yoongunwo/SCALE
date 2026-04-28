#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>  // Requires libjansson-dev

#define SYSCALL_BITS 10  // syscall 번호 최대 1024까지 지원

void generate_bpf_probe(const char* name, int syscall_nr, FILE *out) {
    fprintf(out, "SEC(\"tracepoint/syscalls/sys_enter_%s\")\n", name);
    fprintf(out, "int trace_enter_%s(struct trace_event_raw_sys_enter *ctx) {\n", name);
    fprintf(out, "    u32 pid = bpf_get_current_pid_tgid() >> 32;\n");
    fprintf(out, "    u64 key = ((u64)pid << 32) | %d;\n", syscall_nr);
    fprintf(out, "    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);\n");
    fprintf(out, "    if (!index) return 0;\n");
    fprintf(out, "    bpf_tail_call(ctx, &prog_array_map, *index);\n");
    fprintf(out, "}\n\n");
}

int main() {
    json_error_t error;
    json_t *root = json_load_file("../../x86-64_ABI.json", 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return 1;
    }

    json_t *syscalls = json_object_get(root, "syscalls");
    if (!json_is_array(syscalls)) {
        fprintf(stderr, "Invalid JSON format: 'syscalls' not an array\n");
        json_decref(root);
        return 1;
    }

    FILE *out = fopen("generated_dispatcher.bpf.c", "w");
    if (!out) {
        perror("fopen");
        json_decref(root);
        return 1;
    }

    // Common BPF headers and map declarations
    fprintf(out,
        "#include \"vmlinux.h\"\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_tracing.h>\n"
        "#include <bpf/bpf_core_read.h>\n"
        "\n"
        "char LICENSE[] SEC(\"license\") = \"GPL\";\n\n"
        "struct {\n"
        "    __uint(type, BPF_MAP_TYPE_LRU_HASH);\n"
        // "    __uint(type, BPF_MAP_TYPE_HASH);\n"
        "    __type(key, u64);         // (gpid << 32) | syscall_nr\n"
        "    __type(value, u32);       // index into prog_array_map\n"
        "    __uint(max_entries, 8192);\n"
        "    __uint(pinning, LIBBPF_PIN_BY_NAME);\n"
        "} pid_syscall_to_index SEC(\".maps\");\n\n"
        "struct {\n"
        "    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);\n"
        "    __type(key, u32);\n"
        "    __type(value, u32);\n"
        "    __uint(max_entries, 8192);\n"
        "    __uint(pinning, LIBBPF_PIN_BY_NAME);\n"
        "} prog_array_map SEC(\".maps\");\n\n"
    );

    // Generate syscall-specific tracepoints
    size_t index;
    json_t *syscall;
    json_array_foreach(syscalls, index, syscall) {
        json_t *name = json_object_get(syscall, "name");
        json_t *nr = json_object_get(syscall, "number");

        if (!json_is_string(name) || !json_is_integer(nr))
            continue;

        const char *syscall_name = json_string_value(name);
        int syscall_nr = json_integer_value(nr);

        generate_bpf_probe(syscall_name, syscall_nr, out);
    }

    fclose(out);
    json_decref(root);
    return 0;
}
