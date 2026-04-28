#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>  // Requires libjansson-dev

const char* classify_type(const char* type) {
    if (strstr(type, "char *") || strstr(type, "const char *"))
        return "string";
    else if (strstr(type, "struct sockaddr"))
        return "sockaddr";
    else if (strstr(type, "*"))
        return "ptr";
    else if (strstr(type, "int"))
        return "int";
    else
        return "ulong";
}

void generate_bpf_probe(const char* name, const char* args[], int argc, FILE *out) {
    fprintf(out, "SEC(\"tracepoint/syscalls/sys_enter_%s\")\n", name);
    fprintf(out, "int handle_%s(struct trace_event_raw_sys_enter *ctx) {\n", name);
    fprintf(out, "    struct syscall_event_t *e;\n");
    fprintf(out, "    u32 pid = bpf_get_current_pid_tgid() >> 32;\n");
    fprintf(out, "    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);\n");
    fprintf(out, "    if (!e) return 0;\n");
    fprintf(out, "    e->pid = pid;\n");
    fprintf(out, "    e->syscall_nr = ctx->id;\n");

    // int str_count = 0;
    // for (int i = 0; i < argc && i < 6; i++) {
    //     const char* category = classify_type(args[i]);
    //     if (strcmp(category, "string") == 0 && str_count < 3) {
    //         fprintf(out, "    if (bpf_probe_read_user_str(e->str_args[%d], sizeof(e->str_args[%d]), (void *)ctx->args[%d]) > 0)\n", str_count, str_count, i);
    //         fprintf(out, "        e->str_valid[%d] = 1;\n", str_count);
    //         fprintf(out, "    else\n");
    //         fprintf(out, "        e->str_valid[%d] = 0;\n", str_count);
    //         str_count++;
    //     } else if (strcmp(category, "sockaddr") == 0) {
    //         fprintf(out, "    struct sockaddr_in sa = {};\n");
    //         fprintf(out, "    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[%d]);\n", i);
    //         fprintf(out, "    e->int_args[%d] = sa.sin_port;\n", i);
    //         fprintf(out, "    e->int_args[%d] = sa.sin_addr.s_addr;\n", i+1);
    //     } else {
    //         fprintf(out, "    e->int_args[%d] = ctx->args[%d];\n", i, i);
    //     }
    // }

    // for (int i = argc; i < 6; i++)
    //     fprintf(out, "    e->int_args[%d] = 0;\n", i);
    // for (int i = str_count; i < 3; i++)
    //     fprintf(out, "    e->str_valid[%d] = 0;\n", i);

    fprintf(out, "    bpf_ringbuf_submit(e, 0);\n");
    fprintf(out, "    return 0;\n");
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

    FILE *out = fopen("syscall_direct.bpf.c", "w");
    if (!out) {
        perror("fopen");
        json_decref(root);
        return 1;
    }

    // Common header
    fprintf(out,
        "#include \"vmlinux.h\"\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_tracing.h>\n\n"
        "char LICENSE[] SEC(\"license\") = \"GPL\";\n\n"
        "struct syscall_event_t {\n"
        "    u32 pid;\n"
        "    u32 syscall_nr;\n"
        // "    char str_args[3][64];\n"
        // "    u8 str_valid[3];\n"
        // "    u64 int_args[6];\n"
        "};\n\n"
        "struct {\n"
        "    __uint(type, BPF_MAP_TYPE_RINGBUF);\n"
        "    __uint(max_entries, 1 << 20);\n"
        "} ringbuf_local SEC(\".maps\");\n\n"
    );

    size_t index;
    json_t *syscall;
    json_array_foreach(syscalls, index, syscall) {
        json_t *name = json_object_get(syscall, "name");
        json_t *signature = json_object_get(syscall, "signature");

        if (!json_is_string(name) || !json_is_array(signature))
            continue;

        const char *syscall_name = json_string_value(name);
        int argc = json_array_size(signature);
        const char *argtypes[6];
        for (int i = 0; i < argc && i < 6; i++) {
            argtypes[i] = json_string_value(json_array_get(signature, i));
        }

        generate_bpf_probe(syscall_name, argtypes, argc, out);
    }

    fclose(out);
    json_decref(root);
    return 0;
}
