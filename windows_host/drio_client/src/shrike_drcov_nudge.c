#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "dr_api.h"
#include "dr_events.h"
#include "drmgr.h"
#include "dr_ir_utils.h"
#include "dr_tools.h"
#include "drutil.h"
#include "drwrap.h"

#ifdef WINDOWS
#include <windows.h>
#include <intrin.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#endif

#define TRACE_BUFFER_SIZE 8192
#define DUMP_AFTER_EVENT_THRESHOLD 50000
#define MAX_PROBE_EVENTS 128
#define SAMPLE_PATH_CAP 260

typedef struct _trace_event_t {
    uint64 timestamp;
    uint thread_id;
    app_pc source;
    app_pc target;
    uint event_type;
} trace_event_t;

enum {
    EVENT_CALL = 1,
    EVENT_RET = 2,
    EVENT_BRANCH_TAKEN = 3,
    EVENT_BRANCH_NOT_TAKEN = 4,
    EVENT_INDIRECT_JUMP = 5,
    EVENT_INDIRECT_CALL = 6,
    EVENT_MODULE_LOAD = 7,
    EVENT_BASIC_BLOCK = 8
};

typedef struct _per_thread_t {
    trace_event_t *buffer;
    uint buffer_pos;
    file_t log_file;
    uint64 event_count;
#ifdef WINDOWS
    SOCKET result_socket;
#endif
} per_thread_t;

static bool g_initialized;
static bool g_dump_requested;
static volatile int g_total_event_count;
static int tls_idx;
static const char *g_logdir;
static const char *g_logprefix;
static bool g_dump_text;
static bool g_bypass_antidebug;
static bool g_sample_module_seen;
static bool g_sample_execution_logged;
static int g_probe_event_count;
static app_pc g_sample_base;
static app_pc g_sample_end;
static char g_sample_path[SAMPLE_PATH_CAP];
static const char *g_result_server_host;
static int g_result_server_port;

#ifndef BUILD_ID
#define BUILD_ID "unknown"
#endif

static const char *
get_client_option(int argc, const char *argv[], const char *name)
{
    int i;

    for (i = 1; i < argc - 1; ++i) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool
has_client_option(int argc, const char *argv[], const char *name)
{
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], name) == 0) {
            return true;
        }
    }
    return false;
}

#ifdef WINDOWS
static SOCKET
connect_to_result_server(const char *host, int port)
{
    SOCKET sock;
    struct sockaddr_in server_addr;
    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return INVALID_SOCKET;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((u_short)port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}
#endif

static void json_escape_string(const char *src, char *dst, size_t dst_size);

static void
write_event_json(file_t file, trace_event_t *event, const char *event_name)
{
    char buf[512];
    int len;

    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"%s\",\"tid\":%u,\"src\":\"0x%llx\",\"target\":\"0x%llx\",\"ts\":%llu}\n",
                     event_name,
                     event->thread_id,
                     (unsigned long long)event->source,
                     (unsigned long long)event->target,
                     (unsigned long long)event->timestamp);

    if (len > 0 && len < sizeof(buf)) {
        dr_write_file(file, buf, len);
    }
}

static void
write_module_load_event(file_t file, const module_data_t *mod)
{
    char buf[1024];
    char escaped_path[768];
    int len;
    const char *path = dr_module_preferred_name(mod);

    json_escape_string(path ? path : "unknown", escaped_path, sizeof(escaped_path));
    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"module_load\",\"path\":\"%s\",\"base\":\"0x%llx\",\"end\":\"0x%llx\",\"size\":%llu}\n",
                     escaped_path,
                     (unsigned long long)mod->start,
                     (unsigned long long)mod->end,
                     (unsigned long long)(mod->end - mod->start));

    if (len > 0 && len < sizeof(buf)) {
        dr_write_file(file, buf, len);
    }
}

static bool
string_contains_case_insensitive(const char *haystack, const char *needle)
{
    size_t hay_len, needle_len, i, j;

    if (haystack == NULL || needle == NULL) {
        return false;
    }

    hay_len = strlen(haystack);
    needle_len = strlen(needle);
    if (needle_len == 0 || hay_len < needle_len) {
        return false;
    }

    for (i = 0; i + needle_len <= hay_len; ++i) {
        for (j = 0; j < needle_len; ++j) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == needle_len) {
            return true;
        }
    }

    return false;
}

static void
json_escape_string(const char *src, char *dst, size_t dst_size)
{
    size_t si, di;

    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    di = 0;
    for (si = 0; src[si] != '\0' && di + 1 < dst_size; ++si) {
        unsigned char ch = (unsigned char)src[si];
        const char *escape = NULL;

        switch (ch) {
        case '\\':
            escape = "\\\\";
            break;
        case '"':
            escape = "\\\"";
            break;
        case '\n':
            escape = "\\n";
            break;
        case '\r':
            escape = "\\r";
            break;
        case '\t':
            escape = "\\t";
            break;
        default:
            break;
        }

        if (escape != NULL) {
            size_t ei;
            for (ei = 0; escape[ei] != '\0' && di + 1 < dst_size; ++ei) {
                dst[di++] = escape[ei];
            }
            continue;
        }

        if (ch < 0x20) {
            dst[di++] = '?';
            continue;
        }

        dst[di++] = (char)ch;
    }

    dst[di] = '\0';
}

static void
write_probe_event_json(const char *json)
{
    file_t log_file;
    char filename[256];
    thread_id_t tid;
    size_t len;

    if (json == NULL || g_logdir == NULL) {
        return;
    }
    if (g_probe_event_count >= MAX_PROBE_EVENTS) {
        return;
    }

    tid = dr_get_thread_id(dr_get_current_drcontext());
    dr_snprintf(filename, sizeof(filename), "%s/%s.%05d.ndjson",
               g_logdir ? g_logdir : ".",
               g_logprefix ? g_logprefix : "trace",
               tid);

    log_file = dr_open_file(filename, DR_FILE_WRITE_APPEND);
    if (log_file == INVALID_FILE) {
        return;
    }

    len = strlen(json);
    if (len > 0) {
        dr_write_file(log_file, json, len);
        dr_write_file(log_file, "\n", 1);
        g_probe_event_count++;
    }
    dr_close_file(log_file);
}

static void
maybe_log_sample_execution(app_pc pc)
{
    char buf[1024];
    char escaped_path[768];
    int len;
    ptr_uint_t offset;

    if (g_sample_execution_logged || !g_sample_module_seen || pc == NULL) {
        return;
    }
    if (pc < g_sample_base || pc >= g_sample_end) {
        return;
    }

    offset = (ptr_uint_t)(pc - g_sample_base);
    json_escape_string(g_sample_path[0] ? g_sample_path : "unknown", escaped_path, sizeof(escaped_path));
    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"sample_execution\",\"path\":\"%s\",\"base\":\"0x%llx\",\"pc\":\"0x%llx\",\"offset\":\"0x%llx\",\"tid\":%u,\"ts\":%llu}",
                     escaped_path,
                     (unsigned long long)g_sample_base,
                     (unsigned long long)pc,
                     (unsigned long long)offset,
                     dr_get_thread_id(dr_get_current_drcontext()),
                     (unsigned long long)dr_get_microseconds());
    if (len > 0 && len < sizeof(buf)) {
        write_probe_event_json(buf);
        g_sample_execution_logged = true;
    }
}

static void
write_exception_dispatch_event(const char *api_name, ULONG code, PVOID address, ULONG flags)
{
    char buf[1024];
    int len;

    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"exception_dispatch\",\"api\":\"%s\",\"code\":\"0x%08x\",\"address\":\"0x%llx\",\"flags\":\"0x%08x\",\"tid\":%u,\"ts\":%llu}",
                     api_name ? api_name : "unknown",
                     (unsigned int)code,
                     (unsigned long long)(ptr_uint_t)address,
                     (unsigned int)flags,
                     dr_get_thread_id(dr_get_current_drcontext()),
                     (unsigned long long)dr_get_microseconds());
    if (len > 0 && len < sizeof(buf)) {
        write_probe_event_json(buf);
    }
}

static void
write_raise_exception_event(const char *api_name, ULONG code, ULONG flags, ULONG arg_count)
{
    char buf[512];
    int len;

    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"raise_exception\",\"api\":\"%s\",\"code\":\"0x%08x\",\"flags\":\"0x%08x\",\"arg_count\":%u,\"tid\":%u,\"ts\":%llu}",
                     api_name ? api_name : "unknown",
                     (unsigned int)code,
                     (unsigned int)flags,
                     (unsigned int)arg_count,
                     dr_get_thread_id(dr_get_current_drcontext()),
                     (unsigned long long)dr_get_microseconds());
    if (len > 0 && len < sizeof(buf)) {
        write_probe_event_json(buf);
    }
}

static void
write_exception_handler_install_event(const char *api_name, PVOID handler, BOOL first)
{
    char buf[512];
    int len;

    len = dr_snprintf(buf, sizeof(buf),
                     "{\"event\":\"exception_handler_install\",\"api\":\"%s\",\"handler\":\"0x%llx\",\"first\":%s,\"tid\":%u,\"ts\":%llu}",
                     api_name ? api_name : "unknown",
                     (unsigned long long)(ptr_uint_t)handler,
                     first ? "true" : "false",
                     dr_get_thread_id(dr_get_current_drcontext()),
                     (unsigned long long)dr_get_microseconds());
    if (len > 0 && len < sizeof(buf)) {
        write_probe_event_json(buf);
    }
}

static void
flush_trace_buffer(void *drcontext, per_thread_t *data)
{
    uint i;
    thread_id_t tid;

    if (!data || data->buffer_pos == 0) {
        return;
    }

    tid = dr_get_thread_id(drcontext);

#ifdef WINDOWS
    /* Use socket if result server is configured */
    if (g_result_server_host && g_result_server_port > 0) {
        if (data->result_socket == INVALID_SOCKET) {
            data->result_socket = connect_to_result_server(g_result_server_host, g_result_server_port);
        }

        if (data->result_socket != INVALID_SOCKET) {
            for (i = 0; i < data->buffer_pos; i++) {
                trace_event_t *event = &data->buffer[i];
                const char *event_name = NULL;
                char buf[512];
                int len;

                switch (event->event_type) {
                    case EVENT_CALL:
                        event_name = "call";
                        break;
                    case EVENT_RET:
                        event_name = "return";
                        break;
                    case EVENT_INDIRECT_JUMP:
                        event_name = "indirect_jump";
                        break;
                    case EVENT_INDIRECT_CALL:
                        event_name = "indirect_call";
                        break;
                    default:
                        event_name = "unknown";
                        break;
                }

                len = dr_snprintf(buf, sizeof(buf),
                                 "{\"event\":\"%s\",\"tid\":%u,\"src\":\"0x%llx\",\"target\":\"0x%llx\",\"ts\":%llu}\n",
                                 event_name,
                                 event->thread_id,
                                 (unsigned long long)event->source,
                                 (unsigned long long)event->target,
                                 (unsigned long long)event->timestamp);

                if (len > 0 && len < sizeof(buf)) {
                    send(data->result_socket, buf, len, 0);
                }
            }

            data->buffer_pos = 0;
            return;
        }
    }
#endif

    /* Fallback to file if socket not available */
    char filename[256];
    dr_snprintf(filename, sizeof(filename), "%s/%s.%05d.ndjson",
               g_logdir ? g_logdir : ".",
               g_logprefix ? g_logprefix : "trace",
               tid);

    if (data->log_file == INVALID_FILE) {
#ifdef WINDOWS
        {
            wchar_t wfilename[512];
            int i;
            for (i = 0; i < sizeof(filename) && i < 511 && filename[i]; i++) {
                wfilename[i] = (wchar_t)filename[i];
            }
            wfilename[i] = L'\0';
            HANDLE h = CreateFileW(wfilename, GENERIC_WRITE,
                                   FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                SetFilePointer(h, 0, NULL, FILE_END);
                data->log_file = (file_t)h;
            }
        }
#else
        data->log_file = dr_open_file(filename, DR_FILE_WRITE_APPEND);
#endif
    }

    if (data->log_file == INVALID_FILE) {
        data->buffer_pos = 0;
        return;
    }

    for (i = 0; i < data->buffer_pos; i++) {
        trace_event_t *event = &data->buffer[i];
        const char *event_name = NULL;

        switch (event->event_type) {
        case EVENT_CALL:
            event_name = "call";
            break;
        case EVENT_RET:
            event_name = "ret";
            break;
        case EVENT_BRANCH_TAKEN:
            event_name = "branch_taken";
            break;
        case EVENT_BRANCH_NOT_TAKEN:
            event_name = "branch_not_taken";
            break;
        case EVENT_INDIRECT_JUMP:
            event_name = "indirect_jump";
            break;
        case EVENT_INDIRECT_CALL:
            event_name = "indirect_call";
            break;
        case EVENT_BASIC_BLOCK:
            event_name = "basic_block";
            break;
        default:
            continue;
        }

        write_event_json(data->log_file, event, event_name);
    }

    data->buffer_pos = 0;
}

static void
record_event(uint event_type, app_pc source, app_pc target)
{
    per_thread_t *data;
    trace_event_t *event;
    void *drcontext;

    if (g_dump_requested) {
        return;
    }

    drcontext = dr_get_current_drcontext();
    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (!data || !data->buffer) {
        return;
    }

    if (data->buffer_pos >= TRACE_BUFFER_SIZE) {
        flush_trace_buffer(drcontext, data);
    }

    event = &data->buffer[data->buffer_pos++];
    event->timestamp = dr_get_microseconds();
    event->thread_id = dr_get_thread_id(drcontext);
    event->source = source;
    event->target = target;
    event->event_type = event_type;

    data->event_count++;

    if (dr_atomic_add32_return_sum(&g_total_event_count, 1) >= DUMP_AFTER_EVENT_THRESHOLD) {
        g_dump_requested = true;
    }
}

static void
at_call(app_pc source, app_pc target)
{
    record_event(EVENT_CALL, source, target);
}

static void
at_return(app_pc source, app_pc target)
{
    record_event(EVENT_RET, source, target);
}

static void
at_branch(app_pc source, app_pc target, bool taken)
{
    record_event(taken ? EVENT_BRANCH_TAKEN : EVENT_BRANCH_NOT_TAKEN, source, target);
}

static void
at_indirect_jump(app_pc source, app_pc target)
{
    record_event(EVENT_INDIRECT_JUMP, source, target);
}

static void
at_indirect_call(app_pc source, app_pc target)
{
    record_event(EVENT_INDIRECT_CALL, source, target);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc pc;
    instr_t *next_inst;

    if (!instr_is_app(inst)) {
        return DR_EMIT_DEFAULT;
    }

    /* Handle anti-debug instructions before checking g_dump_requested */
    if (g_bypass_antidebug) {
        /* Replace RDTSC with fake constant values to bypass timing checks */
        if (instr_get_opcode(inst) == OP_rdtsc) {
            next_inst = instr_get_next(inst);
            instrlist_remove(bb, inst);
            instr_destroy(drcontext, inst);

            /* mov edx, 0 */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_EDX),
                    OPND_CREATE_INT32(0)));
            /* mov eax, 0x1000000 (fake timestamp) */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_EAX),
                    OPND_CREATE_INT32(0x1000000)));

            return DR_EMIT_DEFAULT;
        }

        /* Replace CPUID with safe values */
        if (instr_get_opcode(inst) == OP_cpuid) {
            next_inst = instr_get_next(inst);
            instrlist_remove(bb, inst);
            instr_destroy(drcontext, inst);

            /* Return generic CPU info that doesn't indicate virtualization */
            /* mov eax, 0x00000001 */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_EAX),
                    OPND_CREATE_INT32(0x00000001)));
            /* mov ebx, 0 */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_EBX),
                    OPND_CREATE_INT32(0)));
            /* mov ecx, 0 (clear hypervisor bit) */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_ECX),
                    OPND_CREATE_INT32(0)));
            /* mov edx, 0x078bfbff (typical CPU features) */
            instrlist_meta_preinsert(bb, next_inst,
                XINST_CREATE_load_int(drcontext,
                    opnd_create_reg(DR_REG_EDX),
                    OPND_CREATE_INT32(0x078bfbff)));

            return DR_EMIT_DEFAULT;
        }
    }

    if (g_dump_requested) {
        return DR_EMIT_DEFAULT;
    }

    pc = instr_get_app_pc(inst);
    maybe_log_sample_execution(pc);

    if (drmgr_is_first_instr(drcontext, inst)) {
        dr_insert_clean_call(drcontext, bb, inst, (void *)record_event, false, 4,
                           OPND_CREATE_INT32(EVENT_BASIC_BLOCK),
                           OPND_CREATE_INTPTR(pc),
                           OPND_CREATE_INTPTR(0),
                           OPND_CREATE_INT32(0));
    }

    if (instr_is_call_direct(inst)) {
        app_pc target = opnd_get_pc(instr_get_target(inst));
        dr_insert_clean_call(drcontext, bb, inst, (void *)at_call, false, 2,
                           OPND_CREATE_INTPTR(pc),
                           OPND_CREATE_INTPTR(target));
    } else if (instr_is_call_indirect(inst)) {
        dr_insert_mbr_instrumentation(drcontext, bb, inst, (void *)at_indirect_call,
                                     SPILL_SLOT_1);
    } else if (instr_is_return(inst)) {
        dr_insert_mbr_instrumentation(drcontext, bb, inst, (void *)at_return,
                                     SPILL_SLOT_1);
    } else if (instr_is_cbr(inst)) {
        app_pc fall_through = (app_pc)decode_next_pc(drcontext, pc);
        app_pc target = opnd_get_pc(instr_get_target(inst));

        instrlist_meta_preinsert(bb, inst,
            XINST_CREATE_load_int(drcontext,
                                 opnd_create_reg(DR_REG_XAX),
                                 OPND_CREATE_INTPTR(pc)));
        instrlist_meta_preinsert(bb, inst,
            XINST_CREATE_load_int(drcontext,
                                 opnd_create_reg(DR_REG_XCX),
                                 OPND_CREATE_INTPTR(target)));
        dr_insert_clean_call(drcontext, bb, inst, (void *)at_branch, false, 3,
                           opnd_create_reg(DR_REG_XAX),
                           opnd_create_reg(DR_REG_XCX),
                           OPND_CREATE_INT32(1));

        instrlist_meta_preinsert(bb, instr_get_next(inst),
            XINST_CREATE_load_int(drcontext,
                                 opnd_create_reg(DR_REG_XAX),
                                 OPND_CREATE_INTPTR(pc)));
        instrlist_meta_preinsert(bb, instr_get_next(inst),
            XINST_CREATE_load_int(drcontext,
                                 opnd_create_reg(DR_REG_XCX),
                                 OPND_CREATE_INTPTR(fall_through)));
        dr_insert_clean_call(drcontext, bb, instr_get_next(inst), (void *)at_branch, false, 3,
                           opnd_create_reg(DR_REG_XAX),
                           opnd_create_reg(DR_REG_XCX),
                           OPND_CREATE_INT32(0));
    } else if (instr_is_ubr(inst) && opnd_is_pc(instr_get_target(inst))) {
        /* Direct unconditional branch - usually not interesting for CFG */
    } else if (instr_is_mbr(inst) && !instr_is_return(inst) && !instr_is_call(inst)) {
        dr_insert_mbr_instrumentation(drcontext, bb, inst, (void *)at_indirect_jump,
                                     SPILL_SLOT_1);
    }

    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    per_thread_t *data;
    char filename[256];
    file_t log_file;
    thread_id_t tid;

    if (!loaded || g_dump_requested) {
        return;
    }

    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (!data) {
        return;
    }

    tid = dr_get_thread_id(drcontext);
    dr_snprintf(filename, sizeof(filename), "%s/%s.%05d.ndjson",
               g_logdir ? g_logdir : ".",
               g_logprefix ? g_logprefix : "trace",
               tid);

    log_file = dr_open_file(filename, DR_FILE_WRITE_APPEND);
    if (log_file != INVALID_FILE) {
        write_module_load_event(log_file, mod);
        dr_close_file(log_file);
    }

    if (!g_sample_module_seen) {
        const char *module_path = dr_module_preferred_name(mod);
        if (module_path != NULL && string_contains_case_insensitive(module_path, ".exe")) {
            g_sample_module_seen = true;
            g_sample_base = mod->start;
            g_sample_end = mod->end;
            dr_snprintf(g_sample_path, sizeof(g_sample_path), "%s", module_path);
        }
    }
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    char filename[256];
    file_t log_file;
    thread_id_t tid;
    char buf[512];
    int len;

    data->buffer = (trace_event_t *)dr_thread_alloc(drcontext,
                                                     sizeof(trace_event_t) * TRACE_BUFFER_SIZE);
    data->buffer_pos = 0;
    data->log_file = INVALID_FILE;
    data->event_count = 0;
#ifdef WINDOWS
    data->result_socket = INVALID_SOCKET;
#endif

    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Write client metadata event on first thread init */
    tid = dr_get_thread_id(drcontext);
    dr_snprintf(filename, sizeof(filename), "%s/%s.%05d.ndjson",
               g_logdir ? g_logdir : ".",
               g_logprefix ? g_logprefix : "trace",
               tid);

    log_file = dr_open_file(filename, DR_FILE_WRITE_APPEND);
    if (log_file != INVALID_FILE) {
        len = dr_snprintf(buf, sizeof(buf),
                         "{\"event\":\"client_metadata\",\"build_id\":\"%s\",\"bypass_antidebug\":%s,\"pid\":%d,\"logdir\":\"%s\",\"logprefix\":\"%s\"}\n",
                         BUILD_ID,
                         g_bypass_antidebug ? "true" : "false",
                         dr_get_process_id(),
                         g_logdir ? g_logdir : ".",
                         g_logprefix ? g_logprefix : "trace");
        if (len > 0 && len < sizeof(buf)) {
            dr_write_file(log_file, buf, len);
        }
        dr_close_file(log_file);
    }
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    if (data) {
        flush_trace_buffer(drcontext, data);

#ifdef WINDOWS
        if (data->result_socket != INVALID_SOCKET) {
            closesocket(data->result_socket);
        }
#endif

        if (data->log_file != INVALID_FILE) {
#ifdef WINDOWS
            CloseHandle((HANDLE)data->log_file);
#else
            dr_close_file(data->log_file);
#endif
        }

        if (data->buffer) {
            dr_thread_free(drcontext, data->buffer,
                          sizeof(trace_event_t) * TRACE_BUFFER_SIZE);
        }

        dr_thread_free(drcontext, data, sizeof(per_thread_t));
    }
}

static void
event_exit(void)
{

    if (g_initialized) {
        drmgr_unregister_thread_init_event(event_thread_init);
        drmgr_unregister_thread_exit_event(event_thread_exit);
        drmgr_unregister_bb_instrumentation_event(event_app_instruction);
        if (g_bypass_antidebug) {
            drwrap_exit();
        }
        drmgr_exit();
        drutil_exit();
        g_initialized = false;
    }
}

static void
event_nudge(void *drcontext, uint64 argument)
{
    per_thread_t *data;

    if (g_dump_requested) {
        return;
    }

    g_dump_requested = true;

    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (data) {
        flush_trace_buffer(drcontext, data);
    }

    dr_fprintf(STDERR, "shrike_cfg_tracer: dump requested via nudge argument=%llu total_events=%d\n",
               (unsigned long long)argument, g_total_event_count);
}

static void
wrap_IsDebuggerPresent(void *wrapcxt, OUT void **user_data)
{
    /* Always return FALSE (0) to bypass debugger detection */
    drwrap_set_retval(wrapcxt, (void *)0);
}

static void
wrap_CheckRemoteDebuggerPresent(void *wrapcxt, OUT void **user_data)
{
    /* Get the pbDebuggerPresent parameter (second argument) */
    BOOL *pbDebuggerPresent = (BOOL *)drwrap_get_arg(wrapcxt, 1);

    if (pbDebuggerPresent != NULL) {
        /* Set output parameter to FALSE */
        *pbDebuggerPresent = FALSE;
    }

    /* Return TRUE (success) */
    drwrap_set_retval(wrapcxt, (void *)1);
}

static void
wrap_NtQueryInformationProcess_post(void *wrapcxt, void *user_data)
{
    /* Get ProcessInformationClass parameter (second argument) */
    ULONG infoClass = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 1);

    /* ProcessDebugPort = 7, ProcessDebugObjectHandle = 30, ProcessDebugFlags = 31 */
    if (infoClass == 7 || infoClass == 30 || infoClass == 31) {
        void *buffer = drwrap_get_arg(wrapcxt, 2);
        ULONG bufferSize = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 3);

        if (buffer != NULL && bufferSize >= sizeof(ULONG)) {
            /* Set buffer to 0 (no debugger) */
            memset(buffer, 0, bufferSize);
        }

        /* Return STATUS_SUCCESS (0) */
        drwrap_set_retval(wrapcxt, (void *)0);
    }
}

static DWORD g_fake_tick_base = 0x10000000;
static LARGE_INTEGER g_fake_qpc_base = {0};
static FILETIME g_fake_systime_base = {0};

static void
wrap_GetTickCount(void *wrapcxt, OUT void **user_data)
{
    g_fake_tick_base += 100;
    drwrap_set_retval(wrapcxt, (void *)(ptr_uint_t)g_fake_tick_base);
}

static void
wrap_QueryPerformanceCounter(void *wrapcxt, OUT void **user_data)
{
    LARGE_INTEGER *counter = (LARGE_INTEGER *)drwrap_get_arg(wrapcxt, 0);

    if (g_fake_qpc_base.QuadPart == 0) {
        g_fake_qpc_base.QuadPart = 0x100000000LL;
    }
    g_fake_qpc_base.QuadPart += 10000;

    if (counter != NULL) {
        counter->QuadPart = g_fake_qpc_base.QuadPart;
    }

    drwrap_set_retval(wrapcxt, (void *)1);
}

static void
wrap_GetCurrentProcessId(void *wrapcxt, OUT void **user_data)
{
    DWORD real_pid = dr_get_process_id();
    drwrap_set_retval(wrapcxt, (void *)(ptr_uint_t)real_pid);
}

static void
wrap_GetCurrentThreadId(void *wrapcxt, OUT void **user_data)
{
    DWORD real_tid = (DWORD)dr_get_thread_id(dr_get_current_drcontext());
    drwrap_set_retval(wrapcxt, (void *)(ptr_uint_t)real_tid);
}

static void
wrap_GetSystemTimeAsFileTime(void *wrapcxt, OUT void **user_data)
{
    FILETIME *ft = (FILETIME *)drwrap_get_arg(wrapcxt, 0);

    if (g_fake_systime_base.dwLowDateTime == 0 && g_fake_systime_base.dwHighDateTime == 0) {
        g_fake_systime_base.dwLowDateTime = 0xD0000000;
        g_fake_systime_base.dwHighDateTime = 0x01D50000;
    }

    ULARGE_INTEGER uli;
    uli.LowPart = g_fake_systime_base.dwLowDateTime;
    uli.HighPart = g_fake_systime_base.dwHighDateTime;
    uli.QuadPart += 1000000;
    g_fake_systime_base.dwLowDateTime = uli.LowPart;
    g_fake_systime_base.dwHighDateTime = uli.HighPart;

    if (ft != NULL) {
        ft->dwLowDateTime = g_fake_systime_base.dwLowDateTime;
        ft->dwHighDateTime = g_fake_systime_base.dwHighDateTime;
    }
}

static void
wrap_NtSetInformationThread(void *wrapcxt, OUT void **user_data)
{
    /* Get ThreadInformationClass parameter (second argument) */
    ULONG infoClass = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 1);

    /* ThreadHideFromDebugger = 0x11 */
    if (infoClass == 0x11) {
        /* Pretend it succeeded but don't actually hide from debugger */
        drwrap_skip_call(wrapcxt, (void *)0, 0);
    }
}

static void
wrap_RtlDispatchException(void *wrapcxt, OUT void **user_data)
{
    EXCEPTION_RECORD *record = (EXCEPTION_RECORD *)drwrap_get_arg(wrapcxt, 0);
    if (record != NULL) {
        write_exception_dispatch_event("RtlDispatchException", record->ExceptionCode,
                                       record->ExceptionAddress, record->ExceptionFlags);
    }
}

static void
wrap_KiUserExceptionDispatcher(void *wrapcxt, OUT void **user_data)
{
    EXCEPTION_RECORD *record = (EXCEPTION_RECORD *)drwrap_get_arg(wrapcxt, 0);
    if (record != NULL) {
        write_exception_dispatch_event("KiUserExceptionDispatcher", record->ExceptionCode,
                                       record->ExceptionAddress, record->ExceptionFlags);
    }
}

static void
wrap_RaiseException(void *wrapcxt, OUT void **user_data)
{
    ULONG code = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 0);
    ULONG flags = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 1);
    ULONG arg_count = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);
    write_raise_exception_event("RaiseException", code, flags, arg_count);
}

static void
wrap_RtlRaiseException(void *wrapcxt, OUT void **user_data)
{
    EXCEPTION_RECORD *record = (EXCEPTION_RECORD *)drwrap_get_arg(wrapcxt, 0);
    if (record != NULL) {
        write_raise_exception_event("RtlRaiseException", record->ExceptionCode,
                                    record->ExceptionFlags,
                                    record->NumberParameters);
    }
}

static void
wrap_AddVectoredExceptionHandler(void *wrapcxt, OUT void **user_data)
{
    BOOL first = (BOOL)(ptr_uint_t)drwrap_get_arg(wrapcxt, 0);
    PVOID handler = drwrap_get_arg(wrapcxt, 1);
    write_exception_handler_install_event("AddVectoredExceptionHandler", handler, first);
}

static void
wrap_SetUnhandledExceptionFilter(void *wrapcxt, OUT void **user_data)
{
    PVOID handler = drwrap_get_arg(wrapcxt, 0);
    write_exception_handler_install_event("SetUnhandledExceptionFilter", handler, FALSE);
}

static void
wrap_GetThreadContext(void *wrapcxt, OUT void **user_data)
{
    /* Get the CONTEXT* parameter (second argument) */
    CONTEXT *context = (CONTEXT *)drwrap_get_arg(wrapcxt, 1);

    if (context != NULL) {
        /* Clear debug registers to hide hardware breakpoints */
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr3 = 0;
        context->Dr6 = 0;
        context->Dr7 = 0;
    }
}

static void
wrap_NtQuerySystemInformation(void *wrapcxt, OUT void **user_data)
{
    /* Get SystemInformationClass parameter (first argument) */
    ULONG infoClass = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 0);

    /* SystemKernelDebuggerInformation = 0x23 */
    if (infoClass == 0x23) {
        void *buffer = drwrap_get_arg(wrapcxt, 1);
        ULONG bufferSize = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

        if (buffer != NULL && bufferSize >= 2) {
            /* Set both bytes to FALSE (no kernel debugger) */
            memset(buffer, 0, 2);
        }

        /* Return STATUS_SUCCESS (0) */
        drwrap_set_retval(wrapcxt, (void *)0);
    }
}

static void
wrap_OutputDebugStringA(void *wrapcxt, OUT void **user_data)
{
    /* Just skip the call - don't actually output anything */
    drwrap_skip_call(wrapcxt, NULL, 0);
}

static void
wrap_OutputDebugStringW(void *wrapcxt, OUT void **user_data)
{
    /* Just skip the call - don't actually output anything */
    drwrap_skip_call(wrapcxt, NULL, 0);
}

static app_pc g_drio_ranges[10][2];
static int g_drio_range_count;

static void
cache_drio_module_ranges(void)
{
    const char *names[] = {"dynamorio.dll", "drwrap.dll", "drmgr.dll",
                           "drutil.dll", "shrike_drcov_nudge.dll", NULL};
    int i;
    g_drio_range_count = 0;
    for (i = 0; names[i] != NULL && g_drio_range_count < 10; i++) {
        module_data_t *mod = dr_lookup_module_by_name(names[i]);
        if (mod != NULL) {
            g_drio_ranges[g_drio_range_count][0] = mod->start;
            g_drio_ranges[g_drio_range_count][1] = mod->end;
            g_drio_range_count++;
            dr_free_module_data(mod);
        }
    }
}

static bool
is_drio_module_range(app_pc addr)
{
    int i;
    for (i = 0; i < g_drio_range_count; i++) {
        if (addr >= g_drio_ranges[i][0] && addr < g_drio_ranges[i][1])
            return true;
    }
    return false;
}

/* NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
 *                      MemoryInformation, MemoryInformationLength, ReturnLength)
 * MemoryBasicInformation = 0, MemorySectionName = 2 */
static void
wrap_NtQueryVirtualMemory_pre(void *wrapcxt, OUT void **user_data)
{
    app_pc base_addr = (app_pc)drwrap_get_arg(wrapcxt, 1);
    *user_data = (void *)base_addr;
}

static void
wrap_NtQueryVirtualMemory_post(void *wrapcxt, void *user_data)
{
    LONG retval = (LONG)(ptr_int_t)drwrap_get_retval(wrapcxt);
    if (retval != 0) return;

    app_pc base_addr = (app_pc)user_data;
    ULONG info_class = (ULONG)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);
    void *buffer = drwrap_get_arg(wrapcxt, 3);

    if (!is_drio_module_range(base_addr) || buffer == NULL) return;

    if (info_class == 0) {
        /* MemoryBasicInformation — spoof as MEM_FREE */
        typedef struct {
            PVOID BaseAddress;
            PVOID AllocationBase;
            DWORD AllocationProtect;
            SIZE_T RegionSize;
            DWORD State;
            DWORD Protect;
            DWORD Type;
        } MBI;
        MBI *mbi = (MBI *)buffer;
        mbi->State = 0x10000;  /* MEM_FREE */
        mbi->Protect = 0x01;   /* PAGE_NOACCESS */
        mbi->Type = 0;
    } else if (info_class == 2) {
        /* MemorySectionName — return STATUS_INVALID_ADDRESS */
        drwrap_set_retval(wrapcxt, (void *)(ptr_int_t)0xC0000141L);
    }
}

static void
erase_drio_pe_headers(void)
{
    const char *names[] = {"dynamorio.dll", "drwrap.dll", "drmgr.dll",
                           "drutil.dll", "shrike_drcov_nudge.dll", NULL};
    int i;
    char json_buf[256];

    for (i = 0; names[i] != NULL; i++) {
        module_data_t *mod = dr_lookup_module_by_name(names[i]);
        if (mod != NULL) {
            size_t page_size = dr_page_size();
            bool ok = dr_memory_protect(mod->start, page_size, DR_MEMPROT_READ | DR_MEMPROT_WRITE);
            if (ok) {
                memset(mod->start, 0, page_size);
                dr_memory_protect(mod->start, page_size, DR_MEMPROT_READ);
                dr_snprintf(json_buf, sizeof(json_buf),
                    "{\"event\":\"pe_header_erase\",\"module\":\"%s\",\"base\":\"%p\",\"status\":\"erased\"}",
                    names[i], mod->start);
            } else {
                dr_snprintf(json_buf, sizeof(json_buf),
                    "{\"event\":\"pe_header_erase\",\"module\":\"%s\",\"base\":\"%p\",\"status\":\"protect_failed\"}",
                    names[i], mod->start);
            }
            write_probe_event_json(json_buf);
            dr_free_module_data(mod);
        }
    }
}

#ifdef WINDOWS
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - (char *)(&((type *)0)->field)))
#endif

static int
wcsicmp_simple(const wchar_t *s1, const wchar_t *s2)
{
    while (*s1 && *s2) {
        wchar_t c1 = *s1, c2 = *s2;
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return c1 - c2;
        s1++; s2++;
    }
    return *s1 - *s2;
}

static void
wchar_to_ascii(const wchar_t *src, char *dst, size_t dst_size)
{
    size_t i;
    if (dst_size == 0) return;
    for (i = 0; i < dst_size - 1 && src[i] != L'\0'; i++) {
        dst[i] = (src[i] < 128) ? (char)src[i] : '?';
    }
    dst[i] = '\0';
}

static void
patch_peb_fields(void)
{
    BYTE *peb_base;
    char json_buf[512];

#ifdef X64
    peb_base = NULL;
    write_probe_event_json("{\"event\":\"peb_patch\",\"status\":\"x64_not_implemented\"}");
    return;
#else
    __asm {
        mov eax, fs:[0x30]
        mov peb_base, eax
    }
#endif

    if (peb_base == NULL) {
        write_probe_event_json("{\"event\":\"peb_patch\",\"status\":\"peb_null\"}");
        return;
    }

    /* PEB.BeingDebugged at offset 0x02 */
    BYTE old_being_debugged = peb_base[0x02];
    peb_base[0x02] = 0;

    /* PEB.NtGlobalFlag at offset 0x68 (x86) */
    ULONG *ntgf_ptr = (ULONG *)(peb_base + 0x68);
    ULONG old_ntgf = *ntgf_ptr;
    *ntgf_ptr &= ~((ULONG)0x70);

    dr_snprintf(json_buf, sizeof(json_buf),
        "{\"event\":\"peb_patch\",\"status\":\"patched\","
        "\"BeingDebugged_old\":%d,\"BeingDebugged_new\":0,"
        "\"NtGlobalFlag_old\":\"0x%x\",\"NtGlobalFlag_new\":\"0x%x\"}",
        (int)old_being_debugged, old_ntgf, *ntgf_ptr);
    write_probe_event_json(json_buf);
}

static void
unlink_module_from_peb(void)
{
    PEB *peb;
    PPEB_LDR_DATA ldr;
    PLIST_ENTRY head, current;
    PLDR_DATA_TABLE_ENTRY entry;
    int unlinked_count = 0;
    char json_buf[1024];

    /* Get PEB pointer from TEB using inline assembly (MSVC style for x86) */
#ifdef X64
    peb = NULL;
    write_probe_event_json("{\"event\":\"peb_unlink\",\"status\":\"x64_not_implemented\"}");
    return;
#else
    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }
#endif

    dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_unlink\",\"status\":\"start\",\"peb\":\"%p\"}", peb);
    write_probe_event_json(json_buf);

    if (peb == NULL || peb->Ldr == NULL) {
        dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_unlink\",\"status\":\"failed\",\"peb\":\"%p\",\"ldr\":\"%p\"}",
                   peb, peb ? peb->Ldr : NULL);
        write_probe_event_json(json_buf);
        return;
    }

    ldr = peb->Ldr;

    /* Module names to hide */
    const wchar_t *hide_modules[] = {
        L"dynamorio.dll",
        L"drwrap.dll",
        L"drmgr.dll",
        L"drutil.dll",
        L"shrike_drcov_nudge.dll",
        NULL
    };

    /* Unlink from InLoadOrderModuleList */
    head = &ldr->InLoadOrderModuleList;
    current = head->Flink;

    while (current != head && current != NULL) {
        entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        PLIST_ENTRY next = current->Flink;

        if (entry->BaseDllName.Buffer != NULL) {
            char module_name_ascii[256];
            wchar_to_ascii(entry->BaseDllName.Buffer, module_name_ascii, sizeof(module_name_ascii));

            dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_module\",\"name\":\"%s\",\"base\":\"%p\"}",
                       module_name_ascii, entry->DllBase);
            write_probe_event_json(json_buf);

            bool should_hide = false;
            for (int i = 0; hide_modules[i] != NULL; i++) {
                if (wcsicmp_simple(entry->BaseDllName.Buffer, hide_modules[i]) == 0) {
                    should_hide = true;
                    dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_unlink\",\"status\":\"found_target\",\"name\":\"%s\",\"base\":\"%p\"}",
                               module_name_ascii, entry->DllBase);
                    write_probe_event_json(json_buf);
                    break;
                }
            }

            if (should_hide) {
                current->Blink->Flink = current->Flink;
                current->Flink->Blink = current->Blink;
                entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
                entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
                if (entry->InInitializationOrderLinks.Flink != NULL &&
                    entry->InInitializationOrderLinks.Blink != NULL) {
                    entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
                    entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
                }
                dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_unlink\",\"status\":\"unlinked\",\"name\":\"%s\"}",
                           module_name_ascii);
                write_probe_event_json(json_buf);
                unlinked_count++;
            }
        }

        current = next;
    }

    dr_snprintf(json_buf, sizeof(json_buf), "{\"event\":\"peb_unlink\",\"status\":\"completed\",\"unlinked_count\":%d}", unlinked_count);
    write_probe_event_json(json_buf);
}
#endif

static void
setup_antidebug_bypass(void)
{
    module_data_t *kernel32, *ntdll;
    app_pc IsDebuggerPresent_addr, CheckRemoteDebuggerPresent_addr;
    app_pc NtQueryInformationProcess_addr, NtSetInformationThread_addr;
    app_pc GetTickCount_addr, QueryPerformanceCounter_addr;
    app_pc RaiseException_addr, SetUnhandledExceptionFilter_addr;
    app_pc RtlDispatchException_addr, KiUserExceptionDispatcher_addr;
    app_pc RtlRaiseException_addr, AddVectoredExceptionHandler_addr;
    app_pc GetThreadContext_addr, NtQuerySystemInformation_addr;
    app_pc OutputDebugStringA_addr, OutputDebugStringW_addr;
    write_probe_event_json("{\"event\":\"antidebug_setup\",\"status\":\"start\"}");

    cache_drio_module_ranges();

    kernel32 = dr_lookup_module_by_name("kernel32.dll");
    if (kernel32 != NULL) {
        IsDebuggerPresent_addr = (app_pc)dr_get_proc_address(kernel32->handle, "IsDebuggerPresent");
        if (IsDebuggerPresent_addr != NULL) {
            drwrap_wrap(IsDebuggerPresent_addr, wrap_IsDebuggerPresent, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped IsDebuggerPresent\n");
        }

        CheckRemoteDebuggerPresent_addr = (app_pc)dr_get_proc_address(kernel32->handle, "CheckRemoteDebuggerPresent");
        if (CheckRemoteDebuggerPresent_addr != NULL) {
            drwrap_wrap(CheckRemoteDebuggerPresent_addr, wrap_CheckRemoteDebuggerPresent, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped CheckRemoteDebuggerPresent\n");
        }

        GetTickCount_addr = (app_pc)dr_get_proc_address(kernel32->handle, "GetTickCount");
        if (GetTickCount_addr != NULL) {
            drwrap_wrap(GetTickCount_addr, wrap_GetTickCount, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped GetTickCount\n");
        }

        QueryPerformanceCounter_addr = (app_pc)dr_get_proc_address(kernel32->handle, "QueryPerformanceCounter");
        if (QueryPerformanceCounter_addr != NULL) {
            drwrap_wrap(QueryPerformanceCounter_addr, wrap_QueryPerformanceCounter, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped QueryPerformanceCounter\n");
        }

        app_pc GetCurrentProcessId_addr = (app_pc)dr_get_proc_address(kernel32->handle, "GetCurrentProcessId");
        if (GetCurrentProcessId_addr != NULL) {
            drwrap_wrap(GetCurrentProcessId_addr, wrap_GetCurrentProcessId, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped GetCurrentProcessId\n");
        }

        app_pc GetCurrentThreadId_addr = (app_pc)dr_get_proc_address(kernel32->handle, "GetCurrentThreadId");
        if (GetCurrentThreadId_addr != NULL) {
            drwrap_wrap(GetCurrentThreadId_addr, wrap_GetCurrentThreadId, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped GetCurrentThreadId\n");
        }

        app_pc GetSystemTimeAsFileTime_addr = (app_pc)dr_get_proc_address(kernel32->handle, "GetSystemTimeAsFileTime");
        if (GetSystemTimeAsFileTime_addr != NULL) {
            drwrap_wrap(GetSystemTimeAsFileTime_addr, wrap_GetSystemTimeAsFileTime, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped GetSystemTimeAsFileTime\n");
        }

        RaiseException_addr = (app_pc)dr_get_proc_address(kernel32->handle, "RaiseException");
        if (RaiseException_addr != NULL) {
            drwrap_wrap(RaiseException_addr, wrap_RaiseException, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped RaiseException\n");
        }

        SetUnhandledExceptionFilter_addr = (app_pc)dr_get_proc_address(kernel32->handle, "SetUnhandledExceptionFilter");
        if (SetUnhandledExceptionFilter_addr != NULL) {
            drwrap_wrap(SetUnhandledExceptionFilter_addr, wrap_SetUnhandledExceptionFilter, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped SetUnhandledExceptionFilter\n");
        }

        GetThreadContext_addr = (app_pc)dr_get_proc_address(kernel32->handle, "GetThreadContext");
        if (GetThreadContext_addr != NULL) {
            drwrap_wrap(GetThreadContext_addr, NULL, wrap_GetThreadContext);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped GetThreadContext\n");
        }

        OutputDebugStringA_addr = (app_pc)dr_get_proc_address(kernel32->handle, "OutputDebugStringA");
        if (OutputDebugStringA_addr != NULL) {
            drwrap_wrap(OutputDebugStringA_addr, wrap_OutputDebugStringA, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped OutputDebugStringA\n");
        }

        OutputDebugStringW_addr = (app_pc)dr_get_proc_address(kernel32->handle, "OutputDebugStringW");
        if (OutputDebugStringW_addr != NULL) {
            drwrap_wrap(OutputDebugStringW_addr, wrap_OutputDebugStringW, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped OutputDebugStringW\n");
        }

        dr_free_module_data(kernel32);
    }

    ntdll = dr_lookup_module_by_name("ntdll.dll");
    if (ntdll != NULL) {
        NtQueryInformationProcess_addr = (app_pc)dr_get_proc_address(ntdll->handle, "NtQueryInformationProcess");
        if (NtQueryInformationProcess_addr != NULL) {
            drwrap_wrap(NtQueryInformationProcess_addr, NULL, wrap_NtQueryInformationProcess_post);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped NtQueryInformationProcess\n");
        }

        NtSetInformationThread_addr = (app_pc)dr_get_proc_address(ntdll->handle, "NtSetInformationThread");
        if (NtSetInformationThread_addr != NULL) {
            drwrap_wrap(NtSetInformationThread_addr, wrap_NtSetInformationThread, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped NtSetInformationThread\n");
        }

        RtlDispatchException_addr = (app_pc)dr_get_proc_address(ntdll->handle, "RtlDispatchException");
        if (RtlDispatchException_addr != NULL) {
            drwrap_wrap(RtlDispatchException_addr, wrap_RtlDispatchException, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped RtlDispatchException\n");
        }

        KiUserExceptionDispatcher_addr = (app_pc)dr_get_proc_address(ntdll->handle, "KiUserExceptionDispatcher");
        if (KiUserExceptionDispatcher_addr != NULL) {
            drwrap_wrap(KiUserExceptionDispatcher_addr, wrap_KiUserExceptionDispatcher, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped KiUserExceptionDispatcher\n");
        }

        RtlRaiseException_addr = (app_pc)dr_get_proc_address(ntdll->handle, "RtlRaiseException");
        if (RtlRaiseException_addr != NULL) {
            drwrap_wrap(RtlRaiseException_addr, wrap_RtlRaiseException, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped RtlRaiseException\n");
        }

        AddVectoredExceptionHandler_addr = (app_pc)dr_get_proc_address(ntdll->handle, "RtlAddVectoredExceptionHandler");
        if (AddVectoredExceptionHandler_addr == NULL) {
            AddVectoredExceptionHandler_addr = (app_pc)dr_get_proc_address(ntdll->handle, "AddVectoredExceptionHandler");
        }
        if (AddVectoredExceptionHandler_addr != NULL) {
            drwrap_wrap(AddVectoredExceptionHandler_addr, wrap_AddVectoredExceptionHandler, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped AddVectoredExceptionHandler\n");
        }

        NtQuerySystemInformation_addr = (app_pc)dr_get_proc_address(ntdll->handle, "NtQuerySystemInformation");
        if (NtQuerySystemInformation_addr != NULL) {
            drwrap_wrap(NtQuerySystemInformation_addr, wrap_NtQuerySystemInformation, NULL);
            dr_fprintf(STDERR, "shrike_cfg_tracer: wrapped NtQuerySystemInformation\n");
        }

        dr_free_module_data(ntdll);
    }

    dr_fprintf(STDERR, "shrike_cfg_tracer: anti-debug bypass hooks installed\n");

#ifdef WINDOWS
    /* Clear PEB.BeingDebugged and PEB.NtGlobalFlag debug indicators */
    patch_peb_fields();
    dr_fprintf(STDERR, "shrike_cfg_tracer: PEB fields patched\n");

    /* Unlink DynamoRIO modules from PEB to hide from module enumeration */
    unlink_module_from_peb();
    dr_fprintf(STDERR, "shrike_cfg_tracer: PEB unlinking completed\n");
#endif
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Shrike CFG tracer", "https://example.invalid/shrike");

    g_logdir = get_client_option(argc, argv, "-logdir");
    g_logprefix = get_client_option(argc, argv, "-logprefix");
    g_dump_text = has_client_option(argc, argv, "-dump_text");
    g_bypass_antidebug = has_client_option(argc, argv, "-bypass_antidebug");
    g_result_server_host = get_client_option(argc, argv, "-result_server_host");

    {
        const char *port_str = get_client_option(argc, argv, "-result_server_port");
        g_result_server_port = 0;
        if (port_str) {
            int i;
            for (i = 0; port_str[i] >= '0' && port_str[i] <= '9'; i++) {
                g_result_server_port = g_result_server_port * 10 + (port_str[i] - '0');
            }
        }
    }

    if (!drmgr_init()) {
        dr_fprintf(STDERR, "shrike_cfg_tracer: drmgr_init failed\n");
        return;
    }

    if (!drutil_init()) {
        dr_fprintf(STDERR, "shrike_cfg_tracer: drutil_init failed\n");
        drmgr_exit();
        return;
    }

    if (g_bypass_antidebug) {
        if (!drwrap_init()) {
            dr_fprintf(STDERR, "shrike_cfg_tracer: drwrap_init failed\n");
            drutil_exit();
            drmgr_exit();
            return;
        }
        setup_antidebug_bypass();
    }

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        dr_fprintf(STDERR, "shrike_cfg_tracer: failed to register TLS field\n");
        if (g_bypass_antidebug) {
            drwrap_exit();
        }
        drutil_exit();
        drmgr_exit();
        return;
    }

    dr_register_exit_event(event_exit);
    dr_register_nudge_event(event_nudge, id);
    drmgr_register_module_load_event(event_module_load);

    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL)) {
        dr_fprintf(STDERR, "shrike_cfg_tracer: failed to register events\n");
        if (g_bypass_antidebug) {
            drwrap_exit();
        }
        drutil_exit();
        drmgr_exit();
        return;
    }

    g_initialized = true;
    g_dump_requested = false;
    g_total_event_count = 0;
    g_sample_module_seen = false;
    g_sample_execution_logged = false;
    g_probe_event_count = 0;
    g_sample_base = NULL;
    g_sample_end = NULL;
    g_sample_path[0] = '\0';

    dr_fprintf(STDERR, "shrike_cfg_tracer: initialized build_id=%s logdir=%s logprefix=%s bypass_antidebug=%d pid=%d\n",
               BUILD_ID, g_logdir ? g_logdir : ".", g_logprefix ? g_logprefix : "trace", g_bypass_antidebug, dr_get_process_id());
}
