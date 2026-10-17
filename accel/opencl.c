#include "opencl.h"

#include "search.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The CPU scan stays the default. This file runs only when the caller asks
   for the GPU. An Ed25519 v4 fingerprint preimage is 54 bytes, so SHA-1
   pads it into one block, and the only word that changes is the creation
   time at byte 4 (message word 1). The kernel hashes the whole window and
   keeps the smallest index, which is the newest timestamp.

   libOpenCL is loaded with dlopen. Building this file does not need the
   OpenCL headers. One queue serves the process. A lock keeps scans off
   that queue one at a time, because an OpenCL queue is not thread-safe.
   Each work item hashes four timestamps so those chains can overlap.
*/

typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef cl_ulong cl_bitfield;
typedef cl_bitfield cl_device_type;
typedef cl_bitfield cl_mem_flags;
typedef intptr_t cl_context_properties;

typedef struct _cl_platform_id *cl_platform_id;
typedef struct _cl_device_id *cl_device_id;
typedef struct _cl_context *cl_context;
typedef struct _cl_command_queue *cl_command_queue;
typedef struct _cl_mem *cl_mem;
typedef struct _cl_program *cl_program;
typedef struct _cl_kernel *cl_kernel;

enum {
    CL_DEVICE_TYPE_GPU = 1u << 2,
    CL_DEVICE_MAX_COMPUTE_UNITS = 0x1002,
    CL_DEVICE_MAX_WORK_GROUP_SIZE = 0x1004,
    CL_DEVICE_NAME = 0x102B,
    CL_CONTEXT_PLATFORM = 0x1084,
    CL_MEM_READ_WRITE = 1u << 0,
    CL_MEM_WRITE_ONLY = 1u << 1,
    CL_MEM_READ_ONLY = 1u << 2,
    CL_PROGRAM_BUILD_LOG = 0x1183,
    CL_KERNEL_WORK_GROUP_SIZE = 0x11B0
};

typedef cl_int (*cl_get_platform_ids_fn)(cl_uint, cl_platform_id *, cl_uint *);
typedef cl_int (*cl_get_device_ids_fn)(cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *);
typedef cl_int (*cl_get_device_info_fn)(cl_device_id, cl_uint, size_t, void *, size_t *);
typedef cl_context (*cl_create_context_fn)(const cl_context_properties *, cl_uint, const cl_device_id *,
                                           void (*)(const char *, const void *, size_t, void *), void *, cl_int *);
typedef cl_command_queue (*cl_create_queue_fn)(cl_context, cl_device_id, cl_ulong, cl_int *);
typedef cl_command_queue (*cl_create_queue_props_fn)(cl_context, cl_device_id, const cl_ulong *, cl_int *);
typedef cl_program (*cl_create_program_fn)(cl_context, cl_uint, const char **, const size_t *, cl_int *);
typedef cl_int (*cl_build_program_fn)(cl_program, cl_uint, const cl_device_id *, const char *,
                                      void (*)(cl_program, void *), void *);
typedef cl_int (*cl_get_build_info_fn)(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *);
typedef cl_kernel (*cl_create_kernel_fn)(cl_program, const char *, cl_int *);
typedef cl_mem (*cl_create_buffer_fn)(cl_context, cl_mem_flags, size_t, void *, cl_int *);
typedef cl_int (*cl_set_kernel_arg_fn)(cl_kernel, cl_uint, size_t, const void *);
typedef cl_int (*cl_enqueue_write_fn)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, const void *, cl_uint,
                                      const void *, void *);
typedef cl_int (*cl_enqueue_ndrange_fn)(cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *,
                                        const size_t *, cl_uint, const void *, void *);
typedef cl_int (*cl_enqueue_read_fn)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, void *, cl_uint,
                                     const void *, void *);
typedef cl_int (*cl_get_kernel_wg_fn)(cl_kernel, cl_device_id, cl_uint, size_t, void *, size_t *);
typedef cl_int (*cl_release_mem_fn)(cl_mem);
typedef cl_int (*cl_release_kernel_fn)(cl_kernel);
typedef cl_int (*cl_release_program_fn)(cl_program);
typedef cl_int (*cl_release_queue_fn)(cl_command_queue);
typedef cl_int (*cl_release_context_fn)(cl_context);

static struct {
    void *lib;
    cl_get_platform_ids_fn GetPlatformIDs;
    cl_get_device_ids_fn GetDeviceIDs;
    cl_get_device_info_fn GetDeviceInfo;
    cl_create_context_fn CreateContext;
    cl_create_queue_fn CreateCommandQueue;
    cl_create_queue_props_fn CreateCommandQueueWithProperties;
    cl_create_program_fn CreateProgramWithSource;
    cl_build_program_fn BuildProgram;
    cl_get_build_info_fn GetProgramBuildInfo;
    cl_create_kernel_fn CreateKernel;
    cl_create_buffer_fn CreateBuffer;
    cl_set_kernel_arg_fn SetKernelArg;
    cl_enqueue_write_fn EnqueueWriteBuffer;
    cl_enqueue_ndrange_fn EnqueueNDRangeKernel;
    cl_enqueue_read_fn EnqueueReadBuffer;
    cl_get_kernel_wg_fn GetKernelWorkGroupInfo;
    cl_release_mem_fn ReleaseMemObject;
    cl_release_kernel_fn ReleaseKernel;
    cl_release_program_fn ReleaseProgram;
    cl_release_queue_fn ReleaseCommandQueue;
    cl_release_context_fn ReleaseContext;
} ocl;

static struct {
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel scan;
    cl_kernel self;
    cl_mem words;
    cl_mem prefix_len;
    cl_mem prefix_hi;
    cl_mem prefix_lo;
    cl_mem hit;
    cl_device_id device;
    size_t local;
    cl_uint units;
    char name[256];
    int ready;
    int failed;
} gpu;

static pthread_mutex_t gpu_lock = PTHREAD_MUTEX_INITIALIZER;
static char init_error[4096];
static __thread char thread_error[4096];

static const char KERNEL[] =
    "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n"
    "\n"
    "inline uint4 __attribute__((always_inline)) rotl4(uint4 x, uint n) {\n"
    "    return (x << n) | (x >> (32u - n));\n"
    "}\n"
    "\n"
    "inline uint4 __attribute__((always_inline)) sched4(uint4 *w, int i) {\n"
    "    uint4 wi = rotl4(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1u);\n"
    "    w[i & 15] = wi;\n"
    "    return wi;\n"
    "}\n"
    "\n"
    "inline void __attribute__((always_inline)) sha1_x4(uint4 w[16], uint4 *h0, uint4 *h1, uint4 *h2, uint4 *h3, uint4 *h4) {\n"
    "    uint4 a = (uint4)(0x67452301u);\n"
    "    uint4 b = (uint4)(0xEFCDAB89u);\n"
    "    uint4 c = (uint4)(0x98BADCFEu);\n"
    "    uint4 d = (uint4)(0x10325476u);\n"
    "    uint4 e = (uint4)(0xC3D2E1F0u);\n"
    "    #pragma unroll\n"
    "    for (int i = 0; i < 16; i++) {\n"
    "        uint4 f = (b & c) | (~b & d);\n"
    "        uint4 tmp = rotl4(a, 5u) + f + e + (uint4)(0x5A827999u) + w[i];\n"
    "        e = d; d = c; c = rotl4(b, 30u); b = a; a = tmp;\n"
    "    }\n"
    "    #pragma unroll\n"
    "    for (int i = 16; i < 20; i++) {\n"
    "        uint4 wi = sched4(w, i);\n"
    "        uint4 f = (b & c) | (~b & d);\n"
    "        uint4 tmp = rotl4(a, 5u) + f + e + (uint4)(0x5A827999u) + wi;\n"
    "        e = d; d = c; c = rotl4(b, 30u); b = a; a = tmp;\n"
    "    }\n"
    "    #pragma unroll\n"
    "    for (int i = 20; i < 40; i++) {\n"
    "        uint4 wi = sched4(w, i);\n"
    "        uint4 f = b ^ c ^ d;\n"
    "        uint4 tmp = rotl4(a, 5u) + f + e + (uint4)(0x6ED9EBA1u) + wi;\n"
    "        e = d; d = c; c = rotl4(b, 30u); b = a; a = tmp;\n"
    "    }\n"
    "    #pragma unroll\n"
    "    for (int i = 40; i < 60; i++) {\n"
    "        uint4 wi = sched4(w, i);\n"
    "        uint4 f = (b & c) | (b & d) | (c & d);\n"
    "        uint4 tmp = rotl4(a, 5u) + f + e + (uint4)(0x8F1BBCDCu) + wi;\n"
    "        e = d; d = c; c = rotl4(b, 30u); b = a; a = tmp;\n"
    "    }\n"
    "    #pragma unroll\n"
    "    for (int i = 60; i < 80; i++) {\n"
    "        uint4 wi = sched4(w, i);\n"
    "        uint4 f = b ^ c ^ d;\n"
    "        uint4 tmp = rotl4(a, 5u) + f + e + (uint4)(0xCA62C1D6u) + wi;\n"
    "        e = d; d = c; c = rotl4(b, 30u); b = a; a = tmp;\n"
    "    }\n"
    "    *h0 = a + (uint4)(0x67452301u);\n"
    "    *h1 = b + (uint4)(0xEFCDAB89u);\n"
    "    *h2 = c + (uint4)(0x98BADCFEu);\n"
    "    *h3 = d + (uint4)(0x10325476u);\n"
    "    *h4 = e + (uint4)(0xC3D2E1F0u);\n"
    "}\n"
    "\n"
    "inline bool repeat_key(uint h3, uint h4, uint leading) {\n"
    "    uint b0 = h3 >> 24;\n"
    "    if ((b0 >> 4) != (b0 & 0xfu)) return false;\n"
    "    if (leading < 1u || leading > 8u) return false;\n"
    "    uint filled = b0 * 0x01010101u;\n"
    "    if (leading <= 4u) {\n"
    "        uint shift = (4u - leading) * 8u;\n"
    "        return (h3 >> shift) == (filled >> shift);\n"
    "    }\n"
    "    if (h3 != filled) return false;\n"
    "    uint rest = leading - 4u;\n"
    "    uint shift = (4u - rest) * 8u;\n"
    "    return (h4 >> shift) == (filled >> shift);\n"
    "}\n"
    "\n"
    "inline bool prefix_key(uint h3, uint h4, uint n, uint hi, uint lo) {\n"
    "    if (n < 1u || n > 8u) return false;\n"
    "    if (n >= 4u) {\n"
    "        if (h3 != hi) return false;\n"
    "        if (n == 4u) return true;\n"
    "        uint shift = (8u - n) * 8u;\n"
    "        return (h4 >> shift) == (lo >> shift);\n"
    "    }\n"
    "    uint shift = (4u - n) * 8u;\n"
    "    return (h3 >> shift) == (hi >> shift);\n"
    "}\n"
    "\n"
    "__kernel void imsovain_sha1_self(__constant uint *words, __global uint *out) {\n"
    "    if (get_global_id(0) != 0) return;\n"
    "    uint4 w[16];\n"
    "    for (int i = 0; i < 16; i++) w[i] = (uint4)(words[i]);\n"
    "    uint4 h0, h1, h2, h3, h4;\n"
    "    sha1_x4(w, &h0, &h1, &h2, &h3, &h4);\n"
    "    out[0] = h0.s0; out[1] = h1.s0; out[2] = h2.s0; out[3] = h3.s0; out[4] = h4.s0;\n"
    "    out[5] = (h0.s0 == h0.s1 && h0.s0 == h0.s2 && h0.s0 == h0.s3 &&\n"
    "              h1.s0 == h1.s1 && h1.s0 == h1.s2 && h1.s0 == h1.s3 &&\n"
    "              h2.s0 == h2.s1 && h2.s0 == h2.s2 && h2.s0 == h2.s3 &&\n"
    "              h3.s0 == h3.s1 && h3.s0 == h3.s2 && h3.s0 == h3.s3 &&\n"
    "              h4.s0 == h4.s1 && h4.s0 == h4.s2 && h4.s0 == h4.s3) ? 0u : 1u;\n"
    "}\n"
    "\n"
    "__kernel void imsovain_scan(\n"
    "    __constant uint *words,\n"
    "    uint limit,\n"
    "    uint kind,\n"
    "    uint leading,\n"
    "    uint prefix_count,\n"
    "    __constant uint *plen,\n"
    "    __constant uint *phi,\n"
    "    __constant uint *plo,\n"
    "    volatile __global uint *hit) {\n"
    "    size_t gid = get_global_id(0);\n"
    "    size_t stride = get_global_size(0);\n"
    "    size_t n = (size_t)limit;\n"
    "    size_t base = gid << 2;\n"
    "    size_t step = stride << 2;\n"
    "    uint origin = words[1];\n"
    "    uint count = prefix_count > 32u ? 32u : prefix_count;\n"
    "    while (base < n) {\n"
    "        uint g = (uint)base;\n"
    "        uint4 w[16];\n"
    "        #pragma unroll\n"
    "        for (int i = 0; i < 16; i++) w[i] = (uint4)(words[i]);\n"
    "        w[1] = (uint4)(origin) - (uint4)(g, g + 1u, g + 2u, g + 3u);\n"
    "        uint4 h0, h1, h2, h3, h4;\n"
    "        sha1_x4(w, &h0, &h1, &h2, &h3, &h4);\n"
    "        uint h3s[4] = {h3.s0, h3.s1, h3.s2, h3.s3};\n"
    "        uint h4s[4] = {h4.s0, h4.s1, h4.s2, h4.s3};\n"
    "        for (int lane = 0; lane < 4; lane++) {\n"
    "            uint id = g + (uint)lane;\n"
    "            if (id < g || (size_t)id >= n) break;\n"
    "            bool matched = false;\n"
    "            if (kind == 0u) {\n"
    "                matched = repeat_key(h3s[lane], h4s[lane], leading);\n"
    "            } else if (kind == 1u) {\n"
    "                for (uint p = 0u; p < count; p++) {\n"
    "                    if (prefix_key(h3s[lane], h4s[lane], plen[p], phi[p], plo[p])) {\n"
    "                        matched = true;\n"
    "                        break;\n"
    "                    }\n"
    "                }\n"
    "            }\n"
    "            if (matched) atomic_min(hit, id);\n"
    "        }\n"
    "        if (n - base <= step) break;\n"
    "        base += step;\n"
    "    }\n"
    "}\n";

static void copy_error(const char *msg) {
    snprintf(thread_error, sizeof thread_error, "%s", msg == NULL ? "OpenCL search failed" : msg);
}

static void fail_init(const char *msg) {
    snprintf(init_error, sizeof init_error, "%s", msg);
    copy_error(init_error);
}

static void fail_init_code(const char *what, int code) {
    snprintf(init_error, sizeof init_error, "%s (OpenCL %d)", what, code);
    copy_error(init_error);
}

static void fail_call(const char *what, int code) {
    snprintf(thread_error, sizeof thread_error, "%s (OpenCL %d)", what, code);
}

static int load_sym(void *dest, const char *name, int optional) {
    void *sym = dlsym(ocl.lib, name);
    if (sym == NULL) {
        memset(dest, 0, sizeof(void *));
        if (optional) {
            return 0;
        }
        snprintf(init_error, sizeof init_error, "OpenCL is missing %s", name);
        copy_error(init_error);
        return -1;
    }
    memcpy(dest, &sym, sizeof(void *));
    return 0;
}

static void release_gpu(void) {
    if (ocl.ReleaseKernel != NULL) {
        if (gpu.scan != NULL) {
            ocl.ReleaseKernel(gpu.scan);
        }
        if (gpu.self != NULL) {
            ocl.ReleaseKernel(gpu.self);
        }
    }
    gpu.scan = NULL;
    gpu.self = NULL;
    if (ocl.ReleaseProgram != NULL && gpu.program != NULL) {
        ocl.ReleaseProgram(gpu.program);
    }
    gpu.program = NULL;
    if (ocl.ReleaseMemObject != NULL) {
        if (gpu.words != NULL) {
            ocl.ReleaseMemObject(gpu.words);
        }
        if (gpu.prefix_len != NULL) {
            ocl.ReleaseMemObject(gpu.prefix_len);
        }
        if (gpu.prefix_hi != NULL) {
            ocl.ReleaseMemObject(gpu.prefix_hi);
        }
        if (gpu.prefix_lo != NULL) {
            ocl.ReleaseMemObject(gpu.prefix_lo);
        }
        if (gpu.hit != NULL) {
            ocl.ReleaseMemObject(gpu.hit);
        }
    }
    gpu.words = NULL;
    gpu.prefix_len = NULL;
    gpu.prefix_hi = NULL;
    gpu.prefix_lo = NULL;
    gpu.hit = NULL;
    if (ocl.ReleaseCommandQueue != NULL && gpu.queue != NULL) {
        ocl.ReleaseCommandQueue(gpu.queue);
    }
    gpu.queue = NULL;
    if (ocl.ReleaseContext != NULL && gpu.context != NULL) {
        ocl.ReleaseContext(gpu.context);
    }
    gpu.context = NULL;
    gpu.device = NULL;
}

static uint32_t read_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static int load_words(const uint8_t *src, size_t len, uint32_t words[16]) {
    uint8_t block[64];
    if (len >= 56) {
        return -1;
    }
    memset(block, 0, sizeof block);
    if (len > 0) {
        memcpy(block, src, len);
    }
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8u;
    block[56] = (uint8_t)(bits >> 56);
    block[57] = (uint8_t)(bits >> 48);
    block[58] = (uint8_t)(bits >> 40);
    block[59] = (uint8_t)(bits >> 32);
    block[60] = (uint8_t)(bits >> 24);
    block[61] = (uint8_t)(bits >> 16);
    block[62] = (uint8_t)(bits >> 8);
    block[63] = (uint8_t)bits;
    for (int i = 0; i < 16; i++) {
        words[i] = read_be32(block + (size_t)i * 4u);
    }
    return 0;
}

static void hex_bytes(char out[41], const uint8_t in[20]) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[i * 2] = hexd[in[i] >> 4];
        out[i * 2 + 1] = hexd[in[i] & 0x0f];
    }
    out[40] = '\0';
}

static int digest_is(const uint32_t got[5], const uint8_t expect[20]) {
    for (int i = 0; i < 5; i++) {
        if (got[i] != read_be32(expect + (size_t)i * 4u)) {
            return 0;
        }
    }
    return 1;
}

static int set_mem(cl_kernel kernel, cl_uint index, cl_mem mem) {
    cl_int err = ocl.SetKernelArg(kernel, index, sizeof mem, &mem);
    if (err != 0) {
        fail_call("clSetKernelArg", err);
        return -1;
    }
    return 0;
}

static int set_u32(cl_kernel kernel, cl_uint index, uint32_t value) {
    cl_int err = ocl.SetKernelArg(kernel, index, sizeof value, &value);
    if (err != 0) {
        fail_call("clSetKernelArg", err);
        return -1;
    }
    return 0;
}

static int write_buf(cl_mem mem, const void *src, size_t bytes) {
    cl_int err = ocl.EnqueueWriteBuffer(gpu.queue, mem, 0, 0, bytes, src, 0, NULL, NULL);
    if (err != 0) {
        fail_call("clEnqueueWriteBuffer", err);
        return -1;
    }
    return 0;
}

static int self_test_message(const uint8_t *msg, size_t len, const char *label) {
    uint32_t words[16];
    uint32_t got[6];
    uint8_t expect[20];
    cl_int err = 0;
    if (load_words(msg, len, words) != 0 || imsovain_sha1(msg, len, expect) != 0) {
        fail_init("OpenCL SHA-1 self-test could not pad the block");
        return -1;
    }
    cl_mem out = ocl.CreateBuffer(gpu.context, CL_MEM_READ_WRITE, sizeof got, NULL, &err);
    if (out == NULL || err != 0) {
        fail_init_code("clCreateBuffer", err);
        return -1;
    }
    if (write_buf(gpu.words, words, sizeof words) != 0 || set_mem(gpu.self, 0, gpu.words) != 0 ||
        set_mem(gpu.self, 1, out) != 0) {
        ocl.ReleaseMemObject(out);
        fail_init(thread_error);
        return -1;
    }
    size_t one = 1;
    err = ocl.EnqueueNDRangeKernel(gpu.queue, gpu.self, 1, NULL, &one, &one, 0, NULL, NULL);
    if (err != 0) {
        ocl.ReleaseMemObject(out);
        fail_init_code("OpenCL SHA-1 self-test launch", err);
        return -1;
    }
    err = ocl.EnqueueReadBuffer(gpu.queue, out, 1, 0, sizeof got, got, 0, NULL, NULL);
    ocl.ReleaseMemObject(out);
    if (err != 0) {
        fail_init_code("OpenCL SHA-1 self-test read", err);
        return -1;
    }
    if (got[5] != 0) {
        fail_init("OpenCL SHA-1 lanes did not agree");
        return -1;
    }
    if (!digest_is(got, expect)) {
        uint8_t raw[20];
        char got_hex[41];
        char exp_hex[41];
        for (int i = 0; i < 5; i++) {
            raw[i * 4] = (uint8_t)(got[i] >> 24);
            raw[i * 4 + 1] = (uint8_t)(got[i] >> 16);
            raw[i * 4 + 2] = (uint8_t)(got[i] >> 8);
            raw[i * 4 + 3] = (uint8_t)got[i];
        }
        hex_bytes(got_hex, raw);
        hex_bytes(exp_hex, expect);
        snprintf(init_error, sizeof init_error, "OpenCL SHA-1 of %s returned %s, OpenSSL returned %s", label,
                 got_hex, exp_hex);
        copy_error(init_error);
        return -1;
    }
    return 0;
}

static int build_log(cl_program program, cl_device_id device) {
    size_t bytes = 0;
    cl_int err = ocl.GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &bytes);
    if (err != 0 || bytes < 2) {
        fail_init("OpenCL program build failed");
        return -1;
    }
    char *log = malloc(bytes + 1);
    if (log == NULL) {
        fail_init("OpenCL program build failed");
        return -1;
    }
    err = ocl.GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, bytes, log, NULL);
    if (err != 0) {
        free(log);
        fail_init("OpenCL program build failed");
        return -1;
    }
    log[bytes] = '\0';
    const char *show = log;
    if (bytes > 1800) {
        show = log + (bytes - 1800);
    }
    snprintf(init_error, sizeof init_error, "OpenCL program build failed: %s", show);
    copy_error(init_error);
    free(log);
    return -1;
}

static size_t pick_local(size_t limit) {
    size_t local = 1;
    size_t cap = limit < 256 ? limit : 256;
    while (local * 2 <= cap) {
        local *= 2;
    }
    return local < 1 ? 1 : local;
}

static cl_mem make_buffer(cl_mem_flags flags, size_t bytes) {
    cl_int err = 0;
    cl_mem mem = ocl.CreateBuffer(gpu.context, flags, bytes, NULL, &err);
    if (mem == NULL || err != 0) {
        fail_init_code("clCreateBuffer", err);
        return NULL;
    }
    return mem;
}

static int init_gpu(void) {
    ocl.lib = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (ocl.lib == NULL) {
        ocl.lib = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (ocl.lib == NULL) {
        const char *why = dlerror();
        snprintf(init_error, sizeof init_error, "libOpenCL.so.1 did not load%s%s", why == NULL ? "" : ": ",
                 why == NULL ? "" : why);
        copy_error(init_error);
        return -1;
    }
    if (load_sym(&ocl.GetPlatformIDs, "clGetPlatformIDs", 0) != 0 ||
        load_sym(&ocl.GetDeviceIDs, "clGetDeviceIDs", 0) != 0 ||
        load_sym(&ocl.GetDeviceInfo, "clGetDeviceInfo", 0) != 0 ||
        load_sym(&ocl.CreateContext, "clCreateContext", 0) != 0 ||
        load_sym(&ocl.CreateCommandQueue, "clCreateCommandQueue", 1) != 0 ||
        load_sym(&ocl.CreateCommandQueueWithProperties, "clCreateCommandQueueWithProperties", 1) != 0 ||
        load_sym(&ocl.CreateProgramWithSource, "clCreateProgramWithSource", 0) != 0 ||
        load_sym(&ocl.BuildProgram, "clBuildProgram", 0) != 0 ||
        load_sym(&ocl.GetProgramBuildInfo, "clGetProgramBuildInfo", 0) != 0 ||
        load_sym(&ocl.CreateKernel, "clCreateKernel", 0) != 0 ||
        load_sym(&ocl.CreateBuffer, "clCreateBuffer", 0) != 0 ||
        load_sym(&ocl.SetKernelArg, "clSetKernelArg", 0) != 0 ||
        load_sym(&ocl.EnqueueWriteBuffer, "clEnqueueWriteBuffer", 0) != 0 ||
        load_sym(&ocl.EnqueueNDRangeKernel, "clEnqueueNDRangeKernel", 0) != 0 ||
        load_sym(&ocl.EnqueueReadBuffer, "clEnqueueReadBuffer", 0) != 0 ||
        load_sym(&ocl.GetKernelWorkGroupInfo, "clGetKernelWorkGroupInfo", 0) != 0 ||
        load_sym(&ocl.ReleaseMemObject, "clReleaseMemObject", 0) != 0 ||
        load_sym(&ocl.ReleaseKernel, "clReleaseKernel", 0) != 0 ||
        load_sym(&ocl.ReleaseProgram, "clReleaseProgram", 0) != 0 ||
        load_sym(&ocl.ReleaseCommandQueue, "clReleaseCommandQueue", 0) != 0 ||
        load_sym(&ocl.ReleaseContext, "clReleaseContext", 0) != 0) {
        return -1;
    }
    if (ocl.CreateCommandQueueWithProperties == NULL && ocl.CreateCommandQueue == NULL) {
        fail_init("OpenCL is missing clCreateCommandQueue");
        return -1;
    }

    cl_uint platforms_n = 0;
    cl_int err = ocl.GetPlatformIDs(0, NULL, &platforms_n);
    if (err != 0 || platforms_n == 0) {
        fail_init("OpenCL reported no platforms");
        return -1;
    }
    cl_uint listed = platforms_n > 8 ? 8 : platforms_n;
    cl_platform_id platforms[8];
    err = ocl.GetPlatformIDs(listed, platforms, NULL);
    if (err != 0) {
        fail_init_code("clGetPlatformIDs", err);
        return -1;
    }

    cl_platform_id chosen = NULL;
    cl_device_id device = NULL;
    for (cl_uint i = 0; i < listed; i++) {
        cl_uint devices_n = 0;
        err = ocl.GetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 1, &device, &devices_n);
        if (err == 0 && devices_n > 0) {
            chosen = platforms[i];
            break;
        }
        device = NULL;
    }
    if (chosen == NULL || device == NULL) {
        fail_init("OpenCL reported no GPU");
        return -1;
    }

    err = ocl.GetDeviceInfo(device, CL_DEVICE_NAME, sizeof gpu.name, gpu.name, NULL);
    gpu.name[sizeof gpu.name - 1] = '\0';
    if (err != 0 || gpu.name[0] == '\0') {
        fail_init("OpenCL device name is not available");
        return -1;
    }
    size_t name_len = strlen(gpu.name);
    while (name_len > 0 && (gpu.name[name_len - 1] == ' ' || gpu.name[name_len - 1] == '\n')) {
        gpu.name[--name_len] = '\0';
    }

    cl_uint units = 1;
    if (ocl.GetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof units, &units, NULL) != 0 || units == 0) {
        units = 1;
    }
    size_t device_wg = 256;
    if (ocl.GetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof device_wg, &device_wg, NULL) != 0 ||
        device_wg == 0) {
        device_wg = 64;
    }

    cl_context_properties props[3] = {
        (cl_context_properties)CL_CONTEXT_PLATFORM,
        (cl_context_properties)(intptr_t)chosen,
        0,
    };
    cl_context context = ocl.CreateContext(props, 1, &device, NULL, NULL, &err);
    if (context == NULL || err != 0) {
        fail_init_code("clCreateContext", err);
        return -1;
    }
    gpu.context = context;
    gpu.device = device;

    cl_command_queue queue = NULL;
    if (ocl.CreateCommandQueueWithProperties != NULL) {
        queue = ocl.CreateCommandQueueWithProperties(context, device, NULL, &err);
    } else {
        queue = ocl.CreateCommandQueue(context, device, 0, &err);
    }
    if (queue == NULL || err != 0) {
        fail_init_code("clCreateCommandQueue", err);
        release_gpu();
        return -1;
    }
    gpu.queue = queue;

    const char *source = KERNEL;
    cl_program program = ocl.CreateProgramWithSource(context, 1, &source, NULL, &err);
    if (program == NULL || err != 0) {
        fail_init_code("clCreateProgramWithSource", err);
        release_gpu();
        return -1;
    }
    gpu.program = program;
    err = ocl.BuildProgram(program, 1, &device, "-cl-std=CL1.2", NULL, NULL);
    if (err != 0) {
        build_log(program, device);
        release_gpu();
        return -1;
    }

    cl_int self_err = 0;
    cl_int scan_err = 0;
    cl_kernel self = ocl.CreateKernel(program, "imsovain_sha1_self", &self_err);
    cl_kernel scan = ocl.CreateKernel(program, "imsovain_scan", &scan_err);
    if (self == NULL || scan == NULL) {
        if (self != NULL) {
            ocl.ReleaseKernel(self);
        }
        if (scan != NULL) {
            ocl.ReleaseKernel(scan);
        }
        fail_init_code("clCreateKernel", self == NULL ? self_err : scan_err);
        release_gpu();
        return -1;
    }
    gpu.self = self;
    gpu.scan = scan;

    size_t kernel_wg = device_wg;
    if (ocl.GetKernelWorkGroupInfo(scan, device, CL_KERNEL_WORK_GROUP_SIZE, sizeof kernel_wg, &kernel_wg, NULL) !=
            0 ||
        kernel_wg == 0) {
        kernel_wg = device_wg;
    }
    if (kernel_wg > device_wg) {
        kernel_wg = device_wg;
    }
    gpu.local = pick_local(kernel_wg);
    gpu.units = units;

    gpu.words = make_buffer(CL_MEM_READ_ONLY, 16u * sizeof(uint32_t));
    gpu.prefix_len = make_buffer(CL_MEM_READ_ONLY, IMSOVAIN_FILTER_MAX * sizeof(uint32_t));
    gpu.prefix_hi = make_buffer(CL_MEM_READ_ONLY, IMSOVAIN_FILTER_MAX * sizeof(uint32_t));
    gpu.prefix_lo = make_buffer(CL_MEM_READ_ONLY, IMSOVAIN_FILTER_MAX * sizeof(uint32_t));
    gpu.hit = make_buffer(CL_MEM_READ_WRITE, sizeof(uint32_t));
    if (gpu.words == NULL || gpu.prefix_len == NULL || gpu.prefix_hi == NULL || gpu.prefix_lo == NULL ||
        gpu.hit == NULL) {
        release_gpu();
        return -1;
    }

    static const uint8_t abc[3] = {'a', 'b', 'c'};
    if (self_test_message(abc, sizeof abc, "abc") != 0) {
        release_gpu();
        return -1;
    }
    uint8_t sample[54];
    for (size_t i = 0; i < sizeof sample; i++) {
        sample[i] = (uint8_t)(0xA5u ^ i);
    }
    if (self_test_message(sample, sizeof sample, "a 54-byte block") != 0) {
        release_gpu();
        return -1;
    }
    return 0;
}

static int ensure_gpu(void) {
    if (gpu.ready) {
        return 0;
    }
    if (gpu.failed) {
        copy_error(init_error[0] ? init_error : "OpenCL search failed");
        return -1;
    }
    if (init_gpu() != 0) {
        gpu.failed = 1;
        release_gpu();
        return -1;
    }
    gpu.ready = 1;
    return 0;
}

static int filter_ok(const imsovain_filter *filter) {
    if (filter == NULL) {
        return 0;
    }
    if (filter->kind == IMSOVAIN_FILTER_REPEAT) {
        return filter->leading >= 1 && filter->leading <= 8;
    }
    return filter->kind == IMSOVAIN_FILTER_PREFIX && filter->count >= 1 && filter->count <= IMSOVAIN_FILTER_MAX;
}

static size_t launch_threads(uint32_t limit) {
    size_t local = gpu.local < 1 ? 1 : gpu.local;
    size_t need = ((size_t)limit + 3u) / 4u;
    /* 2048 threads per compute unit fills this GPU without extra launches. */
    size_t target = (size_t)gpu.units * 2048u;
    if (target < local) {
        target = local;
    }
    if (target > need) {
        target = need;
    }
    size_t groups = (target + local - 1) / local;
    size_t global = groups * local;
    if (global < local) {
        global = local;
    }
    return global;
}

static int64_t launch_scan(const uint8_t *src, size_t len, uint32_t max_iter, const imsovain_filter *filter,
                           uint64_t *checked) {
    if (len >= 56) {
        copy_error("OpenCL search hashes one SHA-1 block, and this preimage is longer than 55 bytes");
        return -2;
    }
    if (src == NULL || len < 8 || !filter_ok(filter) || max_iter == 0) {
        copy_error("OpenCL search arguments are not valid");
        return -2;
    }

    uint32_t words[16];
    if (load_words(src, len, words) != 0) {
        copy_error("OpenCL search could not pad the block");
        return -2;
    }
    uint32_t start = words[1];
    uint64_t room = (uint64_t)start + 1u;
    uint32_t limit = max_iter;
    if ((uint64_t)limit > room) {
        limit = room > 0xffffffffu ? 0xffffffffu : (uint32_t)room;
    }

    uint32_t plen[IMSOVAIN_FILTER_MAX];
    uint32_t phi[IMSOVAIN_FILTER_MAX];
    uint32_t plo[IMSOVAIN_FILTER_MAX];
    memset(plen, 0, sizeof plen);
    memset(phi, 0, sizeof phi);
    memset(plo, 0, sizeof plo);
    uint32_t prefix_count = 0;
    if (filter->kind == IMSOVAIN_FILTER_PREFIX) {
        prefix_count = filter->count;
        for (uint32_t i = 0; i < prefix_count; i++) {
            plen[i] = filter->len[i];
            phi[i] = read_be32(filter->bytes[i]);
            plo[i] = read_be32(filter->bytes[i] + 4);
        }
    }

    if (write_buf(gpu.words, words, sizeof words) != 0 ||
        write_buf(gpu.prefix_len, plen, sizeof plen) != 0 ||
        write_buf(gpu.prefix_hi, phi, sizeof phi) != 0 ||
        write_buf(gpu.prefix_lo, plo, sizeof plo) != 0) {
        return -2;
    }
    uint32_t sentinel = 0xffffffffu;
    if (write_buf(gpu.hit, &sentinel, sizeof sentinel) != 0) {
        return -2;
    }
    if (set_mem(gpu.scan, 0, gpu.words) != 0 || set_u32(gpu.scan, 1, limit) != 0 ||
        set_u32(gpu.scan, 2, filter->kind) != 0 || set_u32(gpu.scan, 3, filter->leading) != 0 ||
        set_u32(gpu.scan, 4, prefix_count) != 0 || set_mem(gpu.scan, 5, gpu.prefix_len) != 0 ||
        set_mem(gpu.scan, 6, gpu.prefix_hi) != 0 || set_mem(gpu.scan, 7, gpu.prefix_lo) != 0 ||
        set_mem(gpu.scan, 8, gpu.hit) != 0) {
        return -2;
    }

    size_t local = gpu.local < 1 ? 1 : gpu.local;
    size_t global = launch_threads(limit);
    cl_int err = ocl.EnqueueNDRangeKernel(gpu.queue, gpu.scan, 1, NULL, &global, &local, 0, NULL, NULL);
    if (err != 0) {
        fail_call("clEnqueueNDRangeKernel", err);
        return -2;
    }
    uint32_t hit = sentinel;
    err = ocl.EnqueueReadBuffer(gpu.queue, gpu.hit, 1, 0, sizeof hit, &hit, 0, NULL, NULL);
    if (err != 0) {
        fail_call("clEnqueueReadBuffer", err);
        return -2;
    }
    if (checked != NULL) {
        *checked = limit;
    }
    if (hit == sentinel) {
        return -1;
    }
    if (hit >= limit) {
        copy_error("OpenCL returned a match outside the window");
        if (checked != NULL) {
            *checked = 0;
        }
        return -2;
    }
    return (int64_t)(start - hit);
}

int64_t imsovain_opencl_search(const uint8_t *src, size_t len, size_t time_off, uint32_t max_iter,
                             const imsovain_filter *filter, uint64_t *checked) {
    if (checked != NULL) {
        *checked = 0;
    }
    if (time_off != 4) {
        copy_error("OpenCL search wants the creation time at byte 4");
        return -2;
    }
    pthread_mutex_lock(&gpu_lock);
    if (ensure_gpu() != 0) {
        pthread_mutex_unlock(&gpu_lock);
        return -2;
    }
    int64_t found = launch_scan(src, len, max_iter, filter, checked);
    pthread_mutex_unlock(&gpu_lock);
    return found;
}

int imsovain_opencl_device(char *buf, size_t buflen) {
    if (buf == NULL || buflen < 2) {
        copy_error("OpenCL device name buffer is too small");
        return -1;
    }
    buf[0] = '\0';
    pthread_mutex_lock(&gpu_lock);
    if (ensure_gpu() != 0) {
        pthread_mutex_unlock(&gpu_lock);
        return -1;
    }
    snprintf(buf, buflen, "%s", gpu.name);
    pthread_mutex_unlock(&gpu_lock);
    if (buf[0] == '\0') {
        copy_error("OpenCL device name was empty");
        return -1;
    }
    return 0;
}

const char *imsovain_opencl_last_error(void) {
    if (thread_error[0] == '\0') {
        return "OpenCL search failed";
    }
    return thread_error;
}

__attribute__((destructor)) static void imsovain_opencl_shutdown(void) {
    pthread_mutex_lock(&gpu_lock);
    release_gpu();
    gpu.ready = 0;
    pthread_mutex_unlock(&gpu_lock);
}
