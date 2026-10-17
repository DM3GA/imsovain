#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "opencl.h"
#include "search.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static PyObject *py_sha1(PyObject *self, PyObject *args) {
    Py_buffer view;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*", &view)) {
        return NULL;
    }
    uint8_t hash[20];
    const uint8_t *data = view.buf == NULL ? (const uint8_t *)"" : view.buf;
    int rc = pgpgen_sha1(data, (size_t)view.len, hash);
    PyBuffer_Release(&view);
    if (rc != 0) {
        PyErr_SetString(PyExc_RuntimeError, "SHA-1 digest failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)hash, 20);
}

static PyObject *run_search(PyObject *args, int use_opencl) {
    Py_buffer view;
    Py_buffer blob;
    unsigned long time_off = 0;
    unsigned long max_iter = 0;
    if (!PyArg_ParseTuple(args, "y*kky*", &view, &time_off, &max_iter, &blob)) {
        return NULL;
    }
    if (max_iter > 0xfffffffful || max_iter == 0 || time_off > (unsigned long)view.len) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&blob);
        PyErr_SetString(PyExc_ValueError, "search arguments are out of range");
        return NULL;
    }
    pgpgen_filter filter;
    const uint8_t *blob_bytes = blob.buf == NULL ? (const uint8_t *)"" : blob.buf;
    if (pgpgen_filter_parse(blob_bytes, (size_t)blob.len, &filter) != 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&blob);
        PyErr_SetString(PyExc_ValueError, "filter is not valid");
        return NULL;
    }

    size_t len = (size_t)view.len;
    uint8_t *copy = malloc(len == 0 ? 1 : len);
    if (copy == NULL) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&blob);
        return PyErr_NoMemory();
    }
    if (len > 0 && view.buf != NULL) {
        memcpy(copy, view.buf, len);
    }
    PyBuffer_Release(&view);
    PyBuffer_Release(&blob);

    uint64_t checked = 0;
    int64_t found = 0;
    Py_BEGIN_ALLOW_THREADS
    if (use_opencl) {
        found = pgpgen_opencl_search(copy, len, (size_t)time_off, (uint32_t)max_iter, &filter, &checked);
    } else {
        found = pgpgen_search(copy, len, (size_t)time_off, (uint32_t)max_iter, &filter, &checked);
    }
    Py_END_ALLOW_THREADS
    free(copy);

    if (found == -2) {
        const char *message = use_opencl ? pgpgen_opencl_last_error() : "SHA-1 search failed";
        PyErr_SetString(PyExc_RuntimeError, message);
        return NULL;
    }

    PyObject *stamp;
    if (found < 0) {
        Py_INCREF(Py_None);
        stamp = Py_None;
    } else {
        stamp = PyLong_FromLongLong(found);
        if (stamp == NULL) {
            return NULL;
        }
    }
    return Py_BuildValue("NK", stamp, (unsigned long long)checked);
}

static PyObject *py_search(PyObject *self, PyObject *args) {
    (void)self;
    return run_search(args, 0);
}

static PyObject *py_search_opencl(PyObject *self, PyObject *args) {
    (void)self;
    return run_search(args, 1);
}

static PyObject *py_opencl_device(PyObject *self, PyObject *unused) {
    char name[256];
    (void)self;
    (void)unused;
    if (pgpgen_opencl_device(name, sizeof name) != 0) {
        PyErr_SetString(PyExc_RuntimeError, pgpgen_opencl_last_error());
        return NULL;
    }
    return PyUnicode_FromString(name);
}

static PyObject *py_match(PyObject *self, PyObject *args) {
    Py_buffer digest;
    Py_buffer blob;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*y*", &digest, &blob)) {
        return NULL;
    }
    if (digest.len != 20 || digest.buf == NULL) {
        PyBuffer_Release(&digest);
        PyBuffer_Release(&blob);
        PyErr_SetString(PyExc_ValueError, "a v4 fingerprint is 20 bytes");
        return NULL;
    }
    pgpgen_filter filter;
    const uint8_t *blob_bytes = blob.buf == NULL ? (const uint8_t *)"" : blob.buf;
    int parsed = pgpgen_filter_parse(blob_bytes, (size_t)blob.len, &filter);
    int matched = 0;
    if (parsed == 0) {
        matched = pgpgen_filter_match(digest.buf, &filter);
    }
    PyBuffer_Release(&digest);
    PyBuffer_Release(&blob);
    if (parsed != 0) {
        PyErr_SetString(PyExc_ValueError, "filter is not valid");
        return NULL;
    }
    if (matched) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyMethodDef methods[] = {
    {"sha1", py_sha1, METH_VARARGS, "Return the SHA-1 digest of a byte string."},
    {"search", py_search, METH_VARARGS,
     "Search creation times on the CPU. Returns (unix time or None, digests computed)."},
    {"search_opencl", py_search_opencl, METH_VARARGS,
     "Search creation times on an OpenCL GPU. Returns (unix time or None, digests dispatched)."},
    {"opencl_device", py_opencl_device, METH_NOARGS, "Return the OpenCL GPU name."},
    {"match", py_match, METH_VARARGS, "Return whether a fingerprint matches a packed filter."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_accel",
    .m_doc = "In-process OpenPGP v4 fingerprint search. The GPU path is separate from the CPU scan.",
    .m_size = -1,
    .m_methods = methods,
};

PyMODINIT_FUNC PyInit__accel(void) {
    return PyModule_Create(&module_def);
}
