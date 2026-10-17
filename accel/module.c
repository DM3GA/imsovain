#define PY_SSIZE_T_CLEAN
#include <Python.h>

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

static PyObject *py_search(PyObject *self, PyObject *args) {
    Py_buffer view;
    unsigned long time_off = 0;
    unsigned long max_iter = 0;
    unsigned long leading = 0;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*kkk", &view, &time_off, &max_iter, &leading)) {
        return NULL;
    }
    if (max_iter > 0xfffffffful || leading > 8ul || time_off > (unsigned long)view.len) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "search arguments are out of range");
        return NULL;
    }

    size_t len = (size_t)view.len;
    uint8_t *copy = malloc(len == 0 ? 1 : len);
    if (copy == NULL) {
        PyBuffer_Release(&view);
        return PyErr_NoMemory();
    }
    if (len > 0 && view.buf != NULL) {
        memcpy(copy, view.buf, len);
    }
    PyBuffer_Release(&view);

    uint64_t checked = 0;
    int64_t found = 0;
    Py_BEGIN_ALLOW_THREADS
    found = pgpgen_search(copy, len, (size_t)time_off, (uint32_t)max_iter,
                          (unsigned)leading, &checked);
    Py_END_ALLOW_THREADS
    free(copy);

    if (found == -2) {
        PyErr_SetString(PyExc_RuntimeError, "SHA-1 search failed");
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

static PyMethodDef methods[] = {
    {"sha1", py_sha1, METH_VARARGS, "Return the SHA-1 digest of a byte string."},
    {"search", py_search, METH_VARARGS,
     "Search creation times. Returns (unix time or None, digests computed)."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_accel",
    .m_doc = "In-process OpenPGP v4 fingerprint search.",
    .m_size = -1,
    .m_methods = methods,
};

PyMODINIT_FUNC PyInit__accel(void) {
    return PyModule_Create(&module_def);
}
