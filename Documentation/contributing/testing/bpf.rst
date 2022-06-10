.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_testing:

********************************
BPF unit and integration testing
********************************

Our BPF data-path has it own test framework which allows us to write unit and integration tests that 
verify that our BPF code works as intended independently from the other Cilium components. The 
framework uses the ``BPF_PROG_RUN`` feature to run eBPF program in the kernel without attaching
them to actual hooks.

The framework is designed to allow developers, working on the data-path to quickly write tests
for the code they are working on. The tests themselves are fully written in C to minimize context
switching. Tests pass results back to the framework which will output the results in Go test output,
for optimal integration with CIs and other tools.

Running tests
=============

To run the test in your local environment:

.. code-block:: shell-session

    $ make -C test run_bpf_tests

The output is verbose by default. Verbose mode can be disabled with the ``V`` option:

.. code-block:: shell-session

    $ make -C test run_bpf_tests V=0

.. note:: Running BPF tests only works on Linux machines and require sudo access

Writing tests
=============

All BPF tests live in the ``bpf/tests`` directory. All ``.c`` files in this directory are assumed to
contain BPF test programs which can be independently compiled, loaded and executed using 
``BPF_PROG_RUN``. All files in this directory are automatically picked up, so all you have to do is 
create a new ``.c`` file and start writing. All other files like ``.h`` files are ignored and can be
used for shared code for example.

Each ``.c`` file must at least has one ``CHECK`` program. The ``CHECK`` macro replaces the ``SEC`` which is
typically used on BPF programs. The ``CHECK`` macro takes two argument, the first being the program
type(for example ``xdp`` or ``tc``. `link <https://github.com/cilium/ebpf/blob/49ebb13083886fc350167f2cde067e094a2b5037/elf_reader.go#L1074>`_),
the second is the name of the test which will appear in the output. All macros are defined in 
``bpf/tests/common.h``, all programs should start by including it: ``#include "common.h"``

.. code-block:: c
    
    #include "common.h"

    CHECK("xdp", "nodeport-lb4")
    int nodeportLB4(struct __ctx_buff *ctx)
    {
	    test_init();

        /* perform setup some conditions */
        /* call the functions you would like to test */
        /* check that everything works as expected */
        
        test_finish();
    }

Each ``CHECK`` program should start with ``test_init()`` and end with ``test_finish()``, ``CHECK`` programs
will return implicitly with the result of the test. A test is will PASS by default unless it is 
marked as failed or skipped.

Sub-tests
---------

Each ``CHECK`` program may contain sub-tests, each of which have their own test status. A sub-test is
created with the ``TEST`` macro like so:

.. code-block:: c

    #include "common.h"

    #include <bpf/ctx/xdp.h>
    #include <lib/jhash.h>
    #include "bpf/section.h"

    CHECK("xdp", "jhash")
    int bpf_test(__maybe_unused struct xdp_md *ctx)
    {
        test_init();

        TEST("Non-zero", {
            unsigned int hash = jhash_3words(123, 234, 345, 456);

            if (hash != 2698615579)
                test_fatal("expected '2698615579' got '%lu'", hash);
        });

        TEST("Zero", {
            unsigned int hash = jhash_3words(0, 0, 0, 0);

            if (hash != 459859287)
                test_fatal("expected '459859287' got '%lu'", hash);
        });

        test_finish();
    }

Since all sub-tests are part of the same BPF program they are executed all at once and can share
the same setup code which can improve run speed and reduce code duplication. Since each tests has
a name it serves to self-document, and makes it easier to spot what part of a test fails.

Integration tests
-----------------

Writing tests for a single function or small group of functions should be fairly straightforward, 
only requiring a ``CHECK`` program. Testing functionality across tail calls requires an additional step,
Since we will not return to the ``CHECK`` function after making a tail call, we can't check if it was
successful.

The fix is to use a ``SETUP`` program in addition to a ``CHECK`` program. ``SETUP`` programs with the same
name will run before the ``CHECK`` program. The context, modified by ``SETUP`` is then passed to ``CHECK``
which can inspect the result. By executing the test setup and executing the tail call in ``SETUP`` 
we can execute complete programs. The return code of the ``SETUP`` program is prefixed as ``u32`` to
the start of the packet data passed to ``CHECK``. 

This is a abbreviated example showing the key components:

.. code-block:: c
    
    #include "common.h"

    #include "bpf/ctx/xdp.h"
    #include "bpf_xdp.c"

    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(key_size, sizeof(__u32));
        __uint(max_entries, 2);
        __array(values, int());
    } entry_call_map __section(".maps") = {
        .values = {
            [0] = &bpf_xdp_entry,
        },
    };

    SETUP("xdp", "l2_example")
    int test1_setup(struct __ctx_buff *ctx)
    {
        /* Create room for our packet to be crafted */
        unsigned int data_len = ctx->data_end - ctx->data;
        int offset = offset = sizeof(struct ethhdr) - data_len;
        bpf_xdp_adjust_tail(ctx, offset);

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        if (data + sizeof(struct ethhdr) > data_end)
            return TEST_ERROR;

        /* Writing just the L2 header for brevity */
        struct ethhdr l2 = {
            .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
            .h_proto = bpf_htons(ETH_P_IP)
        };
        memcpy(data, &l2, sizeof(struct ethhdr));
       
        /* OMITTED setting up map state */

        /* Jump into the entrypoint */
        tail_call_static(ctx, &entry_call_map, 0);
        /* Fail if we didn't jump */
        return TEST_ERROR;
    }

    CHECK("xdp", "l2_example")
    int test1_check(__maybe_unused const struct __ctx_buff *ctx)
    {
        test_init();

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        if (data + sizeof(__u32) > data_end)
            test_fatal("status code out of bounds");

        __u32 *status_code = data;

        if (*status_code != XDP_TX)
            test_fatal("status code != XDP_TX");

        data += sizeof(__u32);

        if (data + sizeof(struct ethhdr) > data_end)
            test_fatal("ctx doesn't fit ethhdr");

        struct ethhdr *l2 = data;

        data += sizeof(struct ethhdr);

        if (memcmp(l2->h_source, fib_smac, sizeof(fib_smac)) != 0)
            test_fatal("l2->h_source != fib_smac");

        if (memcmp(l2->h_dest, fib_dmac, sizeof(fib_dmac)) != 0)
            test_fatal("l2->h_dest != fib_dmac");

        if (data + sizeof(struct iphdr) > data_end)
            test_fatal("ctx doesn't fit iphdr");

        test_finish();
    }

Function reference
------------------

* ``test_log(fmt, args...)`` - will write a log message. The conversion specifiers supported by *fmt* are the same as for
  ``bpf_trace_printk()``. They are **%d**, **%i**, **%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**, **%lli**, 
  **%llu**, **%llx**. No modifier (size of field, padding with zeroes, etc.) is available.

* ``test_fail()`` - marks the current test or sub-test as failed but will continue execution.

* ``test_fail_now()`` - marks the current test or sub-test as failed and will stop execution of the 
  test or sub-test (If called in a sub-tests, the other sub-tests will still run).

* ``test_fatal(fmt, args...)`` - writes a log and then calls ``test_fail_now()``

* ``assert(stmt)`` - asserts that the statement within is true and will ``test_fail_now()`` otherwise.
  Assert will log the file and line number of the assert statement.

* ``test_skip()`` - marks the current test or sub-test as skipped but will continue execution.

* ``test_skip_now()`` - marks the current test or sub-test as skipped and will stop execution of the 
  test or sub-test (If called in a sub-tests, the other sub-tests will still run).

* ``test_init()`` - this function initializes internal state and must be called before any of the 
  functions above can be called.

* ``test_finish()`` - this function submits the results and returns from the current function.

Function mocking
----------------

Being able to mock out a function is a great tool to have when creating tests for a number of 
reasons. You might for example want to tests what happens if a specific function returns an error 
to see if it is handled gracefully. You might want to proxy function calls to record if the function
under test actually called specific dependencies. Or you might want to test code that uses helpers
which rely on state we can't set in BPF like the routing table.

Mocking is a fairy easy:

1. Create a macro with the exact same name and make it equal to another function name.

2. Create a function with a unique name and the same signature as the function it is replacing.

3. Include the file which contains the definition we are replacing.

The following example mocks out the fib_lookup helper call and replaces it with our
mocked version, since we don't actually have routes for the IPs we want to test:

.. code-block:: c

    #include "common.h"

    #include "bpf/ctx/xdp.h"

    #define fib_lookup mock_fib_lookup

    static const char fib_smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    static const char fib_dmac[6] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};

    long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
                __maybe_unused int plen, __maybe_unused __u32 flags)
    {
        memcpy(params->smac, fib_smac, sizeof(fib_smac));
        memcpy(params->dmac, fib_dmac, sizeof(fib_dmac));
        return 0;
    }

    #include "bpf_xdp.c"
    #include "lib/nodeport.h"

Limitations
-----------

For all its benefits there are some limitations to this way of testing:

* Code must pass the verifier, so our setup and test code has to obey the same rules as other BPF
  programs. A side effect is that it automatically guarantees that all code that passes will also
  load. The biggest concern is the complexity limit on older kernels, this can be somewhat mitigated
  by separating heavy setup work into its own ``SETUP`` program and optionally tail calling into the 
  to be tested code to ensure the testing harness doesn't push us over the complexity limit.

* Test functions like ``test_log()``, ``test_fail()``, ``test_skip()`` can only be executed within the 
  scope of the main program or a ``TEST``. These function rely on variables set by ``test_init()`` and
  will produce errors when used in other functions. 
  
* Functions that stop execution(``test_fail_now()``, ``test_fatal()``, ``test_skip_now()``) can't be
  used within a sub-test(``TEST``) and ``for``, ``while``, or ``select`` since it used ``break`` to stop a
  sub-test. These functions can still be used from within ``for``, ``while`` and ``select`` if no 
  sub-tests are used since here the flow interruption happens via ``return``.

* Sub-test names can't use more than 127 characters.

* Log messages can't use more than 127 characters and have no more than 12 arguments.
