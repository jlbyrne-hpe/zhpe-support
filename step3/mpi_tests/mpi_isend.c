/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a self-contained hello world that takes one argument:
 * a memory length.
 */

#include <libgen.h>
#include <mpi.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <zhpeq_util_fab.h>

#define _GNU_SOURCE

const char *appname;

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <length to malloc>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n",
        appname);

    MPI_Finalize();
    exit(help ? 0 : -1);
}

static int testit(uint64_t length, int myrank)
{
    size_t       i;
    int          ret = -1;
    int          other;
    void         *buf1;
    void         *buf2;
    uint16_t     *p;
    uint64_t     blength;
    MPI_Status   status1, status2;
    MPI_Request  req1, req2;

    other = (myrank ? 0 : 1 );

    blength = length*sizeof(uint16_t);
    buf1 = malloc(blength);
    if (!buf1) {
        print_err("malloc() failed\n");
        return ret;
    }
    buf2 = malloc(blength);
    if (!buf1) {
        print_err("malloc() failed\n");
        return ret;
    }

    printf("Rank %d attempting to send %lxu to %d\n",myrank, length, other);
    /* Minimum underlying length is 1 page. */
    if (length > 0) {
        MPI_Irecv(buf2, length, MPI_UINT16_T, other, 1, MPI_COMM_WORLD, &req2);

        printf("Writing to buf1:\n");
        for (i = 0, p = (uint16_t *) buf1; i < length; i += sizeof (*p), p++)
            *p = (i | 1);

        MPI_Isend(buf1, length, MPI_UINT16_T, other, 1, MPI_COMM_WORLD, &req1);

        MPI_Wait(&req2, &status2);

        printf("Checking contents of buf2:\n");
        ret=0;
        for (i = 0, p = buf2; i < length;
             i += sizeof(*p), p++) {
            if (*p != (typeof(*p))(i | 1)) {
                if (!ret)
                    print_err("first error: off 0x%08lx saw 0x%04x\n", i, *p);
                ret++;
            }
        }
        print_err("Saw %d errors out of %lu\n", ret,i);

        MPI_Wait(&req1, &status1);
    }

    free(buf1);
    free(buf2);
    return ret;
}

int main(int argc, char **argv)
{
    int             ret = 1;
    uint64_t        count, length;
    int             iterations=4;
    int myrank, numprocs;


    MPI_Init(&argc,&argv);

    MPI_Comm_size(MPI_COMM_WORLD, &numprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &myrank);

    appname = basename(argv[0]);

    if (argc < 2)
        usage(true);

    if (numprocs < 2)
        usage(true);

    if (parse_kb_uint64_t(__func__, __LINE__, "length", argv[1], &length, 0,
                          sizeof(uint16_t), SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    count = ceil(length/sizeof(uint16_t));

    for (int i=0; i< iterations; i++)
    {
        ret = testit(count, myrank);
        if (ret < 0) {
            printf("Iteration %d: failed\n",i);
            goto done;
        } else {
            printf("Iteration %d: success\n",i);
        }
    }

done:
    MPI_Finalize();
    return ret;
}
