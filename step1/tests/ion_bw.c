/*
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
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

#include <zhpeq.h>

enum z_op_types {
    ZNONE,
    ZGET,
    ZPUT,
};

/* global variables */
static struct zhpeq_attr zhpeq_attr;

struct args {
    int                 argc;
    char                **argv;
    uint64_t            ring_xfer_len;
    uint64_t            ring_entries;
    uint64_t            runs;
    uint64_t            qlen;
    uint32_t            gcid;
    int                 slice;
    enum z_op_types     op_type;
};

struct stuff {
    /* Both client and server. */
    const struct args       *args;
    struct zhpeq_dom        *zqdom;
    size_t                  ring_xfer_aligned;
    size_t                  ring_len;
    uint32_t                cmdq_entries[2];
    int32_t                 *reservations[2];
    void                    *local_buf[2];
    struct zhpeq_key_data   *qkdata[2];
    struct zhpeq_key_data   *local_kdata[2];
    struct zhpeq_tq         *ztq[2];
    void                    *addr_cookie;
};

static void stuff_free(struct stuff *stuff)
{
    int i;

    if (!stuff)
        return;

    if (stuff->addr_cookie)
        zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);

    for ( i=0;i<2;i++ ) {
        zhpeq_qkdata_free(stuff->local_kdata[i]);

        zhpeq_tq_free(stuff->ztq[i]);
    }

    zhpeq_domain_free(stuff->zqdom);

    for ( i=0;i<2;i++ ) {
        if (stuff->local_buf[i])
            munmap(stuff->local_buf[i], stuff->ring_xfer_aligned);
    }
}


/* get completions */
static int ztq_completions(struct zhpeq_tq *ztq)
{
    ssize_t             ret = 0;
    struct zhpe_cq_entry *cqe;
    struct zhpe_cq_entry cqe_copy;

    while ((cqe = zhpeq_tq_cq_entry(ztq))) {
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS)) {
            cqe_copy = *cqe;
            zhpeq_tq_cq_entry_done(ztq, cqe);
            ret = -EIO;
            print_err("%s,%u:index 0x%x status 0x%x\n", __func__, __LINE__,
                      cqe_copy.index, cqe_copy.status);
            break;
        }
        zhpeq_tq_cq_entry_done(ztq, cqe);
        ret++;
    }

    return ret;
}


/* Advance ztq->wq_tail_commit by cnt and write it */
/* For this test, do not check avail. */
static void ztq_start(struct zhpeq_tq *ztq, int32_t *reservations, uint64_t cnt)
{
    int i;
    for (i = 0; i < cnt; i++)
        zhpeq_tq_insert(ztq, reservations[i]);
    zhpeq_tq_commit(ztq);
}



/* Use existing pre-populated command buffer. */
static int do_client_unidir(struct stuff *conn)
{
    uint64_t            start_cyc;
    uint64_t            stop_cyc;
    uint64_t            elapsed;
    int                 count0=0;
    int                 count1=0;
    uint64_t            ring_entries = conn->args->ring_entries;

    start_cyc = get_cycles(NULL);

    ztq_start(conn->ztq[0], conn->reservations[0], ring_entries );
    ztq_start(conn->ztq[1], conn->reservations[1], ring_entries);

    // could loop the following
    while ((count0 < ring_entries) || (count1 < ring_entries)) {
       count0 += ztq_completions(conn->ztq[0]);
       count1 += ztq_completions(conn->ztq[1]);
    }

    stop_cyc = get_cycles(NULL);
    elapsed=(stop_cyc - start_cyc);

    printf("Elapsed Cycles %"PRIu64" ;",elapsed);
    printf(" size: %"PRIu64" ; numQueues: 2 ; numOps: 3 ;",conn->args->ring_xfer_len );
    printf(" tsc_freq %"PRIu64"\n",get_tsc_freq());
    return 0;
}


/* Allocate memory to store two buffers that can each hold       */
/* one 128 MB region of memory to be used for get/put operations */
static int do_mem_setup(struct stuff *conn)
{
    int                 ret;
    uint64_t            remote_zaddr;

    const struct args   *args = conn->args;
    union zhpe_hw_wq_entry *wqe;
    int                 i, j;

    ret = -EEXIST;

    /* prepare to set up one ring per tq */
    conn->ring_xfer_aligned = l1_up(args->ring_xfer_len);

    for ( i=0;i<2;i++ ) {
        conn->local_buf[i] = _zhpeu_mmap(NULL, conn->ring_xfer_aligned,
                                         PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_SHARED, -1 , 0);

        ret = zhpeq_mr_reg(conn->zqdom, conn->local_buf[i], conn->ring_xfer_aligned,
                           (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                            ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                           &conn->local_kdata[i]);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
            goto done;
        }

        /* do_fam_setup did export/import/zhpeq_zmmu_reg of remote mem */

        remote_zaddr = conn->qkdata[i]->z.zaddr;

        /* allocate reservations */
        conn->reservations[i]=calloc(conn->args->ring_entries, sizeof(uint32_t));

        /* Loop and fill in all commmand buffers. */
        for ( j = 0; j < conn->args->ring_entries; j++ ) {

            // reserve a command buffer
            ret = zhpeq_tq_reserve(conn->ztq[i]);
            if (ret < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "", ret);
                goto done;
            }
            conn->reservations[i][j]=ret;

            // wqe is in a buffer in the mem[] array in the queue
            // as opposed to in the queue or the command buffer
            wqe = zhpeq_tq_get_wqe(conn->ztq[i], ret);

            switch (args->op_type) {

            case ZGET:
                if (args->ring_xfer_len <= ZHPEQ_MAX_IMM)
                    zhpeq_tq_geti(wqe, 0, args->ring_xfer_len,
                                  remote_zaddr);
                else
                    zhpeq_tq_get(wqe, 0,
                                 (uintptr_t)conn->local_buf[i],
                                 args->ring_xfer_len,
                                 remote_zaddr);
            break;

            case ZPUT:
                if (args->ring_xfer_len <= ZHPEQ_MAX_IMM)
                    memset(zhpeq_tq_puti(wqe, 0, args->ring_xfer_len,
                                         remote_zaddr),
                                         0, args->ring_xfer_len);
                else
                    zhpeq_tq_put(wqe, 0,
                                 (uintptr_t)conn->local_buf,
                                  args->ring_xfer_len,
                                  remote_zaddr);
                break;

            default:
                ret = -EINVAL;
                break;
            }
        }
    }
    ret=0;
 done:
    return ret;
}

/* Set up remote address for the FAM memory and insert into the conn->zqdom */
/* Do this one time. */
/* Use zhpeq_fam_qkdata to get zhpeq_key_data for two regions. */
/* zhpeq_fam_qkdata sets length to be as large as possible for platform? */
/* At the end of this, the remote memory will be registered. */
static int do_fam_setup(struct stuff *conn)
{
    size_t                  n_qkdata = 0;
    struct zhpeq_key_data   *qkdata[2];
    size_t                  i;
    int                     rc;
    struct sockaddr_zhpe    *sz;
    uint                    gcid = conn->args->gcid;
    int                     ret=-1;

    /* TODO: save the sz and then free it? */
    sz = malloc(sizeof(struct sockaddr_zhpe));

    memset(sz, 0, sizeof(*sz));
    sz->sz_family = AF_ZHPE;
    zhpeu_install_gcid_in_uuid(sz->sz_uuid, gcid);
    sz->sz_queue = htonl(ZHPE_SZQ_FLAGS_FAM);

    /* Comment said that zctx_lock() must be held. */
    /* TODO: how to set zctx ? Get it from fid?
     *       Comment out fastlock for now because we're single-threaded */
    //    fastlock_acquire(conn->zctx->util_ep.lock);
    rc = zhpeq_domain_insert_addr(conn->zqdom, sz, &conn->addr_cookie);
     //   fastlock_release(conn->zctx->util_ep.lock);
    if (rc < 0) {
            printf("%s,%u:zhpeq_fam_qkdata() error %d\n",
                           __func__, __LINE__, rc);
            goto error;
    }
    /* Get qkdata entries for FAM.*/
    /* n_qkdata starts off being the ARRAY_SIZE (e.g., 2) then gets reset to 2 */
    n_qkdata = ARRAY_SIZE(qkdata);
    rc = zhpeq_fam_qkdata(conn->zqdom, conn->addr_cookie, qkdata, &n_qkdata);
    if (rc < 0) {
            printf("%s,%u:zhpeq_fam_qkdata() error %d\n",
                           __func__, __LINE__, rc);
            goto error;
    }
    for (i = 0; i < n_qkdata; i++) {
            rc = zhpeq_zmmu_reg(qkdata[i]);
            if (rc < 0) {
                    printf("%s,%u:zhpeq_zmmu_reg() error %d\n",
                                   __func__, __LINE__, rc);
                    break;
            }
    }

    if (rc < 0) {
            for (i = 0; i < n_qkdata; i++)
                    zhpeq_qkdata_free(qkdata[i]);
            goto error;
    }

    for (i = 0; i < n_qkdata; i++) {
        conn->qkdata[i] = qkdata[i];
    }

    return 0;

  error:
    return ret;
}

static int do_queue_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    int                 slice_mask;
    int                 i;

    ret = -EINVAL;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }

    for ( i=0;i<2;i++ ) {
        slice_mask = (1 << ( i & (ZHPE_MAX_SLICES - 1)));
        ret = zhpeq_tq_alloc(conn->zqdom, args->ring_entries,
                             args->ring_entries, 0, 0,
                             slice_mask, &conn->ztq[i]);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_tq_qalloc", "", ret);
            goto done;
        }
        conn->cmdq_entries[i] = conn->ztq[i]->tqinfo.cmplq.ent;
    }

    /* allocates FAM memory and get remote memory parameters. */
    ret = do_fam_setup(conn);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "do_mem_setup: returned %d", "", ret);
        goto done;
    }

    /* clients set up and initialize memory. */
    ret = do_mem_setup(conn);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "do_mem_setup", "", ret);
        goto done;
    }
 done:
    return ret;
}

static int do_client(const struct args *args)
{
    int                 ret;
    struct stuff        stuff = {
        .args           = args,
    };
    struct stuff        *conn = &stuff;
    uint64_t            i;

    /* set up conn->ztq[2] and conn->cmdq_entries[2] */
    ret = do_queue_setup(conn);

    /* runs is hard-coded in main for now */
    for (i = 0; i < args->runs; i++) {
        ret = do_client_unidir(conn);
        if (ret < 0)
            goto done;
    }

 done:
    stuff_free(conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-gp] [-s size] [-G gcid]"
        "\n"
        "Default transfer size:  0x8000000\n"
        "",
        appname);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}


/* Take gcid and operation types as input parameters. */
int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .runs           = -1,
        .op_type        = ZNONE,
        .slice          = -1,
        // .ring_xfer_len  = 0x8000000,
    };
    int                 opt;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    args.argc = argc;
    args.argv = argv;

    while ((opt = getopt(argc, argv, "gi:l:ps:G:")) != -1) {

        switch (opt) {

        case 'g':
            if (args.op_type != ZNONE)
                usage(false);
            args.op_type = ZGET;
            break;

        case 'i':
            if (args.runs != -1)
                usage(false);
            args.runs = atoi(optarg);
            break;

        case 'p':
            if (args.op_type != ZNONE)
                usage(false);
            args.op_type = ZPUT;
            break;

        case 's':
            if (args.ring_xfer_len  > 0)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "transfer_len",
                          optarg, &args.ring_xfer_len, 0,
                          1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 )
                usage(false);
            break;

        case 'G':
            if (args.gcid)
                usage(false);
            args.gcid = atoi(optarg);
            break;

        default:
            usage(false);

        }
    }

    if (args.op_type == ZNONE)
        usage(false);

    if (args.gcid <= 0)
        usage(false);

    if (args.ring_xfer_len  <= 0)
        args.ring_xfer_len = 0x8000000;

    /*
     * For now, hard-code to three entries.
     */
    args.ring_entries = 3;

    /* we are a FAM client */
    if (do_client(&args) < 0)
            goto done;

    ret = 0;

 done:

    return ret;
}
