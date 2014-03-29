/* 
 * Copyright (C) Bryton Lee 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "sc_config.h"

#define NGX_HTTP_STYLECOMBINE_START     0
#define NGX_HTTP_STYLECOMBINE_READ      1
#define NGX_HTTP_STYLECOMBINE_PROCESS   2
#define NGX_HTTP_STYLECOMBINE_PASS      3
#define NGX_HTTP_STYLECOMBINE_DONE      4


#define NGX_HTTP_STYLECOMBINE_BUFFERED 0x01

#define NGX_HTTP_STYLECOMBINE_NONE      0
#define NGX_HTTP_STYLECOMBINE_HTML      1


/* module defined struct and function prototypes put here. */
typedef struct {
    ngx_flag_t           enable;
    ngx_str_t            app_name;
    ngx_array_t          *old_domains;
    ngx_array_t          *new_domains;
    ngx_str_t            filter_cntx_type;
    ngx_array_t          *async_var_names;

    ngx_int_t            max_url_len;
    ngx_str_t            black_lst;
    ngx_str_t            white_lst;

    StyleParserTag   *styleParserTags[2];
    GlobalVariable       sc_global_config;
} ngx_http_stylecombine_conf_t;

typedef struct {
    ngx_chain_t                 *in;
    u_char                      *page;
    u_char                      *last;

    off_t                       saved_page_size;
    off_t                       page_size;
    ngx_uint_t                  phase;
    unsigned                    buffered;

    short                       isHTML;
    short                       debugMode;
    ngx_http_request_t  *request;
} ngx_http_stylecombine_ctx_t;

void *nginx_sc_module_init(sc_pool_t*, ngx_http_stylecombine_conf_t *conf);
