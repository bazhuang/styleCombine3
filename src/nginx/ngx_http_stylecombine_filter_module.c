/*
 * Copyright (C) Bryton Lee
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_STYLECOMBINE_START     0
#define NGX_HTTP_STYLECOMBINE_READ      1
#define NGX_HTTP_STYLECOMBINE_PROCESS   2
#define NGX_HTTP_STYLECOMBINE_PASS      3
#define NGX_HTTP_STYLECOMBINE_DONE      4


#define NGX_HTTP_SYTLECOMBINE_BUFFERED 0x01


/* module defined struct and function prototypes put here. */
typedef struct {
    ngx_flag_t           enable;
    ngx_str_t            app_name;
    ngx_array_t          *old_domains;
    ngx_array_t          *new_domains;
    ngx_array_t          *filter_cntx_type;
    ngx_array_t          *async_var_names;

    ngx_int_t            max_url_len;
    ngx_array_t          *black_lst;
    ngx_array_t          *white_lst;
    ngx_str_t            log_format;
    ngx_str_t            custom_log;

} ngx_http_stylecombine_conf_t;

typedef struct {
    u_char                      *page;
    u_char                      *last;

    size_t                      page_size;
    ngx_uint_t                  phase;
    unsigned                    buffered;

    /* TODO: something more here, I guess. */

    ngx_http_request_t  *request;
} ngx_http_stylecombine_ctx_t;

static void *ngx_http_stylecombine_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_stylecombine_filter_init(ngx_conf_t *cf); 
static ngx_int_t ngx_http_stylecombine_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_stylecombine_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t  ngx_http_stylecombine_filter_commands[] = {
    {ngx_string("SC_Enabled"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, enable),
        NULL },

    {ngx_string("SC_AppName"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, app_name),
        NULL },

    {ngx_string("SC_OldDomains"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, old_domains),
        NULL },

    {ngx_string("SC_NewDomains"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, new_domains),
        NULL },

    {ngx_string("SC_FilterCntType"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, filter_cntx_type),
        NULL },

    {ngx_string("SC_AsyncVariableNames"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, async_var_names),
        NULL },

    {ngx_string("SC_MaxUrlLen"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, max_url_len),
        NULL },

    {ngx_string("SC_BlackList"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, black_lst),
        NULL },

    {ngx_string("SC_WhiteList"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, white_lst),
        NULL },

    {ngx_string("LogFormat"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, log_format),
        NULL },

    {ngx_string("CustomLog"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, custom_log),
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_stylecombine_filter_module_ctx = {
    NULL,           /* preconfiguration */
    //ngx_http_stylecombine_add_variables,           /* preconfiguration */
    ngx_http_stylecombine_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,             /* create location configuration */
    //ngx_http_stylecombine_create_conf,             /* create location configuration */
    ngx_http_stylecombine_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_stylecombine_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_stylecombine_filter_module_ctx,      /* module context */
    ngx_http_stylecombine_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void *                                                  
ngx_http_stylecombine_create_conf(ngx_conf_t *cf)                      
{                                                              
    ngx_http_stylecombine_conf_t  *conf;                               
                                                               
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_stylecombine_conf_t));
    if (conf == NULL) {                                        
        return NULL;                                           
    }                                                          
                                                               
    conf->enable = NGX_CONF_UNSET;                             
    conf->app_name = NGX_CONF_UNSET_PTR;                          
    conf->old_domains = NGX_CONF_UNSET_PTR;
    conf->new_domains = NGX_CONF_UNSET_PTR;
    conf->filter_cntx_type = NGX_CONF_UNSET_PTR;
    conf->async_var_names = NGX_CONF_UNSET_PTR;
    conf->max_url_len = NGX_CONF_UNSET;
    conf->black_lst = NGX_CONF_UNSET_PTR;
    conf->white_lst = NGX_CONF_UNSET_PTR;
    conf->log_format = NGX_CONF_UNSET_PTR;
    conf->custom_log = NGX_CONF_UNSET_PTR;
                                                               
    return conf;                                               
}                                                              

static ngx_int_t                                              
ngx_http_stylecombine_filter_init(ngx_conf_t *cf)                     
{                                                             
    /* TODO: init StyleVersionUpdator subprocess, maybe here, I'm not sure. */

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_stylecombine_header_filter; 

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_stylecombine_body_filter;     
                                                              
    return NGX_OK;                                            
}

static ngx_int_t                                                       
ngx_http_stylecombine_header_filter(ngx_http_request_t *r)                     
{                                                                      
    ngx_http_stylecombine_ctx_t   *ctx;                                        
    ngx_http_stylecombine_conf_t  *conf;                                       
    off_t                          len;
                                                                       
    conf = ngx_http_get_module_loc_conf(r, ngx_http_stylecombine_filter_module)
                                                                       
    if (!conf->enable                                                  
        || (r->headers_out.status != NGX_HTTP_OK                       
            && r->headers_out.status != NGX_HTTP_FORBIDDEN             
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)            
        || (r->headers_out.content_encoding                            
            && r->headers_out.content_encoding->value.len)             
        || (r->headers_out.content_length_n != -1                      
            && r->headers_out.content_length_n < conf->min_length)     
        || ngx_http_test_content_type(r, &conf->types) == NULL         
        || r->header_only)                                             
    {                                                                  
        return ngx_http_next_header_filter(r);                         
    }                                                                  

   /* content type */
   if (conf->filter_cntx_type != NGX_CONF_UNSET_PTR) {
        if ( r->headers_out.content_type.len != ngx_strlen(conf->filter_cntx_type)
            || ngx_strncasecmp(r->headers_out.content_type.date, conf->filter_cntx_type, \
                ngx_strlen(conf->filter_cntx_type)) != 0 ) {
            return ngx_http_next_header_filter(r);
        }
   }
                                                                       
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_stylecombine_ctx_t));    
    if (ctx == NULL) {                                          
        return NGX_ERROR;                                       
    }                                                           
                                                                
    ngx_http_set_ctx(r, ctx, ngx_http_stylecombine_filter_module);      
                                                                
    ctx->request = r;                                           

    len = r->headers_out.content_length_n;
    if ( len == -1 )
        return NGX_ERROR;

    ctx->page_size = len;

    /* TODO: fill it. */

    return ngx_http_next_header_filter(r);
}

static ngx_int_t                                                    
ngx_http_stylecombine_body_filter(ngx_http_request_t *r, ngx_chain_t *in)   
{                                                                   
    int                   rc;                                       
    ngx_chain_t                    out;
    ngx_http_stylecombine_ctx_t  *ctx;                                      
    ngx_http_stylecombine_conf_t  *conf;                                       
                                                                       
    conf = ngx_http_get_module_loc_conf(r, ngx_http_stylecombine_filter_module)
    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);  
                                                                    
    if (ctx == NULL || r->header_only) {               
        return ngx_http_next_body_filter(r, in);                    
    }                                                               
    
    switch (ctx->phase) {

    case NGX_HTTP_STYLECOMBINE_START:
        /* do something per-request init or test. */
        ctx->phase = NGX_HTTP_STYLECOMBINE_READ;

        /* fall through */
    case NGX_HTTP_STYLECOMBINE_READ:
        rc = ngx_http_stylecombine_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_stylecombine_filter_module,
                                              NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        /* fall through */
    case NGX_HTTP_IMAGE_PROCESS:

        out.buf = ngx_http_stylecombine_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_stylecombine_filter_module,
                                              NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_STYLECOMBINE_PASS;

        return ngx_http_stylecombine_send(r, ctx, &out);

    case NGX_HTTP_IMAGE_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_STYLECOMBINE_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}

static ngx_int_t
ngx_http_stylecombine_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_stylecombine_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module)

    if (ctx->page == NULL) {
        ctx->page = ngx_palloc(r->pool, ctx->page_size);
        if (ctx->page == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->page;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "styecombine buf: %uz", size);

        rest = ctx->page + ctx->page_size - p;
        size = (rest < size) ? rest : size;

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    ctx->buffered |= NGX_HTTP_SYTLECOMBINE_BUFFERED;

    return NGX_AGAIN;
}

static ngx_buf_t *
ngx_http_stylecombine_process(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_stylecombine_filter_ctx_t   *ctx;
    ngx_http_stylecombine_filter_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);
    ctx->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
    
    /* TODO conjoin with stylecombine html_parse */
    rc =  html_parser(some param xxx ...);
    if (rc == xxx )
        return  NGX_OK;
}
                                                                            

static ngx_int_t
ngx_http_stylecombine_send(ngx_http_request_t *r, ngx_http_stylecombine_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_STYLECOMBINE_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}

