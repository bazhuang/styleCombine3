/*
 * Copyright (C) Bryton Lee
 */

#include "stylecombine_ngx_module.h"
#include "sc_mod_filter.h"
#include "sc_version.h"
#include "sc_config.h"
#ifndef __SC_NEW_VERSION
#include "sc_html_parser.h"
#else
#include "sc_core.h"
#endif

static void *ngx_http_stylecombine_create_conf(ngx_conf_t *cf);
static char *ngx_http_stylecombine_merge_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_stylecombine_filter_init(ngx_conf_t *cf); 
static ngx_int_t ngx_http_stylecombine_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_stylecombine_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_uint_t ngx_http_stylecombine_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_stylecombine_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t * ngx_http_stylecombine_process(ngx_http_request_t *r);
static ngx_int_t ngx_http_stylecombine_send(ngx_http_request_t *r, ngx_http_stylecombine_ctx_t *ctx, 
        ngx_chain_t *in);

static ngx_command_t  ngx_http_stylecombine_filter_commands[] = {
    {ngx_string("SC_Enabled"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, enable),
        NULL },

    {ngx_string("SC_AppName"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, app_name),
        NULL },

    {ngx_string("SC_OldDomains"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, old_domains),
        NULL },

    {ngx_string("SC_NewDomains"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, new_domains),
        NULL },

    {ngx_string("SC_FilterCntType"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, filter_cntx_type),
        NULL },

    {ngx_string("SC_AsyncVariableNames"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, async_var_names),
        NULL },

    {ngx_string("SC_MaxUrlLen"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, max_url_len),
        NULL },

    {ngx_string("SC_BlackList"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, black_lst),
        NULL },

    {ngx_string("SC_WhiteList"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_stylecombine_conf_t, white_lst),
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_stylecombine_filter_module_ctx = {
    NULL,           /* preconfiguration */
    ngx_http_stylecombine_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_stylecombine_create_conf,             /* create location configuration */
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
    ngx_str_null(&conf->app_name);
    conf->old_domains = NGX_CONF_UNSET_PTR;
    conf->new_domains = NGX_CONF_UNSET_PTR;
    ngx_str_null(&conf->filter_cntx_type);
    conf->async_var_names = NGX_CONF_UNSET_PTR;
    conf->max_url_len = NGX_CONF_UNSET;
    ngx_str_null(&conf->black_lst);
    ngx_str_null(&conf->white_lst);
    
    return conf;                                               
}                                                              

static Buffer * ngx_sc_array_to_buffer(ngx_pool_t *pool, ngx_array_t *array,  ngx_int_t index)
{
    Buffer *tmp_buf = NULL;
    ngx_str_t *tmp_str = NULL;

    if ( NULL == pool || NULL == array || array->nelts < (ngx_uint_t)index ) 
        return NULL;
    
    tmp_str = (ngx_str_t*)((u_char *)array->elts + index * array->size);
    tmp_buf = buffer_init_size(pool, tmp_str->len + 1);
    if ( NULL == tmp_buf )
        return NULL;

    string_append(pool, tmp_buf, (char *)tmp_str->data, tmp_str->len);
    if (NULL == tmp_buf->ptr)
        return NULL;

    return tmp_buf;
}

static int ngx_sc_setWhiteList(sc_pool_t *pool, CombineConfig *sc_conf, ngx_str_t *arg)
{
    if ( NULL == pool ||
        NULL == sc_conf || 
        NULL == arg )
        return -1;

    regex_t *regexp = pattern_validate_compile(pool, (const char *)arg->data);
    if (!regexp) {
        return -1;
    }
    linked_list_add(pool, sc_conf->whiteList, regexp);
    return 0;
}

static int ngx_sc_setBlackList(sc_pool_t *pool, CombineConfig *sc_conf, ngx_str_t *arg)
{
    if ( NULL == pool ||
        NULL == sc_conf || 
        NULL == arg )
        return -1;

    regex_t *regexp = pattern_validate_compile(pool, (const char *)arg->data);
    if (!regexp) {
        return -1;
    }
    linked_list_add(pool, sc_conf->blackList, regexp);
    return 0;
}

static char *ngx_http_stylecombine_merge_conf(ngx_conf_t *cf,void *parent, void *child)
{
    ngx_http_stylecombine_conf_t *prev = parent;
    ngx_http_stylecombine_conf_t *conf = child;    
    CombineConfig  *sc_conf;
    ngx_int_t i, saved_count;

    if ( NULL == nginx_sc_module_init((sc_pool_t *)cf->pool, conf) )
        return NGX_CONF_ERROR;

    sc_conf = conf->sc_global_config.pConfig;

    /* enable */
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    sc_conf->enabled = (short )conf->enable;
    if ( !conf->enable )
        return NGX_CONF_OK;

    /* appname */
    ngx_str_t sc_app_unknow = ngx_string("SC_APP_NAME_UNKNOW");
    ngx_conf_merge_str_value(conf->app_name, prev->app_name, "SC_APP_NAME_UNKNOW");
    if ( ngx_strncmp(conf->app_name.data, sc_app_unknow.data, sc_app_unknow.len) == 0 ) {
        ngx_log_stderr(0, "SC_AppName is required");
        return NGX_CONF_ERROR;
    }
    sc_conf->appName = buffer_init_size(cf->pool, conf->app_name.len+1);
    if( NULL == sc_conf->appName )
        return NGX_CONF_ERROR;
    string_append(cf->pool, sc_conf->appName, (char *)conf->app_name.data, conf->app_name.len);

    /* old domains */
    ngx_conf_merge_ptr_value(conf->old_domains, prev->old_domains, NGX_CONF_UNSET_PTR);
    if ( conf->old_domains == NGX_CONF_UNSET_PTR )
        return NGX_CONF_ERROR;
    for(i = 0; i < DOMAINS_COUNT && (ngx_uint_t)i < conf->old_domains->nelts; i++ ) {
        sc_conf->oldDomains[i] = ngx_sc_array_to_buffer(cf->pool, conf->old_domains, i);
        if (NULL == sc_conf->oldDomains[i])
            return NGX_CONF_ERROR;

        SC_PATH_SLASH(sc_conf->oldDomains[i]);
    }

    saved_count = i;

    /* new domains */
    ngx_conf_merge_ptr_value(conf->new_domains, prev->new_domains, NGX_CONF_UNSET_PTR);
    if ( conf->new_domains == NGX_CONF_UNSET_PTR )
        return NGX_CONF_ERROR;
    for( i = 0; i < DOMAINS_COUNT && (ngx_uint_t) i < conf->new_domains->nelts; i++ ) {
        sc_conf->newDomains[i] = ngx_sc_array_to_buffer(cf->pool, conf->new_domains, i);
        if ( NULL == sc_conf->newDomains[i] )
            return NGX_CONF_ERROR;

        SC_PATH_SLASH(sc_conf->newDomains[i]);
    }

    /* old domains count should equal to new domains count */
    if ( i != saved_count )  {
        ngx_log_stderr(0, "oldDomains count should equal to newDomains count");
        return NGX_CONF_ERROR;
    }

    /* filter content type */
    ngx_str_t sc_filter_cntx_type_unknow = ngx_string("SC_FILTER_CNTX_TYPE_UNKNOW");
    ngx_conf_merge_str_value(conf->filter_cntx_type, prev->filter_cntx_type,  \
            "SC_FILTER_CNTX_TYPE_UNKNOW");
    if ( ngx_strncmp(conf->filter_cntx_type.data, sc_filter_cntx_type_unknow.data, \
                sc_filter_cntx_type_unknow.len) == 0 ) {
        ngx_log_stderr(0, "SC_FilterCntType is required");
        return NGX_CONF_ERROR;
    }
    sc_conf->filterCntType = (char *)conf->filter_cntx_type.data;

    /* async variable names */
    ngx_conf_merge_ptr_value(conf->async_var_names, prev->async_var_names, NGX_CONF_UNSET_PTR);
    if ( conf->async_var_names == NGX_CONF_UNSET_PTR ) {
        ngx_log_stderr(0, "SC_AsyncVariableNames is required");
        return NGX_CONF_ERROR;
    }
    for ( i = 0; i < saved_count; i++ ) {
        sc_conf->asyncVariableNames[i] =  \
            ngx_sc_array_to_buffer(cf->pool, conf->async_var_names, i);
        if ( NULL == sc_conf->asyncVariableNames[i] )
            return NGX_CONF_ERROR;
    }

    /* max url len */
    ngx_conf_merge_value(conf->max_url_len, prev->max_url_len, 1024);
    sc_conf->maxUrlLen = (int)conf->max_url_len; 

    /* black list */
    ngx_str_t sc_black_lst_unknow = ngx_string("SC_BLACK_LST_UNKNOW");
    ngx_conf_merge_str_value(conf->black_lst, prev->black_lst, "SC_BLACK_LST_UNKNOW");
    if ( ngx_strncmp(conf->black_lst.data, sc_black_lst_unknow.data, sc_black_lst_unknow.len) != 0 ) {
        if ( ngx_sc_setBlackList(cf->pool, sc_conf, &conf->black_lst) )
            return NGX_CONF_ERROR;
    }

    /* white list */
    ngx_str_t sc_white_lst_unknow = ngx_string("SC_WHITE_LST_UNKNOW");
    ngx_conf_merge_str_value(conf->white_lst, prev->white_lst, "SC_WHITE_LST_UNKNOW");
    if ( ngx_strncmp(conf->white_lst.data, sc_white_lst_unknow.data, sc_white_lst_unknow.len) != 0 ) {
        if ( ngx_sc_setWhiteList(cf->pool, sc_conf, &conf->white_lst) )
            return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

static ngx_int_t                                              
ngx_http_stylecombine_filter_init(ngx_conf_t *cf)                     
{                                                             

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
    CombineConfig   *sc_conf;
    ngx_str_t  arg_value;
    ngx_int_t ret, debugMode = 0;
                                                                       
    if ( r->headers_out.status != NGX_HTTP_OK || r->header_only ) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_stylecombine_filter_module);
    sc_conf = conf->sc_global_config.pConfig;
    if ( !conf->enable || ! sc_conf )
    {
        return ngx_http_next_header_filter(r);
    }

    ret = ngx_http_arg(r, (u_char *)DEBUG_MODE_PARAM, strlen(DEBUG_MODE_PARAM), &arg_value);
    if ( ret == NGX_OK ) {
        debugMode = ngx_atoi(arg_value.data, arg_value.len);
        if ( debugMode == DEBUG_ON ) {
            return ngx_http_next_header_filter(r);
        }
    }

    /* content type */
    if ( !r->headers_out.content_type.len || !r->headers_out.content_type.data || \
            ngx_strncasecmp(r->headers_out.content_type.data, conf->filter_cntx_type.data, \
           conf->filter_cntx_type.len) != 0 ) {
        return ngx_http_next_header_filter(r);
    }
                                                                       
    /* black & white list */
    if ( is_filter_uri((char *)r->uri.data, sc_conf->blackList, sc_conf->whiteList) ) {
        ngx_http_next_header_filter(r);
    }

    /* FIXME: if HTML page size bigger than 2MiB 
     * stylecombine will consume a lot of memory per request.
     * so if page size bigger than 2MiB, just ignore it */
    if ( r->headers_out.content_length_n > 2 * 1024 * 1024 ) {
        return ngx_http_next_header_filter(r);
    }

    /* alloc per request content */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_stylecombine_ctx_t));    
    if (ctx == NULL) {                                          
        return NGX_ERROR;                                       
    }                                                           
    ngx_http_set_ctx(r, ctx, ngx_http_stylecombine_filter_module);      
    ctx->request = r;                                           

    ctx->isHTML = 0;
    ctx->debugMode = debugMode;
    ctx->saved_page_size = ctx->page_size = r->headers_out.content_length_n;

    ngx_http_clear_content_length(r);

    /* update (or initialize) stylecombine global variables */
    check_version_update(conf->sc_global_config.server_pool, r->pool, \
            &conf->sc_global_config);
    checkAmdVersionUpdate(conf->sc_global_config.server_pool, r->pool, \
            &conf->sc_global_config);

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;              

    return ngx_http_next_header_filter(r);
}

static ngx_int_t                                                    
ngx_http_stylecombine_body_filter(ngx_http_request_t *r, ngx_chain_t *in)   
{                                                                   
    int                   rc;                                       
    ngx_chain_t                    out;
    ngx_http_stylecombine_ctx_t  *ctx;                                      
                                                                       
    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module);  
                                                                    
    if (ctx == NULL || r->header_only) {               
        return ngx_http_next_body_filter(r, in);                    
    }                                                               
    
    switch (ctx->phase) {

    case NGX_HTTP_STYLECOMBINE_START:
        if ( NGX_HTTP_STYLECOMBINE_NONE == ngx_http_stylecombine_test(r, in)) {
			if ( ctx->saved_page_size > 0 )
				r->headers_out.content_length_n = ctx->saved_page_size;
			return ngx_http_next_body_filter(r, in);
        }

        ctx->phase = NGX_HTTP_STYLECOMBINE_READ;
        /* fall through */
    case NGX_HTTP_STYLECOMBINE_READ:
        rc = ngx_http_stylecombine_read(r, in);

        if (rc == NGX_AGAIN ) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                  &ngx_http_stylecombine_filter_module,
                  NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        ctx->phase = NGX_HTTP_STYLECOMBINE_PROCESS;
        /* fall through */
    case NGX_HTTP_STYLECOMBINE_PROCESS:

        out.buf = ngx_http_stylecombine_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                  &ngx_http_stylecombine_filter_module,
                  NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_STYLECOMBINE_PASS;

        return ngx_http_stylecombine_send(r, ctx, &out);

    case NGX_HTTP_STYLECOMBINE_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_STYLECOMBINE_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}

static ngx_uint_t                                          
ngx_http_stylecombine_test(ngx_http_request_t *r, ngx_chain_t *in)
{                                                          
    size_t  size;
    ngx_http_stylecombine_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module);

    size =  in->buf->last - in->buf->pos;
    
    if( !ctx->isHTML && size ) {
        /* if page is not HTML, nothing to do */
        if ( !sc_is_html_data((const char*)in->buf->pos) )    
            return NGX_HTTP_STYLECOMBINE_NONE;
        ctx->isHTML = 1;
    }

    return NGX_HTTP_STYLECOMBINE_HTML;
}

static ngx_int_t
ngx_http_stylecombine_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_stylecombine_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module);
    if (ctx == NULL) {                          
        return ngx_http_next_body_filter(r, in);
    }                                           

    if ( in == NULL && ctx->in == NULL ) {
        return ngx_http_next_body_filter(r, in);
    }

    if ( -1 == ctx->saved_page_size ) {
        /* read from upstream */

        /* add the incoming chain to the chain ctx->in */
        if ( in ) {
            if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
                return NGX_ERROR;                                     
            }                                                         
        }

        ctx->page_size = ctx->page_size > 0 ? ctx->page_size : 0;
        for (cl = in; cl; cl = cl->next) {
            ctx->page_size += ngx_buf_size(cl->buf);
            if ( !cl->buf->last_buf )
                ctx->buffered |= NGX_HTTP_STYLECOMBINE_BUFFERED;
            else {
                ctx->buffered &= ~NGX_HTTP_STYLECOMBINE_BUFFERED;
            }
        }

        if ( ctx->buffered & NGX_HTTP_STYLECOMBINE_BUFFERED ) {
            return NGX_AGAIN;
        }

        if (ctx->page == NULL) {
#ifndef __SC_NEW_VERSION
            /*
             * FIXME: we add 100 to solve the page tail has error words issue 
             */ 
            ctx->page = ngx_pcalloc(r->pool, ctx->page_size + 100);
#else
            ctx->page = ngx_palloc(r->pool, ctx->page_size);
#endif
            if (ctx->page == NULL) {
                return NGX_ERROR;
            }

            ctx->last = ctx->page;
        }

        p = ctx->last;

        for (cl = ctx->in; cl; cl = cl->next) {

            b = cl->buf;
            size = ngx_buf_size(b);

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

    } else {
        /* read from local */

        if (ctx->page == NULL) {
#ifndef __SC_NEW_VERSION
            /* 
             * FIXME: we add 100 to solve the page tail has error words issue
             */
            ctx->page = ngx_pcalloc(r->pool, ctx->page_size + 100);
#else
            ctx->page = ngx_palloc(r->pool, ctx->page_size);
#endif
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
        ctx->buffered |= NGX_HTTP_STYLECOMBINE_BUFFERED;

        return NGX_AGAIN;
    }

    /* should never come to here */
    return NGX_ERROR;
}

static void                                               
ngx_http_stylecombine_length(ngx_http_request_t *r, ngx_buf_t *b)
{   
    r->headers_out.content_length_n = b->last - b->pos;   
            
    if (r->headers_out.content_length) {                  
        r->headers_out.content_length->hash = 0;          
    }                     
                                                   
    r->headers_out.content_length = NULL;
}                                       

static void
ngx_http_stylecombine_combine_style(ngx_http_request_t *r, ngx_buf_t *b,
            Buffer *combinedStyleBuf[3], LinkedList *blockList) 
{
	ListNode      *node = NULL;
	ngx_int_t     i=0, totalLen = 0;
    size_t        offsetLen = 0, rest, size;
    ngx_http_stylecombine_ctx_t  *ctx;                                      
                                                                       
    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module);  

	if(NULL == blockList || NULL == combinedStyleBuf || NULL == ctx) {
		return;
	}

    /* calculate buf size */
    for ( node = blockList->first; NULL != node; node = node->next ) {
        ContentBlock *block = (ContentBlock *) node->value;
        if( block->cntBlock ) 
            totalLen += block->cntBlock->used;
        else {
#ifndef __SC_NEW_VERSION
            totalLen += block->eIndex + 1 - block->bIndex;
#else
            totalLen += block->eIndex - block->bIndex;
#endif
        }
    }
    for ( i = 0; i < 3; i++ ) {
        if ( combinedStyleBuf[i] )
            totalLen += combinedStyleBuf[i]->used;
    }

    b->pos = ngx_palloc(r->pool, totalLen);
    if ( NULL == b->pos )
        return;
    b->last = b->pos;

	//按照顺序输出内容
	for(node = blockList->first; NULL != node; node = node->next) {
		ContentBlock *block = (ContentBlock *) node->value;
		if(NULL != block->cntBlock) {
            rest = totalLen - (b->last - b->pos);
            size = (block->cntBlock->used < rest) ? block->cntBlock->used : rest;
            b->last = ngx_cpymem(b->last, block->cntBlock->ptr, size);
			continue;
		}
#ifndef __SC_NEW_VERSION
		if(0 != block->bIndex || 0 != block->eIndex) {
			offsetLen = block->eIndex + 1 - block->bIndex;
            rest = totalLen - (b->last - b->pos);
            size = (offsetLen < rest) ? offsetLen : rest;
            b->last = ngx_cpymem(b->last, ctx->page + block->bIndex, size);
		}
#else
        else if ( block->bIndex >= 0 && block->eIndex > block->bIndex ) {
			offsetLen = block->eIndex - block->bIndex;
            rest = totalLen - (b->last - b->pos);
            size = (offsetLen < rest) ? offsetLen : rest;
            b->last = ngx_cpymem(b->last, ctx->page + block->bIndex, size);
		} else {
            /* should not come to here */
            continue;
        }
#endif

		Buffer *combinedUriBuf = NULL;
		switch(block->tagNameEnum) {
		case SC_BHEAD:
			combinedUriBuf = combinedStyleBuf[SC_TOP];
			combinedStyleBuf[SC_TOP] = NULL;
			break;
		case SC_EHEAD:
			combinedUriBuf = combinedStyleBuf[SC_HEAD];
			combinedStyleBuf[SC_HEAD] = NULL;
			break;
		case SC_EBODY:
			combinedUriBuf = combinedStyleBuf[SC_FOOTER];
			combinedStyleBuf[SC_FOOTER] = NULL;
			break;
		default:
			break;
		}

		if(NULL != combinedUriBuf) {
            rest = totalLen - (b->last - b->pos);
            size = (combinedUriBuf->used < rest) ? combinedUriBuf->used : rest;
            b->last = ngx_cpymem(b->last, combinedUriBuf->ptr, size);
		}
	}
}

static ngx_buf_t *
ngx_http_stylecombine_process(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_stylecombine_ctx_t   *ctx;
    ngx_http_stylecombine_conf_t  *conf;
    ngx_buf_t *b;

    ParamConfig     *paramConfig;
    LinkedList      *blockList;
    Buffer *combinedStyleBuf[3] = {NULL, NULL, NULL};
    Buffer page_buffer = {NULL, 0, 0};

    ctx = ngx_http_get_module_ctx(r, ngx_http_stylecombine_filter_module);
    if ( ctx == NULL )
        return  NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_stylecombine_filter_module);

    /* create stylecombine block list */
    blockList = linked_list_create(r->pool);
    if ( NULL == blockList )
        return NULL;

    /* init ParamConfig */
    paramConfig  = (ParamConfig *) sc_pcalloc(r->pool, sizeof(ParamConfig));
    if ( NULL == paramConfig )
        return NULL;
    paramConfig->pool = r->pool;
    paramConfig->unparsed_uri = (char *)r->unparsed_uri.data;

    paramConfig->debugMode = ctx->debugMode;
    paramConfig->styleParserTags = conf->styleParserTags;
    paramConfig->pConfig = conf->sc_global_config.pConfig;
    paramConfig->globalVariable = &conf->sc_global_config;

    /* init entire page buffer */
    page_buffer.ptr = (char *)ctx->page;
    page_buffer.size = page_buffer.used = ctx->page_size;

#ifndef __SC_NEW_VERSION 
    /* call stylecombine html parser, combinedStyleBuf return combined style */
    rc = sc_html_parser(paramConfig, &page_buffer, combinedStyleBuf, blockList);
#else
    rc = sc_core(paramConfig, &page_buffer, combinedStyleBuf, blockList);
#endif

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {                            
        return NULL;                            
    }                                           
    
    b->memory = 1;  
    b->last_buf = 1;

    if (rc == 0 ) {
        /* no combined style return, nothing need to do */
        b->pos = ctx->page;
        b->last = ctx->page + ctx->page_size;
        ngx_http_stylecombine_length(r, b);
        return b;
    }

    ngx_http_stylecombine_combine_style(r, b, combinedStyleBuf, blockList);
    if ( !b->pos )
        return NULL;
    ngx_http_stylecombine_length(r, b);
    return b;
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
