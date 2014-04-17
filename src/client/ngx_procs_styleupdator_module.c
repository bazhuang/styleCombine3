#include <string.h>
#include <pthread.h>
#include <ngx_event.h>
#include <ngx_channel.h>
#include <ngx_http.h>
#include <ngx_proc.h>
#include "style_updator.h"

typedef struct {
	ngx_str_t	url;
	ngx_str_t	path;
	ngx_int_t	internal;
	ngx_flag_t	amd;
	ngx_flag_t	debug;
	ngx_socket_t fd;
} ngx_proc_styleupdator_conf_t;

static void * ngx_procs_styleupdator_create_proc_conf(ngx_conf_t *cf);
static char * ngx_procs_styleupdator_merge_proc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_procs_styleupdator_prev_start(ngx_cycle_t *cycle);
static ngx_int_t ngx_procs_styleupdator_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_procs_styleupdator_loop_proc(ngx_cycle_t *cycle);
static void ngx_procs_styleupdator_exit(ngx_cycle_t *cycle);
static void style_version_updator(sc_pool_t *pool);

static ngx_command_t ngx_procs_styleupdator_commands[] = {
	{	ngx_string("style_updator_url"),
		NGX_PROC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_PROC_CONF_OFFSET,
		offsetof(ngx_proc_styleupdator_conf_t, url),
		NULL },
	{	ngx_string("style_updator_path"),
		NGX_PROC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_PROC_CONF_OFFSET,
		offsetof(ngx_proc_styleupdator_conf_t, path),
		NULL },
	{	ngx_string("style_updator_internal"),
		NGX_PROC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_PROC_CONF_OFFSET,
		offsetof(ngx_proc_styleupdator_conf_t, internal),
		NULL },
	{	ngx_string("style_updator_amd"),
		NGX_PROC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_PROC_CONF_OFFSET,
		offsetof(ngx_proc_styleupdator_conf_t, amd),
		NULL },
	{	ngx_string("style_updator_debug"),
		NGX_PROC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_PROC_CONF_OFFSET,
		offsetof(ngx_proc_styleupdator_conf_t, debug),
		NULL },

	ngx_null_command
};

static ngx_proc_module_t ngx_proc_styleupdator_module_ctx = {
	ngx_string("styleupdator"),
	NULL,
	NULL,
	ngx_procs_styleupdator_create_proc_conf,      /* create procs conf */
	ngx_procs_styleupdator_merge_proc_conf,       /* merge procs conf */
	ngx_procs_styleupdator_prev_start,            /* prevstart */
	ngx_procs_styleupdator_init_process,          /* process init */
	ngx_procs_styleupdator_loop_proc,             /* process loop proc */
	ngx_procs_styleupdator_exit                   /* process exit */
};

ngx_module_t ngx_proc_styleupdator_module = {
	NGX_MODULE_V1,
	&ngx_proc_styleupdator_module_ctx,
	ngx_procs_styleupdator_commands,
	NGX_PROC_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

static void *
ngx_procs_styleupdator_create_proc_conf(ngx_conf_t *cf)
{
	ngx_proc_styleupdator_conf_t	*pstyle_updator_cf;

	pstyle_updator_cf = ngx_pcalloc(cf->pool, sizeof(ngx_proc_styleupdator_conf_t));
	if ( NULL == pstyle_updator_cf ) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"[style updator] create proc conf error");
		return NULL;
	}

	ngx_str_null(&pstyle_updator_cf->url);
	ngx_str_null(&pstyle_updator_cf->path);
	pstyle_updator_cf->internal = NGX_CONF_UNSET;
	pstyle_updator_cf->amd = NGX_CONF_UNSET;
	pstyle_updator_cf->debug = NGX_CONF_UNSET;

	return pstyle_updator_cf;
}

static char * ngx_procs_styleupdator_merge_proc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_proc_styleupdator_conf_t    *prev = parent;
	ngx_proc_styleupdator_conf_t    *conf = child;

	ngx_conf_merge_str_value(conf->url, prev->url, NULL);
	if ( !conf->url.data ) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"[style updator] style_updator_url is NULL");
		return NGX_CONF_ERROR;
	}
	ngx_conf_merge_str_value(conf->path, prev->path, NULL);
	if ( !conf->path.data ) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"[style updator] style_updator_path is NULL");
		return NGX_CONF_ERROR;
	}
	ngx_conf_merge_value(conf->internal, prev->internal, 120);
	ngx_conf_merge_off_value(conf->amd, prev->amd, 0);
	ngx_conf_merge_off_value(conf->debug, prev->debug, 0);

	gConfig = (style_updator_config *) ngx_pcalloc(cf->pool, sizeof(style_updator_config));
	if ( NULL == gConfig ) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"[style updator] create proc conf error");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_procs_styleupdator_prev_start(ngx_cycle_t *cycle)
{
	ngx_proc_styleupdator_conf_t	*pstyle_updator_cf;
	ngx_file_info_t  fi;
	Buffer *version_url = NULL, *style_path_dir = NULL;

	pstyle_updator_cf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_styleupdator_module);

	if ( NULL == pstyle_updator_cf->url.data || 
			NULL == pstyle_updator_cf->path.data ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
				"[style updator] configure ERROR: url: %s, path: %s", 
				NULL == pstyle_updator_cf->url.data ? "NULL" : (char *)pstyle_updator_cf->url.data,
				NULL == pstyle_updator_cf->path.data ? "NULL" : (char *)pstyle_updator_cf->path.data);

		return NGX_DECLINED;
	}

	gConfig->intervalSecond = pstyle_updator_cf->internal;
	gConfig->openAmd = pstyle_updator_cf->amd;
	gConfig->debug = pstyle_updator_cf->debug;
	gConfig->runasdaemon = 0;
	gConfig->styleModifiedTime = 0;
	gConfig->amdModifiedTime = 0;

	version_url = buffer_init_size(cycle->pool, 1024);
	if ( NULL == version_url ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] URL memory alloc failed");
		return NGX_DECLINED;
	}
	string_append(cycle->pool, version_url, (char *)pstyle_updator_cf->url.data,
			strlen((const char *)pstyle_updator_cf->url.data));
	gConfig->versionURL = version_url;

	if ( !parseLockUrl(cycle->pool, (char *)pstyle_updator_cf->url.data, gConfig) ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] lock url is wrong");
		return NGX_DECLINED;
	}

	style_path_dir = buffer_init_size(cycle->pool, 1024);
	if ( NULL == style_path_dir ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] PATH memory alloc failed");
		return NGX_DECLINED;
	}
	string_append(cycle->pool, style_path_dir, (char *)pstyle_updator_cf->path.data,
			strlen((const char *)pstyle_updator_cf->path.data));
	SC_PATH_SLASH(cycle->pool, style_path_dir);
	gConfig->configFileDir = style_path_dir;
	
	if ( ngx_file_info((const char *)style_path_dir->ptr, &fi) == NGX_FILE_ERROR ) {
		if ( mkdir_recursive(style_path_dir->ptr) == -1 ) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] can not create director: %s",
					style_path_dir->ptr);
			return NGX_DECLINED;
		}
	}

	gConfig->gzipFilePath = buffer_init_size(cycle->pool, style_path_dir->used +
			STYLEVERSION_COMPRESS_LEN);
	if ( !gConfig->gzipFilePath ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] gzipFilePath memory alloc failed");
		return NGX_DECLINED;
	}
	SC_STRING_APPEND_BUFFER(cycle->pool, gConfig->gzipFilePath, style_path_dir);
	string_append(cycle->pool, gConfig->gzipFilePath, STYLEVERSION_COMPRESS, STYLEVERSION_COMPRESS_LEN);

	gConfig->expStyleFilePath = buffer_init_size(cycle->pool, style_path_dir->used + STYLEVERSION_LEN);
	if ( !gConfig->expStyleFilePath ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] expStyleFilePath memory alloc failed");
		return NGX_DECLINED;
	}
	SC_STRING_APPEND_BUFFER(cycle->pool, gConfig->expStyleFilePath, style_path_dir);
	string_append(cycle->pool, gConfig->expStyleFilePath, STYLEVERSION, STYLEVERSION_LEN);

	if ( gConfig->openAmd ) {
		gConfig->expAmdFilePath = buffer_init_size(cycle->pool, style_path_dir->used + AMD_VERSION_LEN);
		if ( !gConfig->expAmdFilePath ) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] expAmdFilePath memory alloc failed");
		}
		 SC_STRING_APPEND_BUFFER(cycle->pool, gConfig->expAmdFilePath, style_path_dir);
		 string_append(cycle->pool, gConfig->expAmdFilePath, AMD_VERSION, AMD_VERSION_LEN);
	}

	gConfig->responseFilePath = buffer_init_size(cycle->pool, style_path_dir->used + RESPONSE_PATH_LEN);
	if ( !gConfig->responseFilePath ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] responseFilePath memory alloc failed");
	}
	SC_STRING_APPEND_BUFFER(cycle->pool, gConfig->responseFilePath, style_path_dir);
	string_append(cycle->pool, gConfig->responseFilePath, RESPONSE_PATH, RESPONSE_PATH_LEN);
	remove(gConfig->responseFilePath->ptr);

	gConfig->tempFilePath = buffer_init_size(cycle->pool, gConfig->gzipFilePath->used + TEMP_FILE_LEN);
	if ( !gConfig->tempFilePath ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] tempFilePath memory alloc failed");
	}
	SC_STRING_APPEND_BUFFER(cycle->pool, gConfig->tempFilePath, gConfig->gzipFilePath);
	string_append(cycle->pool, gConfig->tempFilePath, TEMP_FILE, TEMP_FILE_LEN);

	gUnzipCmd = getUnzipCmd(cycle->pool, gConfig);
	if ( !gUnzipCmd ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] gUnzipCmd memory alloc failed");
		return NGX_DECLINED;
	}
	gWgetParams = getWgetParams(cycle->pool, gConfig);
	if ( !gWgetParams ) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "[style updator] gWgetParams memory alloc failed");
		return NGX_DECLINED;
	}

	return NGX_OK;
}

static void
ngx_proc_styleupdator_accept(ngx_event_t *ev)
{
	struct sockaddr_un		sa;
	socklen_t				socklen;
	ngx_socket_t			s;
	ngx_connection_t		*lc;
	Buffer					dataBuf;

	if ( !ev )
		return;

	socklen = sizeof(struct sockaddr_un);
	lc = ev->data;

	s = accept(lc->fd, (struct sockaddr *)&sa, &socklen);
	if ( s == -1 ) {
		ngx_log_error(NGX_LOG_EMERG, ev->log, 0, "[style updator] socket accept failed %s", strerror(errno));
		return;
	}

	dataBuf.used = 0;
	dataBuf.size = ngx_align(300, sizeof(void *));
	/* Note: why use malloc? 
	 * because data_handler() used malloc(), free() 
	 * I have no choose unless change data_handler()
	 */
	dataBuf.ptr = malloc(dataBuf.size);
	if ( !dataBuf.ptr ) {
		ngx_log_error(NGX_LOG_EMERG, ev->log, 0, "[style updator] memory alloc failed");
		return;
	}
	memset(dataBuf.ptr, '\0', dataBuf.size);

	data_handler(&dataBuf, s);

	free(dataBuf.ptr);
	ngx_close_socket(s);
}

static void style_version_updator(sc_pool_t *pool)
{
	char	*responseCnt = NULL;
	int		httpStatusCode, bLocked;
	Buffer	*lastModifiedTime = NULL;
	Buffer	*wgetCmd = NULL;
	sc_pool_t	*sub_pool = NULL;
	int			ret;

	lastModifiedTime = buffer_init_size(pool, 40);
	if ( !lastModifiedTime ) {
		ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "[style updator] lastModifiedTime memory alloc failed");
		return;
	}

	while ( 1 ) {
		ret = sc_pool_create(&sub_pool, pool);
		if ( ret == -1 || !sub_pool ) {
			ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "[style updator] create sub pool failed");
			return;
		}

		responseCnt = read_file_content(sub_pool, gConfig->responseFilePath);
		if ( responseCnt ) {
			httpStatusCode = get_http_status_code(responseCnt);
			if ( httpStatusCode != 404 ) {
				bLocked = checkLockStatus(gConfig);
				if ( bLocked ) {
					ngx_log_error(NGX_LOG_DEBUG, sub_pool->log, 0, "[style updator] style version is locked");
					ngx_sleep(gConfig->intervalSecond);
					continue;
				}
			}
			get_last_modified(lastModifiedTime, responseCnt);
		}

		/*
		 * FIXME: why 100 ?? */
		wgetCmd = buffer_init_size(sub_pool, gWgetParams->used + 100);
		if ( !wgetCmd ) {
			ngx_log_error(NGX_LOG_DEBUG, sub_pool->log, 0, "[style updator] wgetCmd memory alloc failed");
			ngx_sleep(gConfig->intervalSecond);
			continue;
		}
		string_append(sub_pool, wgetCmd, WGET_CMD, WGET_CMD_LEN);
		if ( 0 != lastModifiedTime->used ) {
			string_append(sub_pool, wgetCmd, MODIFIED_SINCE_HEADER, MODIFIED_SINCE_HEADER_LEN);
			SC_STRING_APPEND_BUFFER(sub_pool, wgetCmd, lastModifiedTime);
			string_append(sub_pool, wgetCmd, "\" ", 2);
		}
		SC_STRING_APPEND_BUFFER(sub_pool, wgetCmd, gWgetParams);
		if ( -1 == execute_cmd(wgetCmd->ptr) ) {
			ngx_log_error(NGX_LOG_ERR, sub_pool->log, 0, "[style updator] wget command execute failed, %s",
					wgetCmd->ptr);
			ngx_sleep(gConfig->intervalSecond);
			continue;
		}
		responseCnt = read_file_content(sub_pool, gConfig->responseFilePath);
		if ( !responseCnt ) {
			ngx_log_error(NGX_LOG_ERR, sub_pool->log, 0, "[style updator] read %s failed",
					gConfig->responseFilePath->ptr);
			ngx_sleep(gConfig->intervalSecond);
			continue;
		}
		ret = file_validate_and_unCompress(gConfig, responseCnt);
		if ( -1 == ret ) {
			ngx_log_error(NGX_LOG_ERR, sub_pool->log, 0, "[style updator] uncompress %s failed",
					gConfig->gzipFilePath->ptr);
			ngx_sleep(gConfig->intervalSecond);
			continue;
		} 

		version_build(pool, sub_pool, gConfig);
		sc_pool_destroy(sub_pool);
		ngx_sleep(gConfig->intervalSecond);
	}

}

static ngx_int_t
ngx_procs_styleupdator_loop_proc(ngx_cycle_t *cycle)
{
	ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "daytime %V",
			&ngx_cached_http_time);
	return NGX_OK;
}

static ngx_int_t
ngx_procs_styleupdator_init_process(ngx_cycle_t *cycle)
{
	int                       reuseaddr;
	mode_t                    omask;
	ngx_event_t              *rev;
	ngx_socket_t              fd;
	ngx_connection_t         *c;
	struct sockaddr_un        sin;
	ngx_proc_styleupdator_conf_t  *pbcf;

	ngx_pool_t	*pool;
	pthread_t	updator_thread;
	int			ret = -1;

	pbcf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_styleupdator_module);

	unlink(SC_SOCKET_FILE_NAME); 
	fd = ngx_socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] socket error");
		return NGX_ERROR;
	}

	reuseaddr = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				(const void *) &reuseaddr, sizeof(int))
			== -1)
	{
		ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
				"[style updator] setsockopt(SO_REUSEADDR) failed");

		ngx_close_socket(fd);
		return NGX_ERROR;
	}
	if (ngx_nonblocking(fd) == -1) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
				"[style updator] nonblocking failed");

		ngx_close_socket(fd);
		return NGX_ERROR;
	}

	sin.sun_family = AF_UNIX;
	strcpy(sin.sun_path, SC_SOCKET_FILE_NAME);
	omask = umask(0111);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] bind error");
		umask(omask);
		return NGX_ERROR;
	}
	umask(omask);
	if (listen(fd, 20) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] listen error");
		return NGX_ERROR;
	}

	c = ngx_get_connection(fd, cycle->log);
	if (c == NULL) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] no connection");
		return NGX_ERROR;
	}

	c->log = cycle->log;
	rev = c->read;
	rev->log = c->log;
	rev->accept = 1;
	rev->handler = ngx_proc_styleupdator_accept;

	if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
		return NGX_ERROR;
	}

	pbcf->fd = fd;

	pool = ngx_create_pool(1024, cycle->log);
	if ( !pool ) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] ngx_create_pool failed");
		return NGX_ERROR;
	}
	ret = pthread_create(&updator_thread, NULL, (void *)style_version_updator, (void *)pool);
	if ( ret != 0 ) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[style updator] pthread_create failed");
		return NGX_ERROR;
	}

	return NGX_OK;
}

static void
ngx_procs_styleupdator_exit(ngx_cycle_t *cycle)
{
	ngx_proc_styleupdator_conf_t *pbcf;
	pbcf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_styleupdator_module);

	ngx_close_socket(pbcf->fd);
}
