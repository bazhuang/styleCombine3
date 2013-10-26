/**
 * zhiwen.mizw@alibaba-inc.com
 * 2013-04-20
 *
 * compile
 * apxs -ic mod_styleCombine.c
 */

#include "sc_common.h"
#include "sc_config.h"
#include "sc_log.h"
#include "sc_mod_filter.h"
#include "sc_version.h"
#include "sc_html_parser.h"

#include "httpd.h"
#include "apr_buckets.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "http_request.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_lib.h"

module AP_MODULE_DECLARE_DATA                styleCombine_module;

#define IS_LOG_ENABLED(logLevelMask) (logLevelMask == globalVariable.pConfig->printLog)

static server_rec       *server;

static GlobalVariable    globalVariable;
static StyleParserTag   *styleParserTags[2] = { NULL, NULL };

void sc_log_core(int logLevelMask, const char *fmt, va_list args) {
	char buf[SC_MAX_STRING_LEN];
	apr_vsnprintf(buf, SC_MAX_STRING_LEN, fmt, args);
	ap_log_error(APLOG_MARK, logLevelMask, 0, server, "%s", buf);
}

void sc_log_error(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	sc_log_core(APLOG_ERR, fmt, args);
	va_end(args);
}

void sc_log_debug(int currentLogLevel, const char *fmt, ...) {
	int logLevelMask = APLOG_DEBUG;
	if(APLOG_DEBUG != server->loglevel) {
		if((NULL != globalVariable.pConfig) && globalVariable.pConfig->printLog != currentLogLevel) {
			return;
		}
		logLevelMask = APLOG_ERR;
	}
	va_list args;
	va_start(args, fmt);
	sc_log_core(logLevelMask, fmt, args);
	va_end(args);
}

typedef struct {
	short                 isHTML;
	short                 debugMode;
	Buffer               *buf;
	apr_bucket_brigade   *pbbOut;
	struct timeval        btime, etime;
} CombineCtx;

static void apr_bucket_nothing_free(void *mem) {
}

static apr_status_t styleCombine_ctx_cleanup(void *data) {
    CombineCtx *ctx = (CombineCtx *) data;
    if (ctx) {
    	SC_BUFF_FREE(ctx->buf);
    	ctx->buf = NULL;
    }
    return APR_SUCCESS;
}

/**
 * 创建一个输出的bucket，用于输出每一段内容；
 * 但内容本身是放在一块内存里，通过不同的坐标进行分段输出。在释放内存时也只需要释放这块地址就行了。
 * 而这里的“apr_bucket_nothing_free” 是为了减少apache帮助我做内存释放，因为一块内存空间会被free多次。
 * 另外如果将“apr_bucket_nothing_free” 设置为NULL也是可行的，但增加了一次memcpy。因为apache会创建一块新内存来存放这个数据，可这些操作都是不需要的。
 * 所以使用一个空方法来绕开这个问题。
 */
static int addBucket(conn_rec *c, apr_bucket_brigade *pbbkOut, char *str, int strLen) {
	if(NULL == str || strLen <= 0) {
		return 0;
	}
	apr_bucket *pbktOut = NULL;
	pbktOut = apr_bucket_heap_create(str, strLen, apr_bucket_nothing_free, c->bucket_alloc);
	if(NULL != pbktOut) {
		APR_BRIGADE_INSERT_TAIL(pbbkOut, pbktOut);
		return strLen;
	}
	return 0;
}

static int put_data_to_bucket(request_rec *req, LinkedList *blockList, Buffer *combinedStyleBuf[3], CombineCtx *ctx) {
	ListNode      *node = NULL;
	int            offsetLen = 0;
	int            totalLen = 0;
	if(NULL == blockList || NULL == combinedStyleBuf || NULL == ctx) {
		return totalLen;
	}
	//按照顺序输出内容
	for(node = blockList->first; NULL != node; node = node->next) {
		ContentBlock *block = (ContentBlock *) node->value;
		if(NULL != block->cntBlock) {
			//用于调度打印输出内容和坐标
			if(IS_LOG_ENABLED(LOG_PRINT_DATA)) {
				sc_log_debug(LOG_PRINT_DATA, "bIndex[%d] eIndex[%d]  str[%s]", block->bIndex, block->eIndex, block->cntBlock->ptr);
			}
			totalLen += addBucket(req->connection, ctx->pbbOut, block->cntBlock->ptr, block->cntBlock->used);
			continue;
		}

		Buffer *combinedUriBuf       = NULL;
		switch(block->tagNameEnum) {
		case SC_BHEAD:
			combinedUriBuf           = combinedStyleBuf[SC_TOP];
			combinedStyleBuf[SC_TOP]    = NULL;
			break;
		case SC_EHEAD:
			combinedUriBuf           = combinedStyleBuf[SC_HEAD];
			combinedStyleBuf[SC_HEAD]   = NULL;
			break;
		case SC_EBODY:
			combinedUriBuf           = combinedStyleBuf[SC_FOOTER];
			combinedStyleBuf[SC_FOOTER] = NULL;
			break;
		default:
			break;
		}

		if(0 != block->bIndex || 0 != block->eIndex) {
			offsetLen                = block->eIndex + 1 - block->bIndex;
			totalLen += addBucket(req->connection, ctx->pbbOut, ctx->buf->ptr + block->bIndex, offsetLen);
		}

		if(NULL != combinedUriBuf) {
			totalLen += addBucket(req->connection, ctx->pbbOut, combinedUriBuf->ptr, combinedUriBuf->used);
		}

		//用于调度打印输出内容和坐标
		if(IS_LOG_ENABLED(LOG_PRINT_DATA)) {
			if(0 != block->bIndex || 0 != block->eIndex) {
				char *buf = apr_pstrmemdup(req->pool, ctx->buf->ptr + block->bIndex, offsetLen);
				sc_log_debug(LOG_PRINT_DATA, "bIndex[%d] eIndex[%d]  str[%s]", block->bIndex, block->eIndex, buf);
			}

			if(NULL != combinedUriBuf) {
				sc_log_debug(LOG_PRINT_DATA, "combinedURI [%s]", combinedUriBuf->ptr);
			}
		}
	}
	return totalLen;
}

static void *configServerCreate(sc_pool_t *p, server_rec *s) {

	CombineConfig *pConfig = sc_palloc(p, sizeof(CombineConfig));
	if(NULL == pConfig) {
		return NULL;
	}

	global_variable_init(p, pConfig, &globalVariable);

	combine_config_init(p, pConfig);

	if(NULL == style_tag_init(p, styleParserTags)) {
		return NULL;
	}

	return pConfig;
}

static void styleCombineInsert(request_rec *r) {
	CombineConfig *pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);
	if(!pConfig->enabled) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "not support styleCombineModule!");
		return;
	}
	ap_add_output_filter(STYLE_COMBINE_NAME, NULL, r, r->connection);
	return;
}

static apr_status_t styleCombineOutputFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
	request_rec *r      = f->r;
	conn_rec    *c      = r->connection;
	CombineCtx  *ctx    = f->ctx;
	server = r->server;

	if (APR_BRIGADE_EMPTY(pbbIn)) {
		return APR_SUCCESS;
	}

	CombineConfig *pConfig = NULL;
	pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);
	if(NULL == pConfig) {
		return ap_pass_brigade(f->next, pbbIn);
	}

	if(!ap_is_HTTP_SUCCESS(r->status)) {
		sc_log_debug(LOG_UNPROCESSED, "=url[%s] the httpstatus value[%d]", r->uri, r->status);
		return ap_pass_brigade(f->next, pbbIn);
	}

	const char * encode = apr_table_get(r->headers_out, "Content-Encoding");
	if(encode && 0 == strcasecmp(encode, "gzip")) {
		sc_log_debug(LOG_UNPROCESSED, "=uri[%s] the Content-Encoding is gzip value[%s]", r->uri, encode);
		return ap_pass_brigade(f->next, pbbIn);
	}

	if(NULL != apr_table_get(r->notes, STYLE_COMBINE_NAME)) {
		sc_log_debug(LOG_UNPROCESSED, "===styleCombined the note is ok");
		return ap_pass_brigade(f->next, pbbIn);
	}

	char *contentType = apr_pstrdup(r->pool, r->content_type);
	if(0 == is_allowed_contentType(contentType, pConfig->filterCntType)){
		sc_log_debug(LOG_UNPROCESSED, "===uri[%s] content-type not match filter[%s] value [%s]",
				r->uri, pConfig->filterCntType, r->content_type);
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 1add runMode
	 * 添加模块的动态开关，由版本文件内容来控制
	 */
	if(NULL != globalVariable.modRunMode && 0 == memcmp(globalVariable.modRunMode, RUN_MODE_STATUS_WITH_LEN)) {
		checkVersionUpdate(r->server->process->pool, r->pool, &globalVariable);
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 2 black & white list
	 */
	if(is_filter_uri(r->uri, pConfig->blackList, pConfig->whiteList)) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 3add debugMode
	 * 本次请求禁用此模块，用于开发调试使用
	 */
	short  debugMode = 0;
	if((debugMode = is_param_disabled_mod(r->parsed_uri.query))) {
		return ap_pass_brigade(f->next, pbbIn);
	}

	if (NULL == ctx) {
		ctx = f->ctx = sc_palloc(r->pool, sizeof(*ctx));
		if(NULL == ctx) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		if(LOG_TIME_COSTED == pConfig->printLog) {
			gettimeofday(&ctx->btime, NULL);
		}
		ctx->pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
		if(NULL == ctx->pbbOut) {
			return ap_pass_brigade(f->next, pbbIn);
		}

		ctx->buf = (Buffer *) malloc(sizeof(Buffer));
		ctx->buf->ptr  = NULL;
		ctx->buf->used = 0;
		ctx->buf->size = DEFAULT_CONTENT_LEN;

		char *contentLengthStr = (char *) apr_table_get(r->headers_out, "Content-Length");
		if(NULL != contentLengthStr) {
			ctx->buf->size = apr_atoi64(contentLengthStr);
		}
		ctx->buf->size    = SC_ALIGN_DEFAULT(ctx->buf->size);
		ctx->buf->ptr     = (char *) malloc(ctx->buf->size);

		if(NULL == ctx->buf) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		//注册释放内存的回调函数
		apr_pool_cleanup_register(r->pool, ctx, styleCombine_ctx_cleanup, apr_pool_cleanup_null);

		ctx->isHTML = 0;
		apr_table_unset(r->headers_out, "Content-Length");
		apr_table_unset(r->headers_out, "Content-MD5");
		//set debugMode value
		ctx->debugMode = (short) debugMode;
        checkVersionUpdate(r->server->process->pool, r->pool, &globalVariable);
	}

	//FIXME:保留trunked传输方式,（未实现）
	apr_bucket *pbktIn = NULL;
	for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
	            							pbktIn = APR_BUCKET_NEXT(pbktIn)) {
		if(APR_BUCKET_IS_EOS(pbktIn)) {
			int totoalLen = 0;
			Buffer *combinedStyleBuf[3] = {NULL, NULL, NULL};
			LinkedList *blockList = linked_list_create(r->pool);

			ParamConfig *paramConfig  = (ParamConfig *) sc_palloc(r->pool, sizeof(ParamConfig));
			paramConfig->pool      = r->pool;
			paramConfig->debugMode = debugMode;
			paramConfig->pConfig   = pConfig;
			paramConfig->styleParserTags = styleParserTags;
			paramConfig->globalVariable  = &globalVariable;

			int styleCount = html_parser(paramConfig, ctx->buf, combinedStyleBuf, blockList, r->unparsed_uri);
			if(0 == styleCount) {
				//FIXME: 没有找到任何的style，则直接保持原来的数据输出，不需要做任何变化（未实现，需要保留原backet列表）
				totoalLen = addBucket(r->connection, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
			} else {
				totoalLen = put_data_to_bucket(r, blockList, combinedStyleBuf, ctx);
			}
			//append EOS
			APR_BUCKET_REMOVE(pbktIn);
			APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, pbktIn);
			apr_table_setn(r->notes, STYLE_COMBINE_NAME, "ok");

			if(IS_LOG_ENABLED(LOG_TIME_COSTED)) {
				gettimeofday(&ctx->etime, NULL);
				long usedtime = 1000000 * ( ctx->etime.tv_sec - ctx->btime.tv_sec ) + ctx->etime.tv_usec - ctx->btime.tv_usec;
				sc_log_debug(LOG_TIME_COSTED, "uri[%s] pid[%d] styleCount[%d] recSize[%d] sendSize[%d] costTime[%ld micro_sec][%ld mill_sec]",
						r->uri, getpid(), styleCount, ctx->buf->used, totoalLen, usedtime, usedtime/1000);
			}

			return ap_pass_brigade(f->next, ctx->pbbOut);
		}
		const char *data;
		apr_size_t  len;
		apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);

		if(!ctx->isHTML && NULL != data) {
			// 如果返回内容中没有以<号打头，就表示不是一个html语言，所以不进行处理。空格换行除外
			if(0 == sc_is_html_data(data)) {
				apr_table_setn(r->notes, STYLE_COMBINE_NAME, "ok");
				return ap_pass_brigade(f->next, pbbIn);
			}
			ctx->isHTML    = 1;
		}

		string_append_content(ctx->buf, (char *) data, len);
		apr_bucket_delete(pbktIn);
	}
	return OK;
}

static ap_regex_t * patternValidate(cmd_parms *cmd, const char *arg) {
	if(NULL == arg) {
		return NULL;
	}
	ap_regex_t *regexp;
	char *str = apr_pstrdup(cmd->pool, arg);
	char *pattern = NULL;
	parseargline(str, &pattern);
	regexp = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
	return regexp;
}

static const char *setEnabled(cmd_parms *cmd, void *dummy, int arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	pConfig->enabled = (short) arg;
	return NULL;
}

static const char *setFilterCntType(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine filterCntType value may not be null.";
	} else {
		pConfig->filterCntType = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

static const char *setAppName(cmd_parms *cmd, void *dummy, const char *arg) {
	int appNameLen = 0;
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (appNameLen = strlen(arg)) <= 1) {
		return "styleCombine appName can't be null OR empty";
	} else {
		pConfig->appName = buffer_init_size(cmd->pool, appNameLen);
		string_append(cmd->pool, pConfig->appName, (char *) arg, appNameLen);
	}
	return NULL;
}

static const char *setOldDomains(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine old domain value may not be null";
	} else {
		string_split(cmd->pool, pConfig->oldDomains, DOMAINS_COUNT, apr_pstrdup(cmd->pool, arg), ";");
	}
	return NULL;
}

static const char *setNewDomains(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		string_split(cmd->pool, pConfig->newDomains, DOMAINS_COUNT, apr_pstrdup(cmd->pool, arg), ";");
	}
	return NULL;
}

static const char *setAsyncVariableNames(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) < 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		string_split(cmd->pool, pConfig->asyncVariableNames, DOMAINS_COUNT, apr_pstrdup(cmd->pool, arg), ";");
	}
	return NULL;
}

static const char *setMaxUrlLen(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	int len = 0;
	if ((NULL == arg) || (len = atoi(arg)) < 1) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, cmd->server, "maxUrlLen too small, will set default  2083!");
	} else {
		pConfig->maxUrlLen = len;
	}
	return NULL;
}

static const char *setPrintLog(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if(NULL != arg) {
		pConfig->printLog = atoi(arg);
	}
	return NULL;
}

static const char *setBlackList(cmd_parms *cmd, void *in_dconf, const char *arg) {
	ap_regex_t *regexp = patternValidate(cmd, arg);
	if (!regexp) {
		return apr_pstrcat(cmd->pool, "blankList: cannot compile regular expression '", arg, "'", NULL);
	}
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	add(cmd->pool, pConfig->blackList, regexp);
	return NULL;
}

static const char *setWhiteList(cmd_parms *cmd, void *in_dconf, const char *arg) {
	ap_regex_t *regexp = patternValidate(cmd, arg);
	if (!regexp) {
		return apr_pstrcat(cmd->pool, "whiteList: cannot compile regular expression '", arg, "'", NULL);
	}
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	add(cmd->pool, pConfig->whiteList, regexp);
	return NULL;
}

static const command_rec styleCombineCmds[] =
{
		AP_INIT_FLAG("SC_Enabled", setEnabled, NULL, OR_ALL, "open or close this module"),

		AP_INIT_TAKE1("SC_AppName", setAppName, NULL, OR_ALL, "app name"),

		AP_INIT_TAKE1("SC_FilterCntType", setFilterCntType, NULL, OR_ALL, "filter content type"),

		AP_INIT_TAKE1("SC_OldDomains", setOldDomains, NULL, OR_ALL, "style old domain url"),

		AP_INIT_TAKE1("SC_NewDomains", setNewDomains, NULL, OR_ALL, "style new domain url"),

		AP_INIT_TAKE1("SC_AsyncVariableNames", setAsyncVariableNames, NULL, OR_ALL, "the name for asynStyle of variable"),

		AP_INIT_TAKE1("SC_MaxUrlLen", setMaxUrlLen, NULL, OR_ALL, "url max len default is IE6 length support"),

		AP_INIT_TAKE1("SC_PrintLog", setPrintLog, NULL, OR_ALL, " set SC_PrintLog level"),

		AP_INIT_RAW_ARGS("SC_BlackList", setBlackList, NULL, OR_ALL, "SC_BlackList uri"),

		AP_INIT_RAW_ARGS("SC_WhiteList", setWhiteList, NULL, OR_ALL, "SC_WhiteList uri"),

		{ NULL }
};

static int configRequired(server_rec *s, char *name, void * value) {
	if(NULL == value) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "mod_styleCombine config [%s] value can't be null or empty", name);
		return 1;
	}
	return 0;
}

static apr_status_t styleCombine_post_conf(sc_pool_t *p, sc_pool_t *plog, sc_pool_t *tmp, server_rec *s) {
	CombineConfig *pConfig = ap_get_module_config(s->module_config, &styleCombine_module);
	if(NULL == pConfig || 0 == pConfig->enabled) {
		return OK;
	}
	ap_add_version_component(p, MODULE_BRAND);
	int resultCount = 0;

	resultCount += configRequired(s, "SC_Pconfig", pConfig);
	if(resultCount) {
		return !OK;
	}
	resultCount += configRequired(s, "SC_AppName", pConfig->appName->ptr);

	int i = 0, domainCount = 0;
	for(i = 0; i < DOMAINS_COUNT; i++) {
		if(NULL == pConfig->newDomains[i] && NULL == pConfig->oldDomains[i]) {
			continue;
		}
		SC_PATH_SLASH(pConfig->newDomains[i]);
		SC_PATH_SLASH(pConfig->oldDomains[i]);
		if(pConfig->newDomains[i] && pConfig->oldDomains[i]) {
			++domainCount;
			continue;
		}
		resultCount += configRequired(s, "SC_NewDomains", pConfig->newDomains[i]);
		resultCount += configRequired(s, "SC_OldDomains", pConfig->oldDomains[i]);
	}
	for(i = 0; i < domainCount; i++) {
		resultCount += configRequired(s, "SC_AsyncVariableNames", pConfig->asyncVariableNames[i]);
	}
	if(resultCount) {
		return !OK;
	}
	return OK;
}

static void styleCombine_register_hooks(sc_pool_t *p) {
	ap_hook_post_config(styleCombine_post_conf, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_insert_filter(styleCombineInsert, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(STYLE_COMBINE_NAME, styleCombineOutputFilter, NULL, AP_FTYPE_RESOURCE);
    return;
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA styleCombine_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                  /* create per-dir    config structures */
	NULL,                  /* merge  per-dir    config structures */
	configServerCreate,    /* create per-server config structures */
	NULL,                  /* merge  per-server config structures */
	styleCombineCmds,      /* table of config file commands       */
	styleCombine_register_hooks  /* register hooks                */
};
