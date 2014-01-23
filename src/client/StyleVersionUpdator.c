/*
 * StyleVersionUpdator.c
 *
 *  Created on: Jul 18, 2013
 *      Author: zhiwenmizw
 *
 *  compile command:
 *
 *	install apr & apr-util
 *
 *  APR_CFG=$(apr-1-config --cflags --cppflags --includes --link-ld)
 *
 *  gcc -Wall StyleVersionUpdator.c -o StyleVersionUpdator $APR_CFG
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_file_info.h"
#include "apr_file_io.h"

#include "sc_log.h"
#include "sc_buffer.h"
#include "sc_socket.h"
#include "sc_string.h"

#define WGET_CMD                            "wget -S -t 1 -T 5 "
#define LAST_MODIFIED_NAME                  "Last-Modified: "
#define MODIFIED_SINCE_HEADER               "\"--header=If-Modified-Since:"
#define GZIP_CMD                            "gzip -cd "
#define USAGE                               STYLE_COMBINE_VS" PARA DESC SEE:\n \
											\n ($1=http://xxxx/styleVersion.gz)  styleVersion url is required \
											\n ($2=/home/admin/output)           styleVersion file director is required \
											\n ($3=180)                          intervalSeconds default 180sec \
											\n ($4=0/1)                          debug Enable for dev enviroment \n"

static int WGET_CMD_LEN                     = 0;
static int MODIFIED_SINCE_HEADER_LEN        = 0;
static int GZIP_CMD_LEN                     = 0;
static char *wday[]                         = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};

typedef struct  {
	//from input
	short    debug;
	int      intervalSecond;
	Buffer  *versionURL;
	Buffer  *configFileDir;
	//auto maked
	Buffer  *gzipFilePath;
	Buffer  *expFilePath;
	Buffer  *reponseFilePath;
	Buffer  *tempFilePath;

	time_t   modifiedTime;
} style_updator_config;

static style_updator_config   *gConfig     = NULL;
static Buffer   *gUnzipCmd   = NULL;
static Buffer   *gWgetParams = NULL;
static apr_hash_t *styleVersionTable    = NULL;
static apr_pool_t *oldPool   = NULL;


void sc_log_core(int logLevelMask, const char *fmt, va_list args) {
	char *logLevelString = "info";
	switch(logLevelMask) {
	case LOG_ERR:
		logLevelString   = "error";
		break;
	case LOG_DEBUG:
		logLevelString   = "debug";
		break;
	default :
		break;
	}

	time_t  currentTime;
	time(&currentTime);
	char    buf[8192];
	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, 8192, fmt, args);
	struct tm *p = localtime(&currentTime);
	fprintf(stderr, "StyleVersionUpdator [%d-%d-%d %s %d:%d:%d][%s]  %s\n",
			(1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday, wday[p->tm_wday], p->tm_hour, p->tm_min, p->tm_sec,
			logLevelString, buf);
}

void sc_log_error(const char *fmt, ...) {
	SC_LOG_PIC(LOG_ERR);
}

void sc_log_debug(int currentLogLevel, const char *fmt, ...) {
	if(((1 == gConfig->debug) ? LOG_DEBUG : 0) == currentLogLevel) {
		SC_LOG_PIC(LOG_DEBUG);
	}
}

static void buffer_debug(Buffer *buf, char *name) {
	if(NULL == buf) {
		sc_log_debug(LOG_DEBUG, "%s : is NULL \n", name);
		return;
	}
	sc_log_debug(LOG_DEBUG, "%s:[%s] USED:[%ld]==strlen[%d] SIZE[%ld]\n", name, buf->ptr, buf->used, strlen(buf->ptr), buf->size);
}

static int mkdir_recursive(char *dir) {
	char *p = dir;
	if (!dir || !dir[0])
		return 0;

	while ((p = strchr(p + 1, '/')) != NULL) {
		*p = '\0';
		if ((mkdir(dir, 0700) != 0) && (errno != EEXIST)) {
			*p = '/';
			return -1;
		}
		*p++ = '/';
		if (!*p) return 0; /* Ignore trailing slash */
	}
	return (mkdir(dir, 0700) != 0) && (errno != EEXIST) ? -1 : 0;
}

static void argsParser(apr_pool_t *pool, int count, char *args[]) {
	if(count < 2) {
		sc_log_error("USAGE:%s\n", USAGE);
		exit(1);
	}

	int i = 0;

	gConfig = (style_updator_config *) apr_palloc(pool, sizeof(style_updator_config));
	gConfig->intervalSecond     = 180;
	if(count > 2) {
		gConfig->intervalSecond = atoi(args[3]);
	}
	if(count > 4) {
		gConfig->debug          = atoi(args[4]);
	}
	for(i = 0; i < count; i++) {
		sc_log_debug(LOG_DEBUG, "param %d == %s\n", i, args[i]);
	}
	//下载版本文件的URL
	Buffer *versionURLBuf = buffer_init_size(pool, 100);
	put_value_to_buffer(versionURLBuf,  args[1]);
	gConfig->versionURL   = versionURLBuf;

	//文件目录
	Buffer *configFileDir       = buffer_init_size(pool, 100);
	put_value_to_buffer(configFileDir, args[2]);
	SC_PATH_SLASH(configFileDir);
	gConfig->configFileDir      = configFileDir;
	buffer_debug(gConfig->configFileDir, "configFileDir");

	gConfig->modifiedTime       = 0;

	apr_finfo_t  finfo;
	if(APR_SUCCESS != apr_stat(&finfo, configFileDir->ptr, APR_FINFO_MIN, pool)) {
		mkdir_recursive(configFileDir->ptr);
		return;
	}

	//下载的文件路径
	gConfig->gzipFilePath     = buffer_init_size(pool, configFileDir->used + 17);
	SC_STRING_APPEND_BUFFER(pool, gConfig->gzipFilePath, configFileDir);
	string_append(pool, gConfig->gzipFilePath, "styleVersion.gz", 15);
	buffer_debug(gConfig->gzipFilePath, "gzipFilePath");

	//减压后的文件路径
	gConfig->expFilePath      = buffer_init_size(pool, configFileDir->used + 14);
	SC_STRING_APPEND_BUFFER(pool, gConfig->expFilePath, configFileDir);
	string_append(pool, gConfig->expFilePath, "styleVersion", 12);
	buffer_debug(gConfig->expFilePath, "expFilePath");

	//请求响应的日志路径
	gConfig->reponseFilePath  = buffer_init_size(pool, configFileDir->used + 14);
	SC_STRING_APPEND_BUFFER(pool, gConfig->reponseFilePath, configFileDir);
	string_append(pool, gConfig->reponseFilePath, "response.log", 12);
	buffer_debug(gConfig->reponseFilePath, "reponseFilePath");

	//style下载时用于临时保存的文件名
	gConfig->tempFilePath     = buffer_init_size(pool, gConfig->gzipFilePath->used + 6);
	SC_STRING_APPEND_BUFFER(pool, gConfig->tempFilePath, gConfig->gzipFilePath);
	string_append(pool, gConfig->tempFilePath, "_temp", 5);
	buffer_debug(gConfig->tempFilePath, "tempFilePath");
}

/**
 * 生成wget的参数 如：
 * http://xx/a.gz -O /home/admin/styleVersion.gz_tmp > /home/admin/styleVersion.gz_response.log 2>&1
 */
static Buffer * getWgetParams(apr_pool_t *pool, style_updator_config *config) {

	int size = config->versionURL->used + config->tempFilePath->used + config->reponseFilePath->used;
	Buffer *wgetParams = buffer_init_size(pool, size + 50);

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->versionURL);
	string_append(pool, wgetParams, " -O ", 4);

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->tempFilePath);
	string_append(pool, wgetParams, " > ", 3);

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->reponseFilePath);
	string_append(pool, wgetParams, " 2>&1 ", 6);

	return wgetParams;
}

static Buffer *getUnzipCmd(apr_pool_t *pool, style_updator_config *config) {

	Buffer *unzipCmd = buffer_init_size(pool, 20 + config->gzipFilePath->used + config->expFilePath->used);

	string_append(pool, unzipCmd, GZIP_CMD, GZIP_CMD_LEN);
	SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->gzipFilePath);
	string_append(pool, unzipCmd, " > ", 3);
	SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->expFilePath);
	buffer_debug(unzipCmd, "unzipCmd");

	return unzipCmd;
}

static int get_http_status_code(char *responseCnt) {
	int httpStatusCode = 304;
	if(NULL == responseCnt) {
		return 404;
	}
	char *respStatus   = strstr(responseCnt, "304 Not Modified");
	if(NULL == respStatus) {
		respStatus = strstr(responseCnt, "200 OK");
		httpStatusCode = (NULL == respStatus) ? 404 : 200;
	}
	return httpStatusCode;
}


static char *read_file_content(apr_pool_t *pool, Buffer *filePath) {
	apr_finfo_t  finfo;
	apr_status_t rc = apr_stat(&finfo, filePath->ptr, APR_FINFO_MIN, pool);
	if(APR_SUCCESS != rc) {
		return NULL;
	}
	apr_size_t  size  = (apr_size_t) finfo.size;
	char *cntBuf = (char *) apr_pcalloc(pool, size + 1);

	apr_file_t *fd = NULL;
	rc = apr_file_open(&fd, filePath->ptr, APR_READ | APR_BINARY | APR_XTHREAD, APR_OS_DEFAULT, pool);
	if (rc != APR_SUCCESS) {
		apr_file_close(fd);
		sc_log_error("open file path:%s error:%s\n", filePath->ptr, strerror(errno));
		return NULL;
	}

	if (APR_SUCCESS != apr_file_read(fd, cntBuf, &size)) {
		sc_log_error("read file error rd:%d == size:%ld %s\n", fd, size, strerror(errno));
	}
	apr_file_close(fd);

	if(NULL == cntBuf) {
		sc_log_error("contentBuf is NULL path:%s error:%s\n", filePath->ptr, strerror(errno));
		return NULL;
	}
	return cntBuf;
}

static void get_last_modified(apr_pool_t *pool, Buffer *lastModifiedBuf, Buffer *reponseFilePath) {

	char *responseCnt = read_file_content(pool, reponseFilePath);
	if(NULL == responseCnt) {
		SC_BUFFER_CLEAN(lastModifiedBuf);
		return;
	}

	if(304 == get_http_status_code(responseCnt)) {
		return;
	}

	SC_BUFFER_CLEAN(lastModifiedBuf);
	char *lastModified = strstr(responseCnt, "Last-Modified: ");
	if(NULL == lastModified) {
		return;
	}
	lastModified += 15;

	for(; (*lastModified != '\n' && lastModifiedBuf->used < lastModifiedBuf->size); ++lastModified) {
		lastModifiedBuf->ptr[lastModifiedBuf->used++] = *lastModified;
	}
	lastModifiedBuf->ptr[lastModifiedBuf->used] = ZERO_END;
}

static int execute_cmd(char *cmd) {
	if(-1 == system(cmd)) {
		sc_log_error("system(%s) error:%s\n", cmd, strerror(errno));
		return -1;
	}
	return 0;
}

static int file_validate_and_unCompress(apr_pool_t *pool, style_updator_config *config) {
	//文件校验
	char *responseCnt = read_file_content(pool, config->reponseFilePath);
	if(NULL == responseCnt) {
		return -1;
	}
	int httpStatusCode = get_http_status_code(responseCnt);
	switch(httpStatusCode) {
	case 304:
		return 304;
	case 200:
		//重命名和减压
		if(-1 != rename(config->tempFilePath->ptr, config->gzipFilePath->ptr)) {
			buffer_debug(gUnzipCmd, "file unzip start");
			return execute_cmd(gUnzipCmd->ptr);
		}
		return -1;
	default:
		return -1;
	}
}

static int file_content_parser(apr_pool_t *pool, apr_hash_t *htable, char *str) {
	if (NULL == str || NULL == htable) {
		return 0;
	}
	int count     = 0;
	char *name    = NULL, *value = NULL;
	int   nameLen =0,   valueLen = 0;
	char *srcStr  = str;
	char *strLine = NULL;
	while (NULL != (strLine = strsep(&srcStr, "\n"))) {
		name = NULL, value = NULL;
		name = strsep(&strLine, "=");
		if (NULL == name || (nameLen = strlen(name)) <= 1) {
			continue;
		}
		value = strLine;
		if (NULL == value || (valueLen = strlen(value)) < 1) {
			sc_log_error("formatParser value error value=[%s],strLine=[%s]", value, strLine);
			continue;
		}
		Buffer *vbuf = buffer_init_size(pool, valueLen);

		//为了与老版本的版本文件做兼容
		if('/' == *name) {
			name++;
			nameLen--;
		}

		sc_log_debug(LOG_DEBUG, "key[%s][%d] = value[%s][%d]", name, nameLen, value, valueLen);

		string_append(pool, vbuf, value, valueLen);

		char *key = apr_palloc(pool, nameLen + 1);
		memcpy(key, name, nameLen);
		key[nameLen] = ZERO_END;

		apr_hash_set(htable, key, nameLen, vbuf);
		strLine = NULL;
		++count;
	}
	return count;
}

static void data_handler(apr_pool_t *pool, Buffer *resultBuf, int socketFd) {

	HeadInfo                headInfo;
	read_head_info(socketFd, &headInfo);

	if(0 == headInfo.length) {
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		return;
	}

	if(headInfo.length > resultBuf->size) {
		resultBuf->size = SC_ALIGN_DEFAULT(headInfo.length + 1);
		resultBuf->used = 0;
		if(NULL != resultBuf->ptr) {
			free(resultBuf->ptr);
		}
		resultBuf->ptr  = (char *) malloc(resultBuf->size);
	}

	Buffer *data     = read_data(socketFd, resultBuf, headInfo.length);

	if(SC_IS_EMPTY_BUFFER(data)) {
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		return;
	}

	char modifyTimeCnt[20];
	memset(modifyTimeCnt, 0, sizeof(modifyTimeCnt));

	switch(headInfo.protocol) {

	case ERROR_PROTOCAL:
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		break;
	case STYLE_UPDATOR_CHECK:
		apr_snprintf(modifyTimeCnt, 20, "%ld", gConfig->modifiedTime);
		write_data(socketFd, STYLE_UPDATOR_CHECK, modifyTimeCnt, strlen(modifyTimeCnt));
		break;
	case STYLE_VERSION_GET:
		if(NULL == styleVersionTable) {
			write_data(socketFd, STYLE_VERSION_GET, NULL, 0);
			return;
		}
		Buffer *version = (Buffer *) apr_hash_get(styleVersionTable, data->ptr, data->used);
		if(SC_IS_EMPTY_BUFFER(version)) {
			write_data(socketFd, STYLE_VERSION_GET, NULL, 0);
			return;
		}
		write_data(socketFd, STYLE_VERSION_GET, version->ptr, version->used);
		break;
	default:
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		break;
	}
}

static int create_socket_server(apr_pool_t *pool){
	int serverSocketFd      = 0;
	struct sockaddr_un      serverAddress;
	mode_t                  omask;
	int rc                  = -1;
	unlink(SC_SOCKET_FILE_NAME);

	if(-1 == (serverSocketFd = socket(AF_UNIX, SOCK_STREAM, 0))) {
		sc_log_error("socket create failed %s", strerror(errno));
		return -1;
	}
	serverAddress.sun_family  = AF_UNIX;
	strcpy(serverAddress.sun_path, SC_SOCKET_FILE_NAME);
	omask = umask(0077);

	rc = bind(serverSocketFd, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
	umask(omask);
	if(rc < 0 ) {
		sc_log_error("socket bind failed %s", strerror(errno));
		return -1;
	}

	if(-1 == listen(serverSocketFd, 20)) {
		sc_log_error("socket listen failed %s", strerror(errno));
		return -1;
	}

	int socketLen    = sizeof(serverAddress);

	Buffer *dataBuf  = (Buffer *) malloc(sizeof(Buffer));
	dataBuf->used    = 0;
	dataBuf->size    = APR_ALIGN_DEFAULT(300);
	dataBuf->ptr     = (char *) malloc(dataBuf->size);

	sc_log_debug(LOG_DEBUG, "ServerSocket is ready");

	while(1) {
		int clientSocketFd = accept(serverSocketFd, (struct sockaddr *) &serverAddress, (socklen_t *) &socketLen);
		sc_log_debug(LOG_DEBUG, "accept client socketfd [%d]", clientSocketFd);
		if(-1 == clientSocketFd) {
			sc_log_error("socket accept failed %s", strerror(errno));
			continue;
		}
		//处理数据
		data_handler(pool, dataBuf, clientSocketFd);
		SC_BUFFER_CLEAN(dataBuf);
		close(clientSocketFd);
	}
	SC_BUFF_FREE(dataBuf);
	return 1;
}

static int version_build(apr_pool_t *gPool, apr_pool_t *pool, style_updator_config *gConfig) {
	sc_log_debug(LOG_DEBUG, "version_build startting");
	apr_finfo_t  finfo;
	apr_status_t rc = apr_stat(&finfo, gConfig->expFilePath->ptr, APR_FINFO_MIN, pool);
	if(APR_SUCCESS != rc) {
		sc_log_error("stat failed %s\n", gConfig->expFilePath->ptr);
		return -1;
	}

	// if modified then reload styleversion
	if(gConfig->modifiedTime == finfo.mtime) {
		sc_log_debug(LOG_DEBUG, "version_build file not modified");
		return 0;
	}

	char *versionCnt       = read_file_content(pool, gConfig->expFilePath);

	//创建一块新的内存池来容纳版本文件信息
	apr_pool_t *newPool = NULL;
	apr_pool_create(&newPool, gPool);
	if(NULL == newPool) {
		return -1;
	}
	//创建一个新的hash表存放新的版本，将htable指向新的table,释放老的table
	apr_hash_t *newHtable  = apr_hash_make(newPool);
	int count              = file_content_parser(newPool, newHtable, versionCnt);
	styleVersionTable      = newHtable;

	if(NULL != oldPool) {
		apr_pool_destroy(oldPool);
	}
	oldPool                = newPool;
	gConfig->modifiedTime  = finfo.mtime;
	sc_log_debug(LOG_DEBUG, "buildVersion finnished totalSize=%d", count);
	return 0;
}

static void interval_work(apr_pool_t *pPool) {
	if(gConfig->debug) {
		sc_log_error("StyleVersionUpdator startting");
	}
	//删除response.log文件
	remove(gConfig->reponseFilePath->ptr);

	Buffer *lastModifiedTime = buffer_init_size(pPool, 40);

	while(1) {

		apr_pool_t         *pool = NULL;

		apr_pool_create(&pool, pPool);

		get_last_modified(pool, lastModifiedTime, gConfig->reponseFilePath);
		buffer_debug(lastModifiedTime, "getLastModified ");

		Buffer *wgetCmd = buffer_init_size(pool, gWgetParams->used + 100);
		string_append(pool, wgetCmd, WGET_CMD, WGET_CMD_LEN);

		if(0 != lastModifiedTime->used) {
			string_append(pool, wgetCmd, MODIFIED_SINCE_HEADER, MODIFIED_SINCE_HEADER_LEN);
			SC_STRING_APPEND_BUFFER(pool, wgetCmd, lastModifiedTime);
			string_append(pool, wgetCmd, "\" ", 2);
		}
		SC_STRING_APPEND_BUFFER(pool, wgetCmd, gWgetParams);
		buffer_debug(wgetCmd, "wget start ");

		if(-1 == execute_cmd(wgetCmd->ptr)) {
			sc_log_error("wget cmd execute faild", wgetCmd->ptr);
		}

		int retCode = file_validate_and_unCompress(pool, gConfig);
		sc_log_debug(LOG_DEBUG, "fileValidAndUnzip retCode %d\n", retCode);

		version_build(pPool, pool, gConfig);
		//free pool
		apr_pool_destroy(pool);

		sleep(gConfig->intervalSecond);
	}
}

static void init(apr_pool_t *pool, style_updator_config *config) {
	WGET_CMD_LEN              = strlen(WGET_CMD);
	MODIFIED_SINCE_HEADER_LEN = strlen(MODIFIED_SINCE_HEADER);
	GZIP_CMD_LEN              = strlen(GZIP_CMD);

	gUnzipCmd   = getUnzipCmd(pool, config);
	gWgetParams = getWgetParams(pool, config);
}

int main(int argc, char *argv[]) {

	apr_pool_initialize();
	apr_pool_t *gPool = NULL;
	apr_pool_create(&gPool, NULL);

	argsParser(gPool, argc, argv);
	init(gPool, gConfig);

	//intervalWork(gPool);

	//createSocketServer(gPool);

	signal(SIGPIPE, SIG_IGN);

	pthread_t threads[2];
	int ret = pthread_create(&threads[0], NULL, (void *) interval_work, (void *) gPool);
	if(ret != 0) {
		sc_log_error("create thread0 error");
		exit(1);
	}
	ret = pthread_create(&threads[1], NULL, (void *) create_socket_server, (void *) gPool);
	if(ret != 0) {
		sc_log_error("create thread1 error");
		exit(1);
	}

	char buf[65536];
	for(;;) {
		int nBytesRead = read(0, buf, sizeof(buf));
		if(nBytesRead == 0) {
			exit(2);
		}
		if(errno == EINTR) {
			continue;
		}
		if(gConfig->debug) {
			sc_log_error("%s", buf);
		}
	}

	apr_pool_destroy(gPool);
	printf("finnished");
	return 0;
}
