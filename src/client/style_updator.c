#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#if defined(SC_HTTPD_PLATFORM)
#include "apr_file_info.h"
#include "apr_file_io.h"
#elif defined(SC_NGINX_PLATFORM)
#include "ngx_config.h"
#include "ngx_core.h"
#endif

#include "style_updator.h"

char *wday[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
style_updator_config   *gConfig = NULL;
Buffer   *gUnzipCmd = NULL;
Buffer   *gWgetParams = NULL;
sc_hash_t *styleVersionTable = NULL;
sc_hash_t *amdVersionTable = NULL;
sc_pool_t *oldStylePool = NULL;
sc_pool_t *oldAmdPool = NULL;

int mkdir_recursive(char *dir)
{
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

int checkLockStatus(style_updator_config *config)
{

	int locked = 0;
	int sockfd;
	struct sockaddr_in address;
	char buf[2048];
	int ret;
	struct hostent *host;
	// 连接接口失败时的重连次数
	int reConnectTimes = 3;
	int connectedSuccess = 0;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		sc_log_error("create socket failed in check lock url!\n");
		return 0;
	};

	bzero(&address, sizeof(address));

	if((host = gethostbyname(config->lockRequestUrl->ptr)) == NULL) {
		sc_log_error("get host by name failed!");
		return 0;
	}

	address.sin_addr = *((struct in_addr *)host->h_addr_list[0]);
	const char *hostip = inet_ntoa(address.sin_addr);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(hostip);
	address.sin_port = htons(config->port);

	int result = connect(sockfd,  (struct sockaddr *)&address, sizeof(address));

	if(-1 == result){
		//重连3次
		while(reConnectTimes) {
			result = connect(sockfd,  (struct sockaddr *)&address, sizeof(address));

			if(-1 == result) {
				sleep(1);
				reConnectTimes--;
			} else {
				connectedSuccess = 1;
				break;
			}
		}

	} else {
		connectedSuccess = 1;
	}

	if (!connectedSuccess) {
		sc_log_error("connect to lock url failed!\n");
		close(sockfd);
		return 0;
	}

	ret = write(sockfd, config->lockRequestHead->ptr, strlen(config->lockRequestHead->ptr));

	if (ret < 0) {
		sc_log_error("request to lock url is not responsed!\n");
		close(sockfd);
		return 0;
	}

	int size=read(sockfd, buf, 1024-1);

	if(size > 0){
		char *bSuccess = strstr(buf, "\"success\":true");
		char *bLocked  = strstr(buf, "\"is_lock\":\"true\"");
		if(bSuccess && bLocked){
			locked = 1;
		}
	} else {
		sc_log_error("read lock url data failed!\n");
	}
	close(sockfd);
	return locked;
}

int parseLockUrl(sc_pool_t *pool, char *lockURL, style_updator_config *config)
{

	char *paramURL = NULL;
	char reqStr[256];
	char portStr[16];
	char param[256];
	int  ipLen;
	int  portLen;
	int  reqLen;

	Buffer *ipAddress = NULL;
	Buffer *lockRequestContent = NULL;

	memset(reqStr, 0, 256);
	memset(portStr, 0, 16);
	memset(param, 0, 256);

	//get app name
	char *appName = strstr(lockURL, "=");

	if (NULL == appName) {
		appName = "=FALSE";
	}

	strcat(param, "/GetAppState?appkey");
	strcat(param, appName);

	//Trim the http://
	char *pStart = strstr(lockURL, "http://");
	if(NULL == pStart){
		return 0;
	}

	//lockURL  = lockURL + strlen("http://");
	pStart = lockURL + strlen("http://");
	paramURL = strchr(pStart, '/');

	if(NULL == paramURL){
		return 0;
	}

	//Get port number
	char *port = strchr(pStart, ':');
	if(NULL != port){
		portLen = paramURL - port -1;
		strncpy(portStr, port +1, portLen);
		config->port = atoi(portStr);
		ipLen = port - pStart;
	}else{
		ipLen = paramURL - pStart;
		config->port = 80;
	}

	ipAddress = buffer_init_size(pool, ipLen + 1);
	string_append(pool, ipAddress, pStart, ipLen);
	config->lockRequestUrl = ipAddress;

	strcat(reqStr, "GET ");
	strcat(reqStr, param);
	strcat(reqStr, " HTTP/1.1\r\n");
	strcat(reqStr, "Host: ");
	strcat(reqStr, ipAddress->ptr);
	strcat(reqStr, "\r\nConnection: Close\r\n\r\n");

	reqLen = strlen(reqStr);
	lockRequestContent = buffer_init_size(pool, reqLen + 1);
	string_append(pool, lockRequestContent, reqStr, reqLen);
	config->lockRequestHead = lockRequestContent;

	return 1;
}

Buffer *getUnzipCmd(sc_pool_t *pool, style_updator_config *config)
{

	Buffer *unzipCmd = buffer_init_size(pool, 20 + config->gzipFilePath->used +
			config->configFileDir->used);
	if ( !unzipCmd ) {
		return NULL;
	}

	string_append(pool, unzipCmd, GZIP_CMD, GZIP_CMD_LEN);
	SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->gzipFilePath);
	string_append(pool, unzipCmd, " -C ", 4);
	SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->configFileDir);

	return unzipCmd;
}

/**
 * 生成wget的参数 如：
 * http://xx/a.gz -O /home/admin/styleVersion.gz_tmp > /home/admin/styleVersion.gz_response.log 2>&1
 */
Buffer *getWgetParams(sc_pool_t *pool, style_updator_config *config)
{

	int size = config->versionURL->used + config->tempFilePath->used + config->responseFilePath->used;
	Buffer *wgetParams = buffer_init_size(pool, size + 50);
	if ( !wgetParams ) {
		return NULL;
	}

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->versionURL);
	string_append(pool, wgetParams, " -O ", 4);

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->tempFilePath);
	string_append(pool, wgetParams, " > ", 3);

	SC_STRING_APPEND_BUFFER(pool, wgetParams, config->responseFilePath);
	string_append(pool, wgetParams, " 2>&1 ", 6);

	return wgetParams;
}

char *read_file_content(sc_pool_t *pool, Buffer *filePath)
{
#if defined(SC_HTTPD_PLATFORM)
	apr_finfo_t  finfo;
	apr_status_t rc = apr_stat(&finfo, filePath->ptr, APR_FINFO_MIN, pool);
	if(APR_SUCCESS != rc) {
		return NULL;
	}
	apr_size_t  size = (apr_size_t) finfo.size;
#elif defined(SC_NGINX_PLATFORM)
	ngx_file_info_t  fi;
	if ( ngx_file_info(filePath->ptr, &fi) == NGX_FILE_ERROR) {
		return NULL;
	}
	if ( !(fi.st_mode & S_IRUSR) ) {
		/* file can not readable */
		return NULL;
	}
	off_t size;
	size = ngx_file_size(&fi);
#else 
	return NULL;
#endif

	char *cntBuf = (char *) sc_pcalloc(pool, size + 1);

#if defined(SC_HTTPD_PLATFORM)
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

#elif defined(SC_NGINX_PLATFORM)
	ngx_fd_t	fd;
	ssize_t     n;

	fd = ngx_open_file(filePath->ptr, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
	if (fd == NGX_INVALID_FILE) {
		sc_log_error("open file path:%s error:%s\n", filePath->ptr, strerror(errno));
		return NULL;
	}
	n = ngx_read_fd(fd, cntBuf, size);
	if (n == -1) {
		sc_log_error("read file path:%s error:%s\n", filePath->ptr, strerror(errno));
	}
	ngx_close_file(fd);

#endif

	if(NULL == cntBuf) {
		sc_log_error("contentBuf is NULL path:%s error:%s\n", filePath->ptr, strerror(errno));
		return NULL;
	}
	return cntBuf;
}

int get_http_status_code(char *responseCnt)
{
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

void get_last_modified(Buffer *lastModifiedBuf, char *responseCnt)
{
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

int execute_cmd(char *cmd)
{
	if(-1 == system(cmd)) {
		sc_log_error("system(%s) error:%s\n", cmd, strerror(errno));
		return -1;
	}

	return 0;
}

int file_validate_and_unCompress(style_updator_config *config, char *responseCnt)
{
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
				return execute_cmd(gUnzipCmd->ptr);
			}
			return -1;
		default:
			return -1;
	}
}

static int
file_content_parser(sc_pool_t *pool, sc_hash_t *htable, char *str)
{
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
			sc_log_error("file_content_parser value error value=[%s],strLine=[%s]", value, strLine);
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

		char *key = sc_palloc(pool, nameLen + 1);
		memcpy(key, name, nameLen);
		key[nameLen] = ZERO_END;

		sc_hash_set(htable, key, nameLen, vbuf);
		strLine = NULL;
		++count;
	}
	return count;
}

static int 
style_version_build(sc_pool_t *gPool, sc_pool_t *pool, style_updator_config *gConfig)
{
	sc_log_debug(LOG_DEBUG, "version_build startting");
#if defined(SC_HTTPD_PLATFORM)
	apr_finfo_t  style_finfo;
	apr_status_t style_rc = apr_stat(&style_finfo, gConfig->expStyleFilePath->ptr, APR_FINFO_MIN, pool);

	if(APR_SUCCESS != style_rc) {
		sc_log_error("stat failed %s\n", gConfig->expStyleFilePath->ptr);
		return -1;
	}
	
	// if modified then reload styleversion
	if(gConfig->styleModifiedTime == style_finfo.mtime) {
		sc_log_debug(LOG_DEBUG, "version_build file not modified");
		return -1;
	}
#elif defined(SC_NGINX_PLATFORM)
	ngx_file_info_t  style_finfo;
	if ( ngx_file_info(gConfig->expStyleFilePath->ptr, &style_finfo) == NGX_FILE_ERROR) {
		return -1;
	}
	if ( !(style_finfo.st_mode & S_IRUSR) ) {
		/* file can not readable */
		return -1;
	}
	
	// if modified then reload styleversion
	if(gConfig->styleModifiedTime == ngx_file_mtime(&style_finfo)) {
		sc_log_debug(LOG_DEBUG, "version_build file not modified");
		return -1;
	}
#else 
	return -1;
#endif


	char *styleVersionCnt = read_file_content(pool, gConfig->expStyleFilePath);

	//创建一块新的内存池来容纳版本文件信息
	sc_pool_t *newStylePool = NULL;
	sc_pool_create(&newStylePool, gPool);
	if(NULL == newStylePool) {
		return -1;
	}

	//创建一个新的hash表存放新的版本，将htable指向新的table,释放老的table
	sc_hash_t *newStyletable = sc_hash_make(newStylePool);
	int styleCount = file_content_parser(newStylePool, newStyletable, styleVersionCnt);
	styleVersionTable = newStyletable;

	if(NULL != oldStylePool) {
		sc_pool_destroy(oldStylePool);
	}
	oldStylePool = newStylePool;

#if defined(SC_HTTPD_PLATFORM)
	gConfig->styleModifiedTime = style_finfo.mtime;
#elif defined(SC_NGINX_PLATFORM)
	gConfig->styleModifiedTime = ngx_file_mtime(&style_finfo);
#endif

	sc_log_debug(LOG_DEBUG, "buildStyleVersion finnished totalSize=%d", styleCount);

	return 0;
}

static int
amd_version_build(sc_pool_t *gPool, sc_pool_t *pool, style_updator_config *gConfig)
{
	sc_log_debug(LOG_DEBUG, "amd_version_build startting");
#if defined(SC_HTTPD_PLATFORM)
	apr_finfo_t  amd_finfo;

	apr_status_t amd_rc = apr_stat(&amd_finfo, gConfig->expAmdFilePath->ptr, APR_FINFO_MIN, pool);

	if(APR_SUCCESS != amd_rc) {
		sc_log_error("stat failed %s\n", gConfig->expAmdFilePath->ptr);
		return -1;
	}
	
	// if modified then reload styleversion
	if(gConfig->amdModifiedTime == amd_finfo.mtime) {
		sc_log_debug(LOG_DEBUG, "amd_version_build file not modified");
		return -1;
	}
#elif defined(SC_NGINX_PLATFORM)
	ngx_file_info_t  amd_finfo;
	if ( ngx_file_info(gConfig->expAmdFilePath->ptr, &amd_finfo) == NGX_FILE_ERROR) {
		return -1;
	}
	if ( !(amd_finfo.st_mode & S_IRUSR) ) {
		/* file can not readable */
		return -1;
	}
	
	// if modified then reload styleversion
	if(gConfig->styleModifiedTime == ngx_file_mtime(&amd_finfo)) {
		sc_log_debug(LOG_DEBUG, "version_build file not modified");
		return -1;
	}
#else
	return -1;
#endif


	char *amdVersionCnt = read_file_content(pool, gConfig->expAmdFilePath);

	sc_pool_t *newAmdPool = NULL;
	sc_pool_create(&newAmdPool, gPool);
	if(NULL == newAmdPool) {
		return -1;
	}

	sc_hash_t *newAmdtable = sc_hash_make(newAmdPool);
	int amdCount = file_content_parser(newAmdPool, newAmdtable, amdVersionCnt);
	amdVersionTable = newAmdtable;

	if(NULL != oldAmdPool) {
		sc_pool_destroy(oldAmdPool);
	}
	oldAmdPool = newAmdPool;

#if defined(SC_HTTPD_PLATFORM)
	gConfig->amdModifiedTime = amd_finfo.mtime;
#elif defined(SC_NGINX_PLATFORM)
	gConfig->amdModifiedTime = ngx_file_mtime(&amd_finfo);
#endif

	sc_log_debug(LOG_DEBUG, "buildAmdVersion finnished totalSize=%d", amdCount);

	return 0;
}


int version_build(sc_pool_t *gPool, sc_pool_t *pool, style_updator_config *gConfig)
{
	style_version_build(gPool, pool, gConfig);

	if(gConfig->openAmd) {
		amd_version_build(gPool, pool, gConfig);
	}

	return 0;
}

void data_handler(Buffer *resultBuf, int socketFd)
{

	HeadInfo                headInfo;
	read_head_info(socketFd, &headInfo);

	if(0 == headInfo.length) {
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		return;
	}

	if(headInfo.length > (long)resultBuf->size) {
		resultBuf->size = SC_ALIGN_DEFAULT(headInfo.length + 1);
		resultBuf->used = 0;
		if(NULL != resultBuf->ptr) {
			free(resultBuf->ptr);
		}
		resultBuf->ptr  = (char *) malloc(resultBuf->size);
	}

	Buffer *data = read_data(socketFd, resultBuf, headInfo.length);

	if(SC_IS_EMPTY_BUFFER(data)) {
		write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
		return;
	}

	char styleModifyTimeCnt[20];
	char amdModifyTimeCnt[20];
	memset(styleModifyTimeCnt, 0, sizeof(styleModifyTimeCnt));
	memset(amdModifyTimeCnt, 0, sizeof(amdModifyTimeCnt));

	switch(headInfo.protocol) {

		case ERROR_PROTOCAL:
			write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
			break;
		case STYLE_UPDATOR_CHECK:
#if defined(SC_HTTPD_PLATFORM)
			apr_snprintf(styleModifyTimeCnt, 20, "%ld", gConfig->styleModifiedTime);
#else
			snprintf(styleModifyTimeCnt, 20, "%ld", gConfig->styleModifiedTime);
#endif
			write_data(socketFd, STYLE_UPDATOR_CHECK, styleModifyTimeCnt, strlen(styleModifyTimeCnt));
			break;
		case AMD_UPDATOR_CHECK:
#if defined(SC_HTTPD_PLATFORM)
			apr_snprintf(amdModifyTimeCnt, 20, "%ld", gConfig->amdModifiedTime);
#else
			snprintf(amdModifyTimeCnt, 20, "%ld", gConfig->amdModifiedTime);
#endif
			write_data(socketFd, STYLE_UPDATOR_CHECK, amdModifyTimeCnt, strlen(amdModifyTimeCnt));
			break;
		case STYLE_VERSION_GET:
			if(NULL == styleVersionTable) {
				write_data(socketFd, STYLE_VERSION_GET, NULL, 0);
				return;
			}
			Buffer *style_version = (Buffer *) sc_hash_get(styleVersionTable, data->ptr, data->used);
			if(SC_IS_EMPTY_BUFFER(style_version)) {
				write_data(socketFd, STYLE_VERSION_GET, NULL, 0);
				return;
			}
			write_data(socketFd, STYLE_VERSION_GET, style_version->ptr, style_version->used);
			break;
		case AMD_VERSION_GET:
			if(NULL == amdVersionTable) {
				write_data(socketFd, AMD_VERSION_GET, NULL, 0);
				return;
			}
			Buffer *amd_version = (Buffer *) sc_hash_get(amdVersionTable, data->ptr, data->used);
			if(SC_IS_EMPTY_BUFFER(amd_version)) {
				write_data(socketFd, AMD_VERSION_GET, NULL, 0);
				return;
			}
			write_data(socketFd, AMD_VERSION_GET, amd_version->ptr, amd_version->used);
			break;
		default:
			write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
			break;
	}
}
