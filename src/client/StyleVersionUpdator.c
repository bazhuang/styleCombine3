/*
 * StyleVersionUpdator.c
 *
 *  Created on: Jul 18, 2013
 *      Author: zhiwenmizw
 *      Author: dongming.jidm
 *      Author: Bryton Lee
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
#include <signal.h>

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_file_info.h"
#include "apr_file_io.h"

#include "sc_conjoin.h"
#include "sc_log.h"
#include "sc_buffer.h"
#include "sc_socket.h"
#include "sc_string.h"

#define WGET_CMD                            "wget -S -t 1 -T 5 "
#define LAST_MODIFIED_NAME                  "Last-Modified: "
#define MODIFIED_SINCE_HEADER               "\"--header=If-Modified-Since:"
#define GZIP_CMD                            "tar -zxf "
#define USAGE                               STYLE_COMBINE_VS" PARA DESC SEE:\n \
    \n ($1=http://xxxx/styleVersion.gz)  styleVersion url is required \
    \n ($2=/home/admin/output)           styleVersion file director is required \
    \n ($3=180)                          intervalSeconds default 180sec \
    \n ($4=0/1)                          is AMD open\
    \n ($5=0/1)                          daemon mode [Off|On] \
    \n ($6=0/1)                          debug Enable for dev enviroment.\n"

/* global varibales */
static int WGET_CMD_LEN                     = 0;
static int MODIFIED_SINCE_HEADER_LEN        = 0;
static int GZIP_CMD_LEN                     = 0;
static char *wday[]                         = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
static int serverSocketFd = -1;

typedef struct  {
    //from input
    int      openAmd;
    int      intervalSecond;
    int      port;
    Buffer  *versionURL;
    Buffer  *configFileDir;
    Buffer  *lockRequestHead;
    Buffer  *lockRequestUrl;

    //auto maked
    Buffer  *gzipFilePath;
    Buffer  *expStyleFilePath;
    Buffer  *expAmdFilePath;
    Buffer  *reponseFilePath;
    Buffer  *tempFilePath;

    time_t   styleModifiedTime;
    time_t   amdModifiedTime;
    
    int      runasdaemon;
    short    debug;
} style_updator_config;

static style_updator_config   *gConfig     = NULL;
static Buffer   *gUnzipCmd   = NULL;
static Buffer   *gWgetParams = NULL;
static apr_hash_t *styleVersionTable    = NULL;
static apr_hash_t *amdVersionTable    = NULL;
static apr_pool_t *oldStylePool   = NULL;
static apr_pool_t *oldAmdPool   = NULL;

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

static int checkLockStatus(/*apr_pool_t *pool,*/ style_updator_config *config){

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


static int parseLockUrl(apr_pool_t *pool, char *lockURL, style_updator_config *config){

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

    lockURL  = lockURL + strlen("http://");
    paramURL = strchr(lockURL, '/');

    if(NULL == paramURL){
        return 0;
    }

    //Get port number
    char *port = strchr(lockURL, ':');
    if(NULL != port){
        portLen = paramURL - port -1;
        strncpy(portStr, port +1, portLen);
        config->port = atoi(portStr);
        ipLen = port - lockURL;
    }else{
        ipLen = paramURL - lockURL;
        config->port = 80;
    }

    ipAddress = buffer_init_size(pool, ipLen + 1);
    string_append(pool, ipAddress, lockURL, ipLen);
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

static int argsParser(apr_pool_t *pool, int count, char *args[])
{
    int ret = -1, i;
    apr_finfo_t  finfo;

    if(count < 3) {
        sc_log_error("USAGE:%s\n", USAGE);
        return ret;
    }

    gConfig = (style_updator_config *) apr_palloc(pool, sizeof(style_updator_config));
    gConfig->intervalSecond = 120;
    gConfig->openAmd = 1;
    gConfig->runasdaemon = 0;
    gConfig->styleModifiedTime = 0;
    gConfig->amdModifiedTime = 0;
    
    //下载版本文件的URL
    Buffer *versionURLBuf = buffer_init_size(pool, 100);
    put_value_to_buffer(versionURLBuf,  args[1]);
    gConfig->versionURL = versionURLBuf;

    // 锁接口的URL
    // dongming.jidm add
    char *lockUrl = args[1];

    if(!parseLockUrl(pool, lockUrl, gConfig)){
        sc_log_error("lock url is wrong\n");
        return ret;
    };

    //文件目录
    Buffer *configFileDir = buffer_init_size(pool, 100);
    put_value_to_buffer(configFileDir, args[2]);
    SC_PATH_SLASH(configFileDir);
    gConfig->configFileDir = configFileDir;
    buffer_debug(gConfig->configFileDir, "configFileDir");

    if(APR_SUCCESS != apr_stat(&finfo, configFileDir->ptr, APR_FINFO_MIN, pool)) {
        if ( mkdir_recursive(configFileDir->ptr) == -1 )  {
            sc_log_error("Can not create director: %s\n", configFileDir->ptr);
            return ret;
        }
    }

    if ( count > 3 ) {
        gConfig->intervalSecond = atoi(args[3]);
    }
    if ( count > 4 ) {
        gConfig->openAmd = atoi(args[4]);
    }
    if ( count > 5 ) {
        gConfig->runasdaemon = atoi(args[5]);
    }
    if ( count > 6 ) {
        gConfig->debug = atoi(args[6]);
    }

    for(i = 0; i < count; i++) {
        sc_log_debug(LOG_DEBUG, "param %d == %s\n", i, args[i]);
    }

    //下载的文件路径
    gConfig->gzipFilePath = buffer_init_size(pool, configFileDir->used + 17);
    SC_STRING_APPEND_BUFFER(pool, gConfig->gzipFilePath, configFileDir);
    string_append(pool, gConfig->gzipFilePath, "styleVersion.tar.gz", 19);
    buffer_debug(gConfig->gzipFilePath, "gzipFilePath");

    //减压后的文件路径
    // style version file path
    gConfig->expStyleFilePath = buffer_init_size(pool, configFileDir->used + 14);
    SC_STRING_APPEND_BUFFER(pool, gConfig->expStyleFilePath, configFileDir);
    string_append(pool, gConfig->expStyleFilePath, "styleVersion", 12);
    buffer_debug(gConfig->expStyleFilePath, "expStyleFilePath");

    // amd version file path
    if (gConfig->openAmd) {
        gConfig->expAmdFilePath = buffer_init_size(pool, configFileDir->used + 12);
        SC_STRING_APPEND_BUFFER(pool, gConfig->expAmdFilePath, configFileDir);
        string_append(pool, gConfig->expAmdFilePath, "amdVersion", 10);
        buffer_debug(gConfig->expAmdFilePath, "expAmdFilePath");
    }

    //请求响应的日志路径
    gConfig->reponseFilePath = buffer_init_size(pool, configFileDir->used + 14);
    SC_STRING_APPEND_BUFFER(pool, gConfig->reponseFilePath, configFileDir);
    string_append(pool, gConfig->reponseFilePath, "response.log", 12);
    buffer_debug(gConfig->reponseFilePath, "reponseFilePath");

    //style下载时用于临时保存的文件名
    gConfig->tempFilePath = buffer_init_size(pool, gConfig->gzipFilePath->used + 6);
    SC_STRING_APPEND_BUFFER(pool, gConfig->tempFilePath, gConfig->gzipFilePath);
    string_append(pool, gConfig->tempFilePath, "_temp", 5);
    buffer_debug(gConfig->tempFilePath, "tempFilePath");
    
    return 0;
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

    Buffer *unzipCmd = buffer_init_size(pool, 20 + config->gzipFilePath->used + config->configFileDir->used);

    string_append(pool, unzipCmd, GZIP_CMD, GZIP_CMD_LEN);
    SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->gzipFilePath);
    string_append(pool, unzipCmd, " -C ", 4);
    SC_STRING_APPEND_BUFFER(pool, unzipCmd, config->configFileDir);
    buffer_debug(unzipCmd, "unzipCmd");

    sc_log_debug(LOG_DEBUG, "unzipCmd is %s", unzipCmd->ptr);

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

        char *key = apr_palloc(pool, nameLen + 1);
        memcpy(key, name, nameLen);
        key[nameLen] = ZERO_END;

        apr_hash_set(htable, key, nameLen, vbuf);
        strLine = NULL;
        ++count;
    }
    return count;
}

static void data_handler(/*apr_pool_t *pool,*/ Buffer *resultBuf, int socketFd) {

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

    char styleModifyTimeCnt[20];
    char amdModifyTimeCnt[20];
    memset(styleModifyTimeCnt, 0, sizeof(styleModifyTimeCnt));
    memset(amdModifyTimeCnt, 0, sizeof(amdModifyTimeCnt));

    switch(headInfo.protocol) {

        case ERROR_PROTOCAL:
            write_data(socketFd, ERROR_PROTOCAL, NULL, 0);
            break;
        case STYLE_UPDATOR_CHECK:
            apr_snprintf(styleModifyTimeCnt, 20, "%ld", gConfig->styleModifiedTime);
            write_data(socketFd, STYLE_UPDATOR_CHECK, styleModifyTimeCnt, strlen(styleModifyTimeCnt));
            break;
        case AMD_UPDATOR_CHECK:
            apr_snprintf(amdModifyTimeCnt, 20, "%ld", gConfig->amdModifiedTime);
            write_data(socketFd, STYLE_UPDATOR_CHECK, amdModifyTimeCnt, strlen(amdModifyTimeCnt));
            break;
        case STYLE_VERSION_GET:
            if(NULL == styleVersionTable) {
                write_data(socketFd, STYLE_VERSION_GET, NULL, 0);
                return;
            }
            Buffer *style_version = (Buffer *) apr_hash_get(styleVersionTable, data->ptr, data->used);
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
            Buffer *amd_version = (Buffer *) apr_hash_get(amdVersionTable, data->ptr, data->used);
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

static int create_socket_server(apr_pool_t *pool){
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
    omask = umask(0111);

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
        data_handler(/*pool, */dataBuf, clientSocketFd);
        SC_BUFFER_CLEAN(dataBuf);
        close(clientSocketFd);
    }
    SC_BUFF_FREE(dataBuf);
    return 1;
}

static int style_version_build(apr_pool_t *gPool, apr_pool_t *pool, style_updator_config *gConfig) {
    sc_log_debug(LOG_DEBUG, "version_build startting");
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

    char *styleVersionCnt       = read_file_content(pool, gConfig->expStyleFilePath);

    //创建一块新的内存池来容纳版本文件信息
    apr_pool_t *newStylePool = NULL;
    apr_pool_create(&newStylePool, gPool);
    if(NULL == newStylePool) {
        return -1;
    }

    //创建一个新的hash表存放新的版本，将htable指向新的table,释放老的table
    apr_hash_t *newStyletable  = apr_hash_make(newStylePool);
    int styleCount              = file_content_parser(newStylePool, newStyletable, styleVersionCnt);
    styleVersionTable      = newStyletable;

    if(NULL != oldStylePool) {
        apr_pool_destroy(oldStylePool);
    }
    oldStylePool                = newStylePool;

    gConfig->styleModifiedTime  = style_finfo.mtime;

    sc_log_debug(LOG_DEBUG, "buildStyleVersion finnished totalSize=%d", styleCount);

    return 0;
}

int amd_version_build(apr_pool_t *gPool, apr_pool_t *pool, style_updator_config *gConfig) {
    sc_log_debug(LOG_DEBUG, "amd_version_build startting");
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

    char *amdVersionCnt       = read_file_content(pool, gConfig->expAmdFilePath);

    apr_pool_t *newAmdPool = NULL;
    apr_pool_create(&newAmdPool, gPool);
    if(NULL == newAmdPool) {
        return -1;
    }

    apr_hash_t *newAmdtable  = apr_hash_make(newAmdPool);
    int amdCount              = file_content_parser(newAmdPool, newAmdtable, amdVersionCnt);
    amdVersionTable      = newAmdtable;

    if(NULL != oldAmdPool) {
        apr_pool_destroy(oldAmdPool);
    }
    oldAmdPool                = newAmdPool;

    gConfig->amdModifiedTime  = amd_finfo.mtime;

    sc_log_debug(LOG_DEBUG, "buildAmdVersion finnished totalSize=%d", amdCount);

    return 0;
}

static int version_build(apr_pool_t *gPool, apr_pool_t *pool, style_updator_config *gConfig) {
    style_version_build(gPool, pool, gConfig);

    if(gConfig->openAmd) {
        amd_version_build(gPool, pool, gConfig);
    }

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

        // dongming.jidm add
        char *responseCnt = read_file_content(pool, gConfig->reponseFilePath);
        int httpStatusCode = get_http_status_code(responseCnt);

        // ignore the lock checke for the first version file request
        if(0 != httpStatusCode && 404 != httpStatusCode) {
            int bLocked = checkLockStatus(/*pool,*/ gConfig);
            if(bLocked){
                sc_log_debug(LOG_DEBUG, "be locked!");
                sleep(gConfig->intervalSecond);
                continue;
            } else {
                sc_log_debug(LOG_DEBUG, "not be locked!");
            }
        }

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
        sc_log_debug(LOG_DEBUG, "file_validate_and_unCompress retCode %d\n", retCode);

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

static int style_client_daemon()
{
    int  fd;

    switch (fork()) {
    case -1:
        sc_log_error("fork() failed");
        return -1;
   
    case 0:
        break;
       
    default:
        exit(0);
    }

    if (setsid() == -1) {
        sc_log_error("setsid() failed");
        return -1;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        sc_log_error("open(\"/dev/null\") failed");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
         sc_log_error("dup2(STDIN) failed");
         return -1;
     }
 
     if (dup2(fd, STDOUT_FILENO) == -1) {
         sc_log_error("dup2(STDOUT) failed");
         return -1;
     }
 
     if (dup2(fd, STDERR_FILENO) == -1) {
         sc_log_error("dup2(STDERR) failed");
         return -1;
     }
 
     if (fd > STDERR_FILENO) {
         if (close(fd) == -1) {
             sc_log_error("close() failed");
             return -1;
         }
     }
 
     return 0;
}

void style_client_sig_int(int signum)
{
    if ( signum == SIGINT) {
        if (serverSocketFd != -1) {
            close(serverSocketFd);
        }
        exit(0);
    }else {
        exit(-1);
    }
}

int main(int argc, char *argv[])
{
    pthread_t threads[2];
    apr_pool_t *gPool = NULL;
    int ret = -1;

    apr_pool_initialize();
    apr_pool_create(&gPool, NULL);

    if (ret == argsParser(gPool, argc, argv))
        return ret;

    init(gPool, gConfig);

    if (gConfig->runasdaemon != 1) {
        signal(SIGPIPE, SIG_IGN);

        ret = pthread_create(&threads[0], NULL, (void *) interval_work, (void *) gPool);
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
    } else {
        /* run as daemon */
        signal(SIGINT, style_client_sig_int);
        if ( -1 == style_client_daemon() ) {
            sc_log_error("run as daemon failed!\n");
            exit(1);
        }
        
        ret = pthread_create(&threads[0], NULL, (void *) interval_work, (void *) gPool);
        if(ret != 0) {
            sc_log_error("create thread0 error");
            exit(1);
        }
        ret = pthread_create(&threads[1], NULL, (void *) create_socket_server, (void *) gPool);
        if(ret != 0) {
            sc_log_error("create thread1 error");
            exit(1);
        }
        pthread_join(threads[0], NULL);
        pthread_join(threads[1], NULL);
    }
    return 0;
}
