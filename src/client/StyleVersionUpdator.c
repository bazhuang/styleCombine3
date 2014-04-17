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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>

#include "apr_pools.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "style_updator.h"

#define USAGE                   STYLE_COMBINE_VS" PARA DESC SEE:\n \
    \n ($1=http://xxxx/styleVersion.gz)  styleVersion url is required \
    \n ($2=/home/admin/output)           styleVersion file director is required \
    \n ($3=180)                          intervalSeconds default 180sec \
    \n ($4=0/1)                          is AMD open\
    \n ($5=0/1)                          daemon mode [Off|On] \
    \n ($6=0/1)                          debug Enable for dev enviroment.\n"

static int serverSocketFd = -1;

void sc_log_core(int logLevelMask, const char *fmt, va_list args)
{
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
			(1900 + p->tm_year), (1 + p->tm_mon),
			p->tm_mday, wday[p->tm_wday],
			p->tm_hour, p->tm_min, p->tm_sec,
			logLevelString, buf);
}

void sc_log_error(const char *fmt, ...)
{
	SC_LOG_PIC(LOG_ERR);
}

void sc_log_debug(int currentLogLevel, const char *fmt, ...)
{
	if(((1 == gConfig->debug) ? LOG_DEBUG : 0) == currentLogLevel) {
		SC_LOG_PIC(LOG_DEBUG);
	}
}

static void buffer_debug(Buffer *buf, char *name)
{
	if(NULL == buf) {
		sc_log_debug(LOG_DEBUG, "%s : is NULL \n", name);
		return;
	}
	sc_log_debug(LOG_DEBUG, "%s:[%s] USED:[%ld]==strlen[%d] SIZE[%ld]\n",
			name, buf->ptr, buf->used, strlen(buf->ptr), buf->size);
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
    SC_PATH_SLASH(pool, configFileDir);
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
    gConfig->responseFilePath = buffer_init_size(pool, configFileDir->used + 14);
    SC_STRING_APPEND_BUFFER(pool, gConfig->responseFilePath, configFileDir);
    string_append(pool, gConfig->responseFilePath, "response.log", 12);
    buffer_debug(gConfig->responseFilePath, "responseFilePath");

    //style下载时用于临时保存的文件名
    gConfig->tempFilePath = buffer_init_size(pool, gConfig->gzipFilePath->used + 6);
    SC_STRING_APPEND_BUFFER(pool, gConfig->tempFilePath, gConfig->gzipFilePath);
    string_append(pool, gConfig->tempFilePath, "_temp", 5);
    buffer_debug(gConfig->tempFilePath, "tempFilePath");
    
    gUnzipCmd   = getUnzipCmd(pool, gConfig);
    gWgetParams = getWgetParams(pool, gConfig);

    return 0;
}

static int create_socket_server(apr_pool_t *pool)
{
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
        data_handler(dataBuf, clientSocketFd);
        SC_BUFFER_CLEAN(dataBuf);
        close(clientSocketFd);
    }
    SC_BUFF_FREE(dataBuf);
    return 1;
}


static void interval_work(apr_pool_t *pPool)
{
    if(gConfig->debug) {
        sc_log_error("StyleVersionUpdator startting");
    }
    //删除response.log文件
    remove(gConfig->responseFilePath->ptr);

    Buffer *lastModifiedTime = buffer_init_size(pPool, 40);

    while(1) {

        apr_pool_t *pool = NULL;

        apr_pool_create(&pool, pPool);

        // dongming.jidm add
        char *responseCnt = read_file_content(pool, gConfig->responseFilePath);
        int httpStatusCode = get_http_status_code(responseCnt);

        // ignore the lock check for the first version file request
        if(0 != httpStatusCode && 404 != httpStatusCode) {
            int bLocked = checkLockStatus(gConfig);
            if(bLocked){
                sc_log_debug(LOG_DEBUG, "be locked!");
                sleep(gConfig->intervalSecond);
                continue;
            } else {
                sc_log_debug(LOG_DEBUG, "not be locked!");
            }
        }

        get_last_modified(lastModifiedTime, responseCnt);
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

		responseCnt = read_file_content(pool, gConfig->responseFilePath);
        int retCode = file_validate_and_unCompress(gConfig, responseCnt);
        sc_log_debug(LOG_DEBUG, "file_validate_and_unCompress retCode %d\n", retCode);

        version_build(pPool, pool, gConfig);
        //free pool
        apr_pool_destroy(pool);

        sleep(gConfig->intervalSecond);
    }
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
