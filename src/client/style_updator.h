#ifndef __STYLE_UPDATOR_H
#define __STYLE_UPDATOR_H

#include "sc_conjoin.h"
#include "sc_log.h"
#include "sc_buffer.h"
#include "sc_hash.h"
#include "sc_socket.h"

#define LAST_MODIFIED_NAME                  "Last-Modified: "
#define WGET_CMD                            "wget -S -t 1 -T 5 "
#define MODIFIED_SINCE_HEADER               "\"--header=If-Modified-Since:"
#define GZIP_CMD                            "tar -zxf "
#define WGET_CMD_LEN				strlen(WGET_CMD)
#define MODIFIED_SINCE_HEADER_LEN	strlen(MODIFIED_SINCE_HEADER)
#define GZIP_CMD_LEN				strlen(GZIP_CMD)

#define STYLEVERSION_COMPRESS	"styleVersion.tar.gz"
#define STYLEVERSION_COMPRESS_LEN	(sizeof(STYLEVERSION_COMPRESS) - 1)
#define STYLEVERSION	"styleVersion"
#define	STYLEVERSION_LEN	(sizeof(STYLEVERSION) - 1)
#define AMD_VERSION		"amdVersion"
#define	AMD_VERSION_LEN		(sizeof(AMD_VERSION) -1)
#define RESPONSE_PATH	"response.log"
#define RESPONSE_PATH_LEN	(sizeof(RESPONSE_PATH) - 1)
#define	TEMP_FILE	"_temp"
#define TEMP_FILE_LEN	(sizeof(TEMP_FILE) - 1)

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
	Buffer  *responseFilePath;
	Buffer  *tempFilePath;

	time_t   styleModifiedTime;
	time_t   amdModifiedTime;

	int      runasdaemon;
	short    debug;
} style_updator_config;

extern char					*wday[];
extern style_updator_config   *gConfig;
extern Buffer   *gUnzipCmd;
extern Buffer   *gWgetParams;
extern sc_hash_t *styleVersionTable;
extern sc_hash_t *amdVersionTable;
extern sc_pool_t *oldStylePool;
extern sc_pool_t *oldAmdPool;

int mkdir_recursive(char *dir);
int checkLockStatus(style_updator_config *config);
int parseLockUrl(sc_pool_t *pool, char *lockURL, style_updator_config *config);
Buffer *getUnzipCmd(sc_pool_t *pool, style_updator_config *config);
Buffer *getWgetParams(sc_pool_t *pool, style_updator_config *config);
char *read_file_content(sc_pool_t *pool, Buffer *filePath);
int file_validate_and_unCompress(style_updator_config *config, char *responseCnt);
int get_http_status_code(char *responseCnt);
void get_last_modified(Buffer *lastModifiedBuf, char *responseCnt);
int version_build(sc_pool_t *gPool, sc_pool_t *pool, style_updator_config *gConfig);
void data_handler(Buffer *resultBuf, int socketFd);
int execute_cmd(char *cmd);

#endif
