/*
 * sc_log.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_LOG_H_
#define SC_LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <sys/errno.h>
#include <sys/syslog.h>

enum StyleCombineLogEnum {
	NO_LOG,                //不输出日志
	LOG_UNPROCESSED,       //信息未被模块处理时的日志
	LOG_TIME_COSTED,       //模块处理消耗时间
	LOG_VERSION_UPDATE,    //检查版本信息是否有更新
	LOG_PRINT_DATA,        //将模块处理过的数据打印出来
	LOG_STYLE_FIELD,       //打印styleField信息
	LOG_GET_VERSION,       //打印每个style获取版本信息
	LOG_NET_READ,          //打印网络读取的数据
	LOG_NET_WRITE          //打印网络写出的数据
};


void sc_log_core(int logLevelMask, const char *fmt, va_list args);

void sc_log_error(const char *fmt, ...);

void sc_log_debug(int currentLogLevel, const char *fmt, ...);

#define SC_LOG_PIC(logLevelMask) { \
	va_list args; \
	va_start(args, fmt); \
	sc_log_core(logLevelMask, fmt, args); \
	va_end(args); \
}

#endif /* SC_LOG_H_ */
