/*
 * sc_html_parser.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 *      Author: dongming.jidm
 *      Author: Bryton Lee
 */

#include "sc_log.h"
#include "sc_html_parser.h"
#include "sc_version.h"
#include "sc_combine.h"
#include "sc_config.h"

#define INIT_TAG_CONFIG(tagConfig, stylefield, newDomain, haveNewLine) {\
	tagConfig->styleField   = stylefield; \
	tagConfig->domain       = newDomain; \
	tagConfig->isNewLine    = haveNewLine; \
	tagConfig->styleCount   = 0; \
}

//解析field属性的值，有空格则去空格
#define FIELD_PARSE(p, ret, symbl) {\
	while(isspace(*p)){ ++p; }\
	if('=' == *p++) {\
		while(isspace(*p)){ ++p; }\
		if('"' == *p || '\'' == *p) { ++p; symbl = 1;} \
		while(isspace(*p)){ ++p; }\
	} else { ret = -1; } \
}

#define NEXT_CHARS(istr, eIndex, offset) { istr += offset, eIndex += offset; }

#define NEXT_CHAR(istr, eIndex) { istr++, eIndex++; }

#define RESET(bIndex, eIndex) { bIndex = eIndex + 1; }

#define NEXT_CHARS_WITH_RESET(istr, bIndex, eIndex, offset) { \
	NEXT_CHARS(istr, eIndex, offset); \
	RESET(bIndex, eIndex); \
}

/* Glibc substitutes strncmp by a macro when optimization is turned on and
 * macro arguments are checked before substitution.
 * so if strncmp is defined, undefine it.
 */
#ifdef strncmp
#undef strncmp
#endif
#define STR_TO_POSITION(str, position, posLen) \
do{ \
	(posLen) = 0; (position) = SC_NONE; \
	if(NULL != (str)) { \
		if (0 == strncmp((str), POSITION_TOP_WITH_LEN)) { \
			(posLen) = 3; (position) = SC_TOP; \
		}else if (0 == strncmp((str), POSITION_HEAD_WITH_LEN)) { \
			(posLen) = 4; (position) = SC_HEAD; \
		} else if (0 == strncmp((str), POSITION_FOOTER_WITH_LEN)) { \
			(posLen) = 6; (position) = SC_FOOTER; \
		} \
	} \
}while (0)

static char *tagPatterns[7]    =        { "head", "/head", "/body", "link", "script", "textarea", "!--" };
static short tagPatternsLen[7] =        { 4, 5, 5, 4, 6, 8, 3 };

static StyleField *style_field_create(sc_pool_t  *pool) {
	StyleField *styleField  = (StyleField *) sc_palloc(pool, sizeof(StyleField));
	if(NULL == styleField) {
		return NULL;
	}
	styleField->async       = 0;
    styleField->amd         = 0;
	styleField->styleUri    = NULL;
	styleField->version     = NULL;
    styleField->amdVersion  = NULL;
	styleField->position    = SC_NONE;
	styleField->styleType   = SC_TYPE_CSS;
	styleField->domainIndex = 0;
	styleField->group       = NULL;
	return styleField;
}

static ContentBlock *contentBlock_create_init(sc_pool_t *pool, int bIndex, int eIndex, enum TagNameEnum tagNameEnum) {
	if(eIndex < bIndex) {
		return NULL;
	}
	ContentBlock *contentBlock = (ContentBlock *) sc_palloc(pool, sizeof(ContentBlock));
	if(NULL == contentBlock) {
		return NULL;
	}
	contentBlock->bIndex       = bIndex,  contentBlock->eIndex = eIndex;
	contentBlock->cntBlock     = NULL;
	contentBlock->tagNameEnum  = tagNameEnum;
	return contentBlock;
}

static int getFieldValueLen(char *str, short symbl) {
	if(NULL == str) {
		return 0;
	}
	register int valueLen = 0, stop = 0;
	while(*str) {
		switch(*str) {
		case '\'':
		case '"':
			stop = 1;
			break;
		case ' ':
			//如果是以单双引号开始和结束的，中间可以有空格；否则以空格为结束
			if(1 == symbl) {
				break;
			}
			stop = 1;
			break;
		}
		if(stop) {
			break;
		}
		++str;
		++valueLen;
	}
	return valueLen;
}

static int parserTag(ParamConfig *paramConfig, StyleParserTag *ptag, Buffer *maxUrlBuf, StyleField **pStyleField, char *input) {

	if(NULL == ptag || NULL == input || NULL == maxUrlBuf) {
		return 0;
	}
	sc_pool_t *pool = paramConfig->pool;

	int count = 0;
	char ch   = '0' , pchar = '0';

	SC_BUFFER_CLEAN(maxUrlBuf);

	NEXT_CHARS(input, count, ptag->prefix->used - 1);

	for(ch = *input; (ZERO_END != ch && ch != ptag->suffix); ch = *(++input), count++) {
		//换行直接跳过, 并去除重复的空格
		if('\n' == ch || '\r' == ch) {
			continue;
		}
		ch = ('\t' == ch ? ' ' : ch); //将\t转为空格
		if(isspace(ch) && isspace(pchar)) {
			continue;
		}
		pchar           = ch;

		if(maxUrlBuf->used + 1 < maxUrlBuf->size) {
			maxUrlBuf->ptr[maxUrlBuf->used++] = ch;
		} else {
			sc_log_error("parserTag error url is too long [%s]", maxUrlBuf->ptr);
			return count;
		}
	}
	count                      += 1;
	maxUrlBuf->ptr[maxUrlBuf->used++] = *input++;
	maxUrlBuf->ptr[maxUrlBuf->used]   = ZERO_END;
	if (SC_TYPE_JS == ptag->styleType) {
		//对script需要特别处理，因为它是以</script>为结束，那么需要确定它是否是这样的。
		//如果不是那么则认为它是一个script代码块，或无效的js引用
		while(isspace(*input)) {
			NEXT_CHAR(input, count);
		}

		if (memcmp(ptag->closeTag->ptr, input, ptag->closeTag->used) != 0) {
			return count;
		}
		count += ptag->closeTag->used;
	}
	//===start parser===
	short dIndex         = 0;
	Buffer *domain       = NULL;
	char *tagBufPtr      = maxUrlBuf->ptr,  *currURL = NULL;
	for(dIndex = 0; dIndex < DOMAINS_COUNT; dIndex++) {
		domain = paramConfig->pConfig->oldDomains[dIndex];
		if(NULL == domain) {
			continue;
		}
		char *domainIndex = strstr(tagBufPtr, domain->ptr);
		if(NULL != domainIndex) {
			currURL = domainIndex;
			break;
		}
	}
	if(NULL == currURL) {
		return count;
	}

	if(SC_TYPE_CSS == ptag->styleType) {
		//如果是css 则检查它的rel属性是否为stylesheet
		if (NULL == strstr(tagBufPtr, ptag->mark->ptr)) {
			return count;
		}
	}

	char *currURI    = currURL + domain->used;
	short hasDot      = 0,  stop = 0;
	Buffer *styleUri = buffer_init_size(pool, (maxUrlBuf->used - domain->used));
	if(NULL == styleUri) {
		return count;
	}
	while(*currURI) {
		ch = *(currURI++);
		switch(ch) {
		case '"':
		case '\'':
		case '?':
		case ' ': //考虑 一些URL没有或忘记 以 单双引号结束的。浏览器是可以兼容这种错误的。
		case '>': //考虑 一些URL没被引号包起的，而且直接‘>’结束的。如：<script src=http://domain/app/a.js></script>
			//清除uri后面带的参数
			stop = 1;
			break;
		case '.':
			hasDot = 1;
			break;
		}
		if(stop) {
			break;
		}
		if(isspace(ch)) {
			continue;
		}
		styleUri->ptr[styleUri->used++] = ch;
	}
	if (!hasDot) { //没有带有.js/.css后缀的style文件将忽略处理
		return count;
	}
	styleUri->ptr[styleUri->used] = ZERO_END;
	StyleField *styleField = style_field_create(pool);
	if(NULL == styleField) {
		return count;
	}
	*pStyleField = styleField;
	int retValue               = 0;
	short hasSymble            = 0;
	//记录到URL和属性名的开始位置，如： href="xx" 记录的则是h前面的空格位置
	char *urlIndex             = currURL - ptag->refTag->used - 1;
	Buffer *group              = NULL,   *media = NULL;
	enum PositionEnum position = SC_NONE;
	while(*tagBufPtr) {
		if(tagBufPtr == urlIndex) {
			//解析属性的时候，URL直接跳过不做解析，因为URL中没有属性内容以提高效率
			tagBufPtr += (styleUri->used + ptag->refTag->used + domain->used);
		}
		if(!isspace(*tagBufPtr)) {
			++tagBufPtr;
			continue;
		}
		++tagBufPtr;  //偏移空格
		//parser media
		if(0 == memcmp(tagBufPtr, "media", 5)) {
			tagBufPtr   += 5; //偏移media
			retValue     = 0;
			hasSymble    = 0;
			FIELD_PARSE(tagBufPtr, retValue, hasSymble);
			if(retValue == -1) {
				continue;
			}
			int valueLen = getFieldValueLen(tagBufPtr, hasSymble);
			if(valueLen > 0) {
				media = buffer_init_size(pool, valueLen + 8);
				string_append(pool, media, tagBufPtr, valueLen);
				tagBufPtr += valueLen;
				continue;
			}
		}
		//parser customize field
		int fieldPrefixLen = 8;
		if(0 != memcmp(tagBufPtr, "data-sc-", fieldPrefixLen)) {
			tagBufPtr++;
			continue;
		}
		tagBufPtr         += fieldPrefixLen;
		switch(*tagBufPtr) {
		case 'p': //data-sc-pos
			if(0 == compare(tagBufPtr, "pos", 3, 0)) {
				tagBufPtr   += 3;
				retValue     = 0;
				hasSymble    = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				int posLen = 0;
				STR_TO_POSITION(tagBufPtr, position, posLen);
				tagBufPtr  += posLen + hasSymble;
				continue;
			}
			break;
		case 'a': //data-sc-async or data-sc-amd
			if(0 == compare(tagBufPtr, "async", 5, 0)) {
				tagBufPtr   += 5;
				retValue     = 0;
				hasSymble    = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				if(0 == memcmp(tagBufPtr, "true", 4)) {
					styleField->async = 1;
					tagBufPtr        += 4 + hasSymble;
					continue;
				}
			}
            if(0 == compare(tagBufPtr, "amd", 3, 0)) {
                tagBufPtr   += 3;
                retValue     = 0, 
                hasSymble    = 0;
                FIELD_PARSE(tagBufPtr, retValue, hasSymble);
                if(retValue == -1) {
                    continue;
                }
                if(0 == memcmp(tagBufPtr, "true", 4)) {
                    styleField->amd = 1;
                    tagBufPtr += 4 + hasSymble;
                    continue;
                }
            }
			break;
		case 'g': //data-sc-group
			if(0 == compare(tagBufPtr, "group", 5, 0)) {
				tagBufPtr     += 5;
				retValue       = 0;
				hasSymble      = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				int valueLen    = getFieldValueLen(tagBufPtr, hasSymble);
				if(valueLen > 0) {
					group       = buffer_init_size(pool, valueLen + 8);
					string_append(pool, group, tagBufPtr, valueLen);
					tagBufPtr   += valueLen;
					continue;
				}
				continue;
			}
			break;
		}
	}
	styleField->domainIndex = dIndex;
	styleField->styleType   = ptag->styleType;
	styleField->position    = position;
	styleField->styleUri    = styleUri;
	styleField->media       = media;
	if(NULL == group) {
		//group和pos 都为空时，保持原地不变
		if(SC_NONE == position) {
			styleField->async = 0;
			return count;
		}
		//当只有async属性时，保证原地不变
		if(styleField->async) {
			styleField->async   = 0;
			styleField->position = SC_NONE;
			return count;
		}
	} else {
		if(SC_NONE == position && !styleField->async) {
			styleField->group = NULL;
			return count;
		}
	}
	//pos build
	char g;
	if(SC_NONE != position && NULL == group) {
		//create default group
		group = buffer_init_size(pool, 24);
		string_append(pool, group, "_def_group_name_", 16);
		g     = '0' + (int) position;
	} else {
		g     = '0' + styleField->async;
	}
	group->ptr[group->used++] = g;
	group->ptr[group->used]   = ZERO_END;
	styleField->group         = group;
	return count;
}

/**
 * style去重，对于异步style去重必须是当整个页面都解析完之后再进行，因为一些异步的js写在页面开始的地方.
 * 页面实际页面上非异步的style还没有解析到，导致无法与页面上的style去重效果
 *
 * key的生成策略，
 * 非异步为：域名下标+URI
 * 异步为：域名下标+URI+组名
 */
static short isRepeat(sc_pool_t *pool, sc_hash_t *duplicats, StyleField *styleField) {
	if(NULL == duplicats) {
		return 0;
	}
	int len = styleField->styleUri->used;
	//make a key
	Buffer *key = buffer_init_size(pool, len + 26);
	if(NULL == key) {
		return 0;
	}
	//add domain area
	key->ptr[key->used++] = '0' + styleField->domainIndex;
	string_append(pool, key, styleField->styleUri->ptr, styleField->styleUri->used);
	if(NULL != sc_hash_get(duplicats, key->ptr, key->used)) {
		//if uri has exsit then skiping it
		return 1;
	}
	if(styleField->async) {
		//add group area
		string_append(pool, key, styleField->group->ptr, styleField->group->used);
		if(NULL != sc_hash_get(duplicats, key->ptr, key->used)) {
			//if uri has exsit then skiping it
			return 1;
		}
	}
	sc_hash_set(duplicats, key->ptr, key->used, "1");
	return 0;
}

/**
 * 解析出amd模块依赖，将每个依赖作为单独的script插入到js列表中
 * dongming.jidm
 */
static void parseDependecies(sc_pool_t *pool, GlobalVariable *globalVariable,
                StyleField *styleField, LinkedList *listItem, char *url, sc_hash_t *duplicates)
{

    char *amdVersion = sc_pstrdup(pool, styleField->amdVersion->ptr);
    char **result = NULL;
    char *sepreator = ",";
    int i = 0;
    int num = count_n(amdVersion, sepreator);

    //result = ( char ** ) malloc( sizeof(char*) * ( num +1));
    result  = (char **) sc_palloc(pool, sizeof(char*) * ( num +1));

    int count = split_n(result, amdVersion, sepreator);

    for ( i = 0; i < count; i++) {
        StyleField *styleFieldAmd = style_field_create(pool);
        Buffer *dependBuf = buffer_init_size(pool, 1024);

        char *restr = sc_pstrdup(pool, result[i]);
        dependBuf->ptr = restr;
        dependBuf->used = strlen(restr);

//        dependBuf->ptr = result[i];
//        dependBuf->used = strlen(result[i]);

        styleFieldAmd->async = styleField->async;
        styleFieldAmd->styleType = styleField->styleType;
        styleFieldAmd->domainIndex = styleField->domainIndex;
        styleFieldAmd->styleUri = dependBuf;
        styleFieldAmd->group = styleField->group;
        styleFieldAmd->media = styleField->media;
        styleFieldAmd->version = get_string_version(pool, url, dependBuf, globalVariable);
        styleFieldAmd->position = styleField->position;

        //去重，但不包括最后一个入口文件
        if(!styleField->async && isRepeat(pool, duplicates, styleFieldAmd) && i != (count - 1)) {
            continue;
        }

//        log_error("url is %s", styleFieldAmd->styleUri->ptr);

        add(pool, listItem, styleFieldAmd);
    }

    //free(result);
}

int html_parser(ParamConfig *paramConfig, Buffer *sourceCnt,
        Buffer *combinedStyleBuf[3], LinkedList *blockList, char *unparsed_uri)
{

	if (SC_IS_EMPTY_BUFFER(sourceCnt) || NULL == combinedStyleBuf || NULL == blockList) {
		return 0;
	}
	sc_pool_t *req_pool   = paramConfig->pool;
	CombineConfig *pConfig= paramConfig->pConfig;
	char *input           = sourceCnt->ptr;
	//创建一个列表，用于存放所有的索引对象，包括一些未分组和未指定位置的style
	ContentBlock *block   = NULL;

    //dongming.jidm
    Buffer *appState = get_string_version(req_pool, unparsed_uri,
                            pConfig->appName, paramConfig->globalVariable);
    if (strcmp(appState->ptr, "off") == 0) {
        return 0;
    }

	//用于去重的 hash
	sc_hash_t *duplicates= sc_hash_make(req_pool);

	//用于存放解析出来的style URL 长度为 maxURL的2倍
	Buffer     *maxUrlBuf    = buffer_init_size(req_pool, pConfig->maxUrlLen * 2);

	//域名数组，用于存放不同域名下的styleMap
	sc_hash_t *domains[DOMAINS_COUNT] = { NULL, NULL };

	//用于存放 同步（直接加载）的style列表
	LinkedList *syncStyleList  = linked_list_create(req_pool);

	//用于存放 异步的style列表
	LinkedList *asyncStyleList = linked_list_create(req_pool);

	/**
	 * posHTMLTagExist
	 *
	 * html的位置标签是否存在，如果不存在则直接退合并（本模块将不做任何的事情，直接原样输出）
	 * 所谓位置标签为：输出时的3个位置 top、head、footer
	 * top是    <head> 尾部
	 * head是   </head>前面
	 * footer是 </body>前面
	 *
	 * 如果一个页面的HTML标签不具备这几个位置标签，则本次模块合并失败，直接原样输出HTML。产生一条日志做为提示。
	 */
	short  posHTMLTagExist[]    = { 0, 0, 0 };
	short isExpression          = 0;

	enum TagNameEnum  tnameEnum = SC_LINK;
	enum PositionEnum posEnum   = SC_NONE;
	enum StyleType    styleType = SC_TYPE_CSS;

	int styleCount = 0, retIndex  = 0;
	int bIndex     = 0, eIndex  = -1, i = 0;
	char *istr     = input, *istrTemp = NULL;

	while (*istr) {
		if('<' != *istr) {
			NEXT_CHAR(istr, eIndex);
			continue;
		}

		NEXT_CHAR(istr, eIndex);
		switch (*istr) {
		case 'H':
		case 'h': // find <head>
			if(1 == posHTMLTagExist[SC_BHEAD]) {
				NEXT_CHAR(istr, eIndex);                         //偏移 h 1个字符长度
				continue;
			}

			retIndex = compare(istr, tagPatterns[SC_BHEAD], tagPatternsLen[SC_BHEAD], 1);
			if(0 != retIndex) {
				NEXT_CHAR(istr, eIndex);                         //偏移 h 1个字符长度
				continue;
			}

			NEXT_CHARS(istr, eIndex, tagPatternsLen[SC_BHEAD] + 1);    //偏移 > 1个结束符字符长度
			block         = contentBlock_create_init(req_pool, bIndex, eIndex, SC_BHEAD);
			add(req_pool, blockList, (void *) block);
			RESET(bIndex, eIndex);
			posHTMLTagExist[SC_TOP] = 1;
			break;
		case '/': // find </head> </body>
			switch(*(istr + 1)) {
			case 'h':
			case 'H':
				tnameEnum = SC_EHEAD;
				posEnum   = SC_HEAD;
				break;
			case 'b':
			case 'B':
				tnameEnum = SC_EBODY;
				posEnum   = SC_FOOTER;
				break;
			default:
				continue;
			}
			//如果页面上有多个结束的head,body标签。应使用第一次出现的/head /body标签，后面的忽略
			if(1 == posHTMLTagExist[posEnum]) {
				NEXT_CHAR(istr, eIndex);
				continue;
			}

			if(0 != compare(istr, tagPatterns[tnameEnum], tagPatternsLen[tnameEnum], 1)) {
				NEXT_CHAR(istr, eIndex);
				continue;
			}
			/**
			 * 这里需要注意一个问题，当以<script data-sc-pos=head src=a.js></script>结束后紧跟</head>时。
			 * 那么bIndex 与 eIndex - 1是相等的，所以创建的block为NULL，最终导致a.js没有在head中输出，而是消失了。
			 */
			block         = contentBlock_create_init(req_pool, bIndex, eIndex - 1, tnameEnum); // </
			if(NULL == block) {
				block = (ContentBlock *) sc_palloc(req_pool, sizeof(ContentBlock));
				if(NULL == block) {
					continue;
				}
				block->bIndex       = 0,  block->eIndex = 0;
				block->cntBlock     = NULL;
				block->tagNameEnum  = tnameEnum;
			}

			add(req_pool, blockList, (void *) block);
			bIndex        = eIndex;
			NEXT_CHARS(istr, eIndex, tagPatternsLen[tnameEnum] + 1);    //偏移 /head>|/body> 6个字符长度
			posHTMLTagExist[posEnum] = 1;
			break;
		case 'T':
		case 't': // find <textarea ...>...</textarea>  must be suppor (upper&lower) case
			retIndex = compare(istr, tagPatterns[SC_TEXTAREA], tagPatternsLen[SC_TEXTAREA], 1);
			if (0 != retIndex) {
				NEXT_CHAR(istr, eIndex);
				continue;
			}
			char *textArea = istr + tagPatternsLen[SC_TEXTAREA] + 1; // 偏移 textarea> 9个字符长度
			while(*textArea) {
				if(0 == strncasecmp("</textarea>", textArea, 11)) {
					textArea += 11;         // 偏移 </textarea> 11字符长度
					break;
				}
				++textArea;
			}
			int offsetLen = (textArea - istr);
			NEXT_CHARS(istr, eIndex, offsetLen);
			break;
		case 'l': // find link
		case 's': // find script
			if('s' == *istr) { //默认是 link
				styleType                  = SC_TYPE_JS;
				tnameEnum                  = SC_SCRIPT;
			} else {
				styleType                  = SC_TYPE_CSS;
				tnameEnum                  = SC_LINK;
			}
			retIndex = compare(istr, tagPatterns[tnameEnum], tagPatternsLen[tnameEnum], 0);
			if(0 != retIndex) {
				NEXT_CHAR(istr, eIndex);
				continue;
			}

			//parser Tag
			StyleField *styleField = NULL;
			int retLen = parserTag(paramConfig, paramConfig->styleParserTags[styleType], maxUrlBuf, &styleField, istr);
			if(NULL == styleField) { //an error style
				NEXT_CHARS(istr, eIndex, retLen);
				continue;
			}

			//扫过的内容位置记录下来保存到列表中
			block         = contentBlock_create_init(req_pool, bIndex, eIndex - 1, tnameEnum);
			add(req_pool, blockList, (void *) block);
			bIndex        = eIndex;

			if(LOG_STYLE_FIELD == paramConfig->pConfig->printLog) {
				sc_log_debug(LOG_STYLE_FIELD, "styleField "
                    "uri[%s]used[%d]len[%d]size[%d] type[%d]"
                    " group[%s] media[%s] pos[%d] async[%d] amd[%d]",
								styleField->styleUri->ptr, 
                                styleField->styleUri->used, 
                                strlen(styleField->styleUri->ptr), 
                                styleField->styleUri->size,
								styleField->styleType, 
                                styleField->group->ptr,
								((styleField->media)==NULL ? "" : styleField->media->ptr), 
                                styleField->position, 
                                styleField->async,
                                styleField->amd
                );
			}

			NEXT_CHARS_WITH_RESET(istr, bIndex, eIndex, retLen);
			INIT_TAG_CONFIG(paramConfig, styleField, pConfig->newDomains[styleField->domainIndex], 0);
			++styleCount; //计数有多少个style

			//IE条件表达式里面的style不能做去重操作
			if(isExpression) {
				styleField->version = get_string_version(req_pool, unparsed_uri, styleField->styleUri, paramConfig->globalVariable);
				block               = contentBlock_create_init(req_pool, -1, 0, tnameEnum);
				block->cntBlock     = buffer_init_size(req_pool, paramConfig->domain->used + styleField->styleUri->used + 100);
				add(req_pool, blockList, (void *) block);
				addExtStyle(block->cntBlock, paramConfig);
				continue;
			}

			//clean duplicate
			if(!styleField->async && isRepeat(req_pool, duplicates, styleField)) {
				continue;
			}

			styleField->version = get_string_version(req_pool, unparsed_uri, styleField->styleUri, paramConfig->globalVariable);
            if (styleField->amd) {
                styleField->amdVersion = getAmdVersion(req_pool, unparsed_uri, 
                        styleField->styleUri, paramConfig->globalVariable);
            }
			//当没有使用异步并且又没有设置位置则保持原位不动
			if(0 == styleField->async && SC_NONE == styleField->position) {
				block               = contentBlock_create_init(req_pool, -1, 0, tnameEnum);
				block->cntBlock     = buffer_init_size(req_pool, paramConfig->domain->used + styleField->styleUri->used + 100);
				add(req_pool, blockList, (void *) block);
				addExtStyle(block->cntBlock, paramConfig);
				continue;
			}

			/**
			 * ---domains[2]               两个域名
			 *    ---groupsMap[N]          域名下有多个分组，用于对每个分组内容进行隔离（异步和同步的都放在这里面）
			 *       ---styleList[2]       每个分组下面有js、css列表
			 *       |  ---itemList[N]     js/css列表
			 *       |
			 * 输出/合并时根据以下两个List 按顺序输出；（styleList指针为上面注释中所指的 "styleList[2]" 的指针）
			 *    ---syncStyleList         存放所有同步（直接加载）的 styleList指针
			 *    ---asyncStyleList        存放所有异步的 styleList指针
			 *
			 */

			StyleList *styleList = NULL;
			sc_hash_t *groupsMap = domains[styleField->domainIndex];
			if(NULL == groupsMap) {
				domains[styleField->domainIndex] = groupsMap = sc_hash_make(req_pool);
                if ( !groupsMap ) {
                    // hash create failed !
                    return 0;
                }
			} else {
				styleList = sc_hash_get(groupsMap, styleField->group->ptr, styleField->group->used);
			}

			if(NULL == styleList || NULL == styleList->list[(int) styleField->styleType]) {
				if(NULL == styleList) {
					styleList = (StyleList *) sc_palloc(req_pool, sizeof(StyleList));
					if(NULL == styleList) {
						continue;
					}
					styleList->list[0] = NULL, styleList->list[1] = NULL;
					/**
					 * 将所有的styleList放入相应的 异步和非异步的列表中去。用于输出合并时使用。
					 */
					add(req_pool, (styleField->async == 1 ? asyncStyleList : syncStyleList), styleList);
				}

				LinkedList *itemList = linked_list_create(req_pool);
				if(NULL == itemList) {
					continue;
				}

                if (styleField->amd  && paramConfig->globalVariable->isAmdVersionGood &&
                         strcmp(styleField->amdVersion->ptr, "false") != 0) {
                    //dongming.jidm
                    parseDependecies(req_pool, paramConfig->globalVariable, styleField, 
                                itemList, unparsed_uri, duplicates);
                }else{
                    add(req_pool, itemList, styleField);
                }

				styleList->domainIndex = styleField->domainIndex;
				styleList->group = styleField->group;
				styleList->list[(int) styleField->styleType] = itemList;
				/**
				 * 通过使用hash来控制每个group对应一个list
				 */
				sc_hash_set(groupsMap, styleField->group->ptr, styleField->group->used, styleList);
			} else {
                if (styleField->amd  && paramConfig->globalVariable->isAmdVersionGood && 
                        strcmp(styleField->amdVersion->ptr, "false") != 0) {
                    //dongming.jidm
                    parseDependecies(req_pool, paramConfig->globalVariable, styleField, 
                        styleList->list[(int) styleField->styleType], unparsed_uri, duplicates);
                }else{
                    add(req_pool, styleList->list[(int) styleField->styleType], styleField);
                }
			}
			//去掉style后面的回车 制表 空格等符号
			while(isspace(*istr)) {
				NEXT_CHARS_WITH_RESET(istr, bIndex, eIndex, 1);
			}
			break;
		case '!':

			/**
			 * 对HTML语法的注释和IE注释表达式的支持
			 *
			 * 1.	<!--[if lt IE 7]> <html class="ie6" lang="en"> <![endif]-->   
			 * 2.	<!--[if IE 7]>    <html class="ie7" lang="en"> <![endif]-->   
			 * 3.	<!--[if IE 8]>    <html class="ie8" lang="en"> <![endif]-->   
			 * 4.	<!--[if IE 9]>    <html class="ie9" lang="en"> <![endif]-->   
			 * 5.	<!--[if gt IE 9]> <html lang="en"> <![endif]--> 
			 * 6.	<!--[if !IE]>-->  <html lang="en"> <!--<![endif]--> 
			 * 7.   <!--  .....  -->
			 *
			 */
			retIndex = compare(istr, tagPatterns[SC_COMMENT_EXPRESSION], tagPatternsLen[SC_COMMENT_EXPRESSION], 0);
			if (0 != retIndex) {
				// 处理IE条件表达式是否结束 "<![endif]-->"
				istrTemp = istr + 1;
				if(0 == memcmp(istrTemp , "[endif]", 7)) {
					isExpression = 0;
					NEXT_CHARS(istr, eIndex, 11);           //偏移 ![endif]--> 11个字符长度
					continue;
				}
				NEXT_CHAR(istr, eIndex);                    //偏移 ! 1个字符长度
				continue;
			}
			NEXT_CHARS(istr, eIndex, tagPatternsLen[SC_COMMENT_EXPRESSION]);  //偏移 <!-- 4个长度

			// 对第6种语法结束进行判断处理 "...<!--<![endif]-->"
			if(0 == memcmp(istr, "<![endif]", 9)) {
				isExpression = 0;
				NEXT_CHARS(istr, eIndex, 12);
				continue;
			}

			// 处理当前是否为IE表达式开始 "<!--[if IE xx]"
			if(0 == memcmp(istr, "[if", 3)) {
				isExpression = 1;
				NEXT_CHARS(istr, eIndex, 8);                //偏移 [if IE]> 8个字符“以最小集的长度来换算，其它 eq IE9/ge IE6则忽略”
				continue;
			}

			// 跳过当前的HTML注释语法
			while(*istr) {
				if (0 == memcmp(istr, "-->", 3)) {
					NEXT_CHARS(istr, eIndex, 2);           // 偏移 --> 3个字符长度，由于当前已经是-所以只需要偏移2位
					break;
				}
				NEXT_CHAR(istr, eIndex);
			}
			break;
		default:
			NEXT_CHAR(istr, eIndex);
			break;
		}
	}

	/**
	 * 没有找到任何的style, 或者页面上所需要的3个标签不完整。直接就可以返回了，不作任何合并处理
	 */
	short posHTMLTagCount = (posHTMLTagExist[0] + posHTMLTagExist[1] + posHTMLTagExist[2]);
	if(0 == styleCount || posHTMLTagCount < 3) {
		return 0;
	}

	//追加尾部的内容
	block = contentBlock_create_init(req_pool, bIndex, ++eIndex, SC_TN_NONE);
	add(req_pool, blockList, (void *) block);

	ListNode      *node = NULL;
	//对解析出来的异步style URL与同步style进行去重。如果同步的style已经存在，则丢弃异步的style
	LinkedList *asyncSDGroups[DOMAINS_COUNT] = { NULL, NULL };
	for(node = asyncStyleList->first; NULL != node; node = node->next) {
		StyleList *styleList = (StyleList *) node->value;

		//将所有的异步的style按照所属不同的域名进行分开，方便后续合并和输出
		LinkedList *asyncSLGroup = asyncSDGroups[styleList->domainIndex];
		if(NULL == asyncSLGroup) {
			asyncSDGroups[styleList->domainIndex] = asyncSLGroup = linked_list_create(req_pool);
		}
		add(req_pool, asyncSLGroup, styleList);

		for(i = 0; i < 2; i++) {
			LinkedList *list = styleList->list[i];
			if(NULL == list || !list->size) {
				continue;
			}
			ListNode *parentNode = NULL;
			ListNode *styleNode = (ListNode *) list->first;
			while(NULL != styleNode) {
				StyleField *styleField = (StyleField *) styleNode->value;
				if(isRepeat(req_pool, duplicates, styleField)) {
					//if exeist delete this node
					if(NULL == parentNode) {
						list->first = styleNode->next;
					} else {
						parentNode->next = styleNode->next;
					}
					styleNode = styleNode->next;
					--list->size;
					continue;
				}
				parentNode = styleNode;
				styleNode = styleNode->next;
			}
		}
	}

	if(0 == paramConfig->debugMode) {

		Buffer *versionBuf = buffer_init_size(req_pool, 1024);
		Buffer *tmpUriBuf = buffer_init_size(req_pool, pConfig->maxUrlLen + 50);

		//将解析出来的异步style URL进行合并
		short addScriptPic = 0;
		Buffer *headBuf = NULL;
		for(i = 0; i < DOMAINS_COUNT; i++) {
			LinkedList *asyncSDGroup = asyncSDGroups[i];
			if(NULL == asyncSDGroup) {
				continue;
			}
			if(0 == addScriptPic) {
				combinedStyleBuf[SC_HEAD] = headBuf = buffer_init_size(req_pool, 2048);
				string_append(req_pool, combinedStyleBuf[SC_HEAD], "\n<script type=\"text/javascript\">\n", 33);
				addScriptPic   =  1;
			}
			if(NULL != (node = asyncSDGroup->first)) {
				StyleList *styleList = (StyleList *) node->value;
				string_append(req_pool, headBuf, "var ", 4);
				Buffer *variableName = pConfig->asyncVariableNames[styleList->domainIndex];
				string_append(req_pool, headBuf, variableName->ptr, variableName->used);
				string_append(req_pool, headBuf, "={", 2);
				while(NULL != node) {
					styleList = (StyleList *) node->value;
					combineStylesAsync(paramConfig, styleList, headBuf, tmpUriBuf, versionBuf);
					node = (ListNode *) node->next;
				}
				headBuf->used -= 1;
				string_append(req_pool, headBuf, "};\n", 3);
			}
		}
		if(addScriptPic) {
			string_append(req_pool, headBuf, "</script>\n", 10);
		}

		//将解析出来的同步style URL进行合并
		for(node = syncStyleList->first; NULL != node; node = node->next) {
			StyleList *styleList = (StyleList *) node->value;
			for(i = 0; i < 2; i++) {
				LinkedList *list = styleList->list[i];
				if(NULL == list) {
					continue;
				}
				SC_BUFFER_CLEAN(tmpUriBuf); SC_BUFFER_CLEAN(versionBuf);
				combineStyles(paramConfig, list, combinedStyleBuf, tmpUriBuf, versionBuf);
			}
		}
	} else if(2 == paramConfig->debugMode) {
		//调式模式下的style输出格式
		combineStylesDebug(paramConfig, syncStyleList, combinedStyleBuf);
		for(i = 0; i < DOMAINS_COUNT; i++) {
			LinkedList *asyncList = asyncSDGroups[i];
			if(NULL != asyncList) {
				combineStylesDebug(paramConfig, asyncList, combinedStyleBuf);
			}
		}
	}
	return styleCount;
}
