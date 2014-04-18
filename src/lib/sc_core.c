/* 
 * Author: Bryton Lee
 */

/*
 * strcasestr is a nonstandard extension,
 * need to define _GNU_SOURCE before any #include */
#define _GNU_SOURCE
#include <string.h>
#include "sc_version.h"
#include "sc_combine.h"
#include "sc_log.h"
#include "sc_core.h"

#define INIT_TAG_CONFIG(tagConfig, stylefield, newDomain, haveNewLine) \
	do {\
		tagConfig->styleField   = stylefield; \
		tagConfig->domain       = newDomain; \
		tagConfig->isNewLine    = haveNewLine; \
		tagConfig->styleCount   = 0; \
	}while(0)

#define FIELD_PARSE(p, ret, symbl) \
	do{\
		while(isspace(*p)){ ++p; }\
		if('=' == *p++) {\
			while(isspace(*p)){ ++p; }\
			if('"' == *p || '\'' == *p) { ++p; symbl = 1;} \
			while(isspace(*p)){ ++p; }\
		} else { ret = -1; } \
	}while(0)

#define NEXT_CHARS(istr, eIndex, offset) { istr += offset, eIndex += offset; }
#define NEXT_CHAR(istr, eIndex) { istr++, eIndex++; }

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

#define SC_HTML_HEAD    "<head>"
#define SC_HTML_EHEAD   "</head>"
#define SC_HTML_LINK    "<link"
#define SC_HTML_SCRIPT  "<script"
#define SC_HTML_TEXTAREA "<textarea"
#define SC_HTML_COMMENT  "<!--"
#define SC_HTML_EBODY    "</body>"
#define SC_HTML_TAG_LEN(tag) (sizeof(tag) - 1)

typedef struct html_tag_flag_t {
	unsigned int pad:1;
	unsigned int head:1;
	unsigned int ehead:1;
	unsigned int link:1;
	unsigned int script:1;
	unsigned int textarea:1;
	unsigned int comment:1;
	unsigned int ebody:1;
}html_tag_flag;

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

/**
 * style去重，对于异步style去重必须是当整个页面都解析完之后再进行，因为一些异步的js写在页面开始的地方.
 * 页面实际页面上非异步的style还没有解析到，导致无法与页面上的style去重效果
 *
 * key的生成策略，
 * 非异步为：域名下标+URI
 * 异步为：域名下标+URI+组名
 */
	static short
isRepeat(sc_pool_t *pool, sc_hash_t *duplicates, StyleField *styleField)
{
	if(NULL == duplicates) {
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
	if(NULL != sc_hash_get(duplicates, key->ptr, key->used)) {
		//if uri has exsit then skiping it
		return 1;
	}
	if(styleField->async) {
		//add group area
		string_append(pool, key, styleField->group->ptr, styleField->group->used);
		if(NULL != sc_hash_get(duplicates, key->ptr, key->used)) {
			//if uri has exsit then skiping it
			return 1;
		}
	}
	sc_hash_set(duplicates, key->ptr, key->used, "1");
	return 0;
}

static int
parserTag(ParamConfig *paramConfig, StyleParserTag *ptag,
		StyleField **pStyleField, char *input){

	sc_pool_t   *pool = NULL;
	Buffer  *maxUrlBuf = NULL;
	char ch   = '0' , pchar = '0';
	int count = 0; 
	int ret = -1;

	if ( !paramConfig ||
			!ptag ||
			!pStyleField ||
			!input ) {
		return ret;
	}

	pool = paramConfig->pool;
	CombineConfig *pConfig= paramConfig->pConfig;

	maxUrlBuf = paramConfig->maxUrlBuf;
	if ( !maxUrlBuf )
		maxUrlBuf = paramConfig->maxUrlBuf = buffer_init_size(pool, pConfig->maxUrlLen * 2);
	else 
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

		linked_list_add(pool, listItem, styleFieldAmd);
	}

	//free(result);
}

	static ContentBlock *
content_block_create(sc_pool_t *pool, int bIndex, int eIndex, enum TagNameEnum tagNameEnum)
{
	if(eIndex <= bIndex) {
		return NULL;
	}

	ContentBlock *contentBlock = (ContentBlock *)sc_palloc(pool, sizeof(ContentBlock));
	if(NULL == contentBlock) {
		return NULL;
	}

	contentBlock->bIndex = bIndex;
	contentBlock->eIndex = eIndex;
	contentBlock->cntBlock = NULL;
	contentBlock->tagNameEnum = tagNameEnum;

	return contentBlock;
}

	static int
content_list_order_insert(sc_pool_t *pool, LinkedList *list, void *item)
{
	ListNode  *pre, *node = NULL;
	ContentBlock    *insert_block, *block;

	if ( !pool ||
			!list ||
			!item )
		return -1;

	insert_block = (ContentBlock *)item;
	block = NULL;

	pre = NULL;
	for ( node = list->first; node; node = node->next ) {
		block = (ContentBlock *) node->value;
		if ( block->bIndex < insert_block->bIndex ) {
			pre = node;
			continue;
		} else 
			break;
	}

	if ( !pre ) {
		node = (ListNode *) sc_palloc(pool, sizeof(ListNode));
		if ( !node )
			return -1;

		node->value = item;
		node->next = list->first;
		list->first = node;

	} else {
		node = (ListNode *) sc_palloc(pool, sizeof(ListNode));
		if ( !node )
			return -1;

		node->value = item;
		node->next = pre->next;
		pre->next = node;
		if ( !node->next )
			list->head = node;
	}

	list->size++;
	return 0;
}

/* sc_core_page_scan scan whole html_page and then return content list and style_list */
	static int
sc_core_page_scan(sc_pool_t *pool, Buffer *html_page,
		LinkedList *content_lst, LinkedList *style_lst)
{
	html_tag_flag flag={0,0,0,0,0,0,0,0};
	char *c, *tmp, *page;
	unsigned int   rest;
	ContentBlock *block = NULL;
	//int block_begin, block_end;
	size_t  block_begin, block_end;
	int ret = -1;

	if ( !pool || !html_page || !content_lst || !style_lst )
		return ret;

	page = html_page->ptr;
	if (!page || html_page->used <= 0)
		return ret;

	block_begin = block_end = 0;
	c = page;
	while ( *c ) {
		while ( block_end < html_page->size && *c != '<') {
			c++;
			block_end++;
		}

		if ( block_end >= html_page->size )
			break;

		/*
		 * sc_core_scan only care follow HTML tags:
		 *
		 * <head>
		 * </head>
		 * <link
		 * <script
		 * <textarea
		 * <!--
		 * </body>
		 */

		/* Note: rest size should biger or equal than HTML tag (which we interested in) size.
		 * otherwise strncasecmp will trigger wrong memory access */
		rest = (page + html_page->used) - c;
		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_HEAD) ) {
			ret = strncasecmp(c, SC_HTML_HEAD, SC_HTML_TAG_LEN(SC_HTML_HEAD)); 
			if ( ret == 0 ) {
				/* <head> found */
				if ( flag.head ) {
					/* Warning: duplicated <head>, just ignore it. */
					c += SC_HTML_TAG_LEN(SC_HTML_HEAD);
					block_end += SC_HTML_TAG_LEN(SC_HTML_HEAD);
					continue;
				}
				flag.head = 1;
				c += SC_HTML_TAG_LEN(SC_HTML_HEAD);
				block_end += SC_HTML_TAG_LEN(SC_HTML_HEAD);
				block = content_block_create(pool, block_begin, block_end, SC_BHEAD);
				if ( block ) {
					/* add to content list */
					linked_list_add(pool, content_lst, (void *)block);
					block_begin = block_end;
				} else {
					/* content block create failed! */
					return -1;
				}
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_EHEAD) ) {
			ret = strncasecmp(c, SC_HTML_EHEAD, SC_HTML_TAG_LEN(SC_HTML_EHEAD));
			if ( ret == 0 ) {
				/* </head> found */
				if ( !flag.head ) {
					/* Warning: </head> found before <head> */
					return -1;
				} else if ( flag.ehead ) {
					/* Warning: duplicated </head>, just ignore it. */
					c += SC_HTML_TAG_LEN(SC_HTML_EHEAD);
					block_end += SC_HTML_TAG_LEN(SC_HTML_EHEAD);
					continue;
				}
				flag.ehead = 1;
				block = content_block_create(pool, block_begin, block_end, SC_TN_NONE);
				if ( block ) {
					linked_list_add(pool, content_lst, (void *)block);
					block_begin = block_end;
				}else {
					/* content block create failed! */
					return -1;
				}
				c += SC_HTML_TAG_LEN(SC_HTML_EHEAD);
				block_end += SC_HTML_TAG_LEN(SC_HTML_EHEAD);
				block = content_block_create(pool, block_begin, block_end, SC_EHEAD);
				if ( block ) {
					/* add to content list */
					linked_list_add(pool, content_lst, (void *)block);
					block_begin = block_end;
				} else {
					/* content block create failed! */
					return -1;
				}
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_LINK) ) {
			ret = strncasecmp(c, SC_HTML_LINK, SC_HTML_TAG_LEN(SC_HTML_LINK));
			if ( ret == 0 ) {
				/* <link found */
				if ( !flag.link )
					flag.link = 1;

				/* save scanned content */
				if ( block_end > block_begin ) {
					block = content_block_create(pool, block_begin, block_end, SC_TN_NONE);
					if ( block ) {
						linked_list_add(pool, content_lst, (void *)block);
						block_begin = block_end;
					}else {
						/* content block create failed! */
						return -1;
					}
				}
				/* find the end of <link */
				tmp = strstr(c, ">");
				if ( tmp ) {
					block_end += tmp - c + 1; /* 1 means size of ">" */
					c = tmp + 1; /* ditto */
					block = content_block_create(pool, block_begin, block_end, SC_LINK);
					if ( block ) {
						/* add to style list */
						linked_list_add(pool, style_lst, (void *)block);
						block_begin = block_end;
					} else {
						/* content block create failed! */
						return -1;
					}
				} else {
					/* Warning: can not find "/>" to terminate "<link" */
					return -1;
				}
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_SCRIPT) ) {
			ret = strncasecmp(c, SC_HTML_SCRIPT, SC_HTML_TAG_LEN(SC_HTML_SCRIPT));
			if ( ret == 0 ) {
				/* <script found */
				if ( !flag.script ) {
					flag.script = 1;
				}

				/* save scanned content */
				if ( block_end > block_begin ) {
					block = content_block_create(pool, block_begin, block_end, SC_TN_NONE);
					if ( block ) {
						linked_list_add(pool, content_lst, (void *)block);
						block_begin = block_end;
					}else {
						/* content block create failed! */
						return -1;
					}
				}

				/* find the end of <script */
				tmp = strcasestr(c, "</script>");
				if ( !tmp ) {
					return -1;
				}
				block_end += tmp + SC_HTML_TAG_LEN("</script>") - c;
				c = tmp + SC_HTML_TAG_LEN("</script>");
				block = content_block_create(pool, block_begin, block_end, SC_SCRIPT);
				if ( block ) {
					/* add to style list */
					linked_list_add(pool, style_lst, (void *)block);
					block_begin = block_end;
				} else {
					/* can not create content block */
					return -1;
				}
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_TEXTAREA) ) {
			ret = strncasecmp(c, SC_HTML_TEXTAREA, SC_HTML_TAG_LEN(SC_HTML_TEXTAREA));
			if ( ret == 0 ) {
				/* </textarea found  */
				if ( !flag.textarea )
					flag.textarea = 1;

				/* </textarea will not add to content list alone, just skip 
				 * the while tag */
				tmp = strcasestr(c, "</textarea>");
				if ( !tmp ) {
					/* Warning: can not find </textarea> to terminate <textarea */
					return -1;
				}
				block_end += tmp + SC_HTML_TAG_LEN("</textarea>") - c;
				c = tmp + SC_HTML_TAG_LEN("</textarea>");
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_COMMENT) ) {
			ret = strncmp(c, SC_HTML_COMMENT, SC_HTML_TAG_LEN(SC_HTML_COMMENT));
			if ( ret == 0) {
				/* <!-- found */
				if ( !flag.comment )
					flag.comment = 1;

				/* <!-- --> will not add to content list alone, just skip
				 * the while tag */
				tmp = strstr(c, "-->");
				if ( !tmp ) {
					/* Warning: can not find --> to terminate <!-- */
					return -1;
				}
				/* TODO: support IE */
				block_end += tmp + SC_HTML_TAG_LEN("-->") - c;
				c = tmp + SC_HTML_TAG_LEN("-->");
				continue;
			}
		}

		if ( rest >= SC_HTML_TAG_LEN(SC_HTML_EBODY) ) {
			ret = strncasecmp(c, SC_HTML_EBODY, SC_HTML_TAG_LEN(SC_HTML_EBODY));
			if ( ret == 0 ) {
				/* </body> found */
				if ( flag.ebody ) {
					/* Warning: duplicated </body> found, just ignore it */
					c += SC_HTML_TAG_LEN(SC_HTML_EBODY);
					block_end += SC_HTML_TAG_LEN(SC_HTML_EBODY);
					continue;
				}
				flag.ebody = 1;
				block = content_block_create(pool, block_begin, block_end, SC_TN_NONE);
				if ( block ) {
					linked_list_add(pool, content_lst, (void *)block);
					block_begin = block_end;
				}else {
					/* content block create failed! */
					return -1;
				}
				c += SC_HTML_TAG_LEN(SC_HTML_EBODY);
				block_end += SC_HTML_TAG_LEN(SC_HTML_EBODY);
				block = content_block_create(pool, block_begin, block_end, SC_EBODY);
				if ( block ) {
					/* add to content list */
					linked_list_add(pool, content_lst, (void *) block);
					block_begin = block_end;
				} else {
					/* content block create failed! */
					return -1;
				}
			}
		}
		c++;
		block_end++;
	}/* while */

	if ( flag.head != 1 || 
			flag.ehead !=1 ||
			flag.ebody != 1 ||
			(flag.link == 0 && flag.script == 0) ) {
		/* HTML page is broken, or no link and script find in the page */
		return 0;
	}

	//block_end--; /* because *(page + block_end ) == '\0'; strip the last '\0' */ 
	/* add tail content to content block */
	if ( block_end > block_begin ) {
		block = content_block_create(pool, block_begin, block_end, SC_TN_NONE);
		if ( block ) {
			linked_list_add(pool, content_lst, (void *)block);
		} else {
			/* content block create failed! */
			return -1;
		}
	}

	return 1;
}

/* sc_core_style_parse parse the style list  */
	static int
sc_core_style_parse(ParamConfig *paramConfig, Buffer *html_page,
		LinkedList *content_lst, LinkedList *style_lst,
		LinkedList *syncStyleList, LinkedList *asyncStyleList)
{
	sc_pool_t   *pool = NULL;
	char        *unparsed_uri;
	char        *page, *style_start = NULL;
	ListNode    *list_node = NULL;
	ContentBlock    *tmp_block, *block = NULL;
	StyleField      *styleField = NULL;
	enum StyleType  styleType = SC_TYPE_CSS;
	/* used to strip duplicate styles */
	sc_hash_t       *duplicates = NULL;

	/* Note: we manage styles in such structure:
	 *      domain[DOMAINS_COUNT] contains DOMAINS_COUNT hash tables. 
	 *      each hash table can has many groups.
	 *      each group is a hash table's node and it is composed by style list(type StyleList)
	 *      each stylelist is composed by one JS style list and one CSS style list.
	 */
	sc_hash_t *domains[DOMAINS_COUNT] = { NULL, NULL };
	sc_hash_t *group_hash = NULL;
	StyleList *styleList = NULL;
	LinkedList *list = NULL; /* can be JS list or CSS list */

	int stylecount, ret = -1;

	if ( !paramConfig ||
			!html_page ||
			!content_lst ||
			!style_lst ||
			!syncStyleList ||
			!asyncStyleList )
		return ret;

	pool = paramConfig->pool;
	page = html_page->ptr;
	unparsed_uri = paramConfig->unparsed_uri;
	if ( !unparsed_uri )
		return ret;

	stylecount = 0;
	duplicates = sc_hash_make(pool);
	if ( !duplicates )
		return ret;

	for ( list_node = style_lst->first; list_node; list_node = list_node->next ) {
		block = (ContentBlock *)list_node->value;
		if ( block->tagNameEnum == SC_SCRIPT ) {
			styleType = SC_TYPE_JS;
		}else if ( block->tagNameEnum == SC_LINK ) {
			styleType = SC_TYPE_CSS;
		}else {
			/* should not run to here */
			content_list_order_insert(pool, content_lst, (void *)block); 
			continue;
		}
		style_start = page + block->bIndex;

		parserTag(paramConfig, paramConfig->styleParserTags[styleType],
				&styleField, style_start);
		if ( !styleField ) {
			/* bad lucky!!
			 * put back to the content list */
			content_list_order_insert(pool, content_lst, (void *)block); 
			continue;
		}
		stylecount++;

#if 0
		/* duplicate sync style does not add to sync style list.
		 *
		 * Note: there is a tricky here that isRepeact() not only return if it is duplicate
		 * but also set the styleField to duplicates hash table for the querying next time.
		 */
		if( !styleField->async && isRepeat(pool, duplicates, styleField) ) {
			continue;
		}
#else 
		/* duplicate styles does not add to style list.
		 *
		 * Note: there is a tricky here that isRepeact() not only return if it is duplicate
		 * but also set the styleField to duplicates hash table for the querying next time.
		 */
		if( isRepeat(pool, duplicates, styleField) )
			continue;
#endif

		styleField->version = get_string_version(pool, unparsed_uri, 
				styleField->styleUri, paramConfig->globalVariable);
		if ( styleField->amd ) {
			styleField->amdVersion = getAmdVersion(pool, unparsed_uri,
					styleField->styleUri, paramConfig->globalVariable);
		}


		/* if the block is a sync style and style position is not set can not combine directly
		 * we make a new block, do some necessary processes
		 * and then add it back to content list */
		if( 0 == styleField->async && SC_NONE == styleField->position ) {
			//tmp_block = content_block_create(pool, -1, 0, block->tagNameEnum);
			tmp_block = content_block_create(pool, block->bIndex, block->eIndex, block->tagNameEnum);
			if ( tmp_block ) {
				/* FIXME: INIT_TAG_CONFIG initialized some variables 
				 * that will be used later, but I think 
				 * these change to local variables will be better. */
				INIT_TAG_CONFIG(paramConfig, styleField, 
						paramConfig->pConfig->newDomains[styleField->domainIndex], 0);

				block->cntBlock = buffer_init_size(pool, 
						paramConfig->domain->used + styleField->styleUri->used + 100);

				addExtStyle(block->cntBlock, paramConfig);

				content_list_order_insert(pool, content_lst, (void *)tmp_block);
#if 0
				/* TODO: clear tmp_block->bIndex and tmp_block->eIndex */
				tmp_block->bIndex = -1;
				tmp_block->eIndex = 0;
#endif
			} else {
				/* bad lucky */
				content_list_order_insert(pool, content_lst, (void *)block); 
			}
			continue;
		}

		group_hash = domains[styleField->domainIndex];
		if ( !group_hash ) {
			group_hash = sc_hash_make(pool);
			if ( !group_hash ) {
				content_list_order_insert(pool, content_lst, (void *)block);
				continue;
			}
			domains[styleField->domainIndex] = group_hash;
		} 

		styleList = sc_hash_get(group_hash, styleField->group->ptr, styleField->group->used);
		if ( !styleList ) {
			styleList = (StyleList *) sc_palloc(pool, sizeof(StyleList)); 
			if ( !styleList ) {
				/* memory alloc failed */
				content_list_order_insert(pool, content_lst, (void *)block);
				continue;
			}
			styleList->domainIndex = styleField->domainIndex;
			styleList->group = styleField->group;
			styleList->list[0] = NULL, styleList->list[1] = NULL;
			linked_list_add(pool, (styleField->async == 1 ? asyncStyleList : syncStyleList), styleList);
			sc_hash_set(group_hash, styleField->group->ptr, styleField->group->used, styleList);
		}

		list = styleList->list[styleField->styleType];
		if ( !list ) {
			list = linked_list_create(pool);
			if ( !list ) {
				content_list_order_insert(pool, content_lst, (void *)block);
				continue;
			}
			styleList->list[styleField->styleType] = list;
		}

		if ( styleField->amd && paramConfig->globalVariable->isAmdVersionGood 
				&& strcmp(styleField->amdVersion->ptr, "false") != 0 ) {
			parseDependecies(pool, paramConfig->globalVariable, styleField,
					list, unparsed_uri, duplicates);
		} else {
			linked_list_add(pool, list, styleField);
		}
	}

	return stylecount;
}

	static int
sc_core_split_asynclist_by_domain(sc_pool_t *pool, LinkedList *asynclist,
		LinkedList *async_list_domain[DOMAINS_COUNT])
{
	int ret = -1;
	ListNode    *node = NULL;
	LinkedList *domain_list = NULL;
	StyleList   *styleList = NULL;

	if ( !pool ||
			!asynclist ||
			!async_list_domain )
		return ret;

	for ( node = asynclist->first; node ; node = node->next ) {
		styleList = (StyleList *)node->value;
		domain_list = async_list_domain[styleList->domainIndex];
		if ( !domain_list ) {
			domain_list = linked_list_create(pool);
			if ( !domain_list ) {
				/* create list failed!!! */
				return ret;
			}
			async_list_domain[styleList->domainIndex] = domain_list;
		}
		linked_list_add(pool, domain_list, styleList);
	}
	return 0;
}

	static int
sc_core_combine_async_style(ParamConfig *paramConfig, 
		LinkedList *async_list_domain[DOMAINS_COUNT], Buffer *combinedStyleBuf[3])
{
	CombineConfig *pConfig = NULL;
	sc_pool_t *pool;
	Buffer  *headBuf = NULL;
	Buffer  *variableName = NULL;

	LinkedList  *domain_list = NULL;
	ListNode    *node = NULL;
	StyleList   *styleList = NULL;

	short   add_script_prefix  = 0;
	short   add_async_var = 0;
	int i, ret = -1;


	if ( !*async_list_domain ||
			!paramConfig ||
			!combinedStyleBuf ) {
		return ret;
	}

	pConfig = paramConfig->pConfig;
	pool = paramConfig->pool;

	for ( i = 0; i < DOMAINS_COUNT; i++ ) {
		domain_list = async_list_domain[i];
		if ( !domain_list ) {
			continue;
		}

		if ( !add_script_prefix ) {
			combinedStyleBuf[SC_HEAD] = headBuf = buffer_init_size(pool, 2048);
			if ( !headBuf ) {
				/* buffer create failed */
				return ret;
			}
			string_append(pool, combinedStyleBuf[SC_HEAD],
					"\n<script type=\"text/javascript\">\n", 33);
			add_script_prefix = 1;
		}
		add_async_var = 0;
		for ( node = domain_list->first; node; node = node->next ) {
			styleList = (StyleList *)node->value; 
			variableName = pConfig->asyncVariableNames[styleList->domainIndex];
			if ( !add_async_var ) {
				string_append(pool, headBuf, "var ", 4);
				string_append(pool, headBuf, variableName->ptr, variableName->used);
				string_append(pool, headBuf, "={", 2);
				add_async_var = 1;
			} 
			combineStylesAsync(paramConfig, styleList, headBuf);
		}
		if ( add_async_var ) {
			string_append(pool, headBuf, "};\n", 3);
		}
	}

	if ( add_script_prefix ) {
		string_append(pool, headBuf, "</script>\n", 10);
	}

	return 0;
}

	static int
sc_core_combine_sync_style(ParamConfig *paramConfig, LinkedList *sync_style_list,
		Buffer *combinedStyleBuf[3])
{
	ListNode    *node = NULL;
	StyleList   *styleList = NULL;
	LinkedList  *list = NULL;
	int i, ret = -1;

	if ( !paramConfig ||
			!sync_style_list ||
			!combinedStyleBuf)
		return ret;

	for ( node = sync_style_list->first; node; node = node->next ) {
		styleList = (StyleList *)node->value;
		for ( i = 0; i < 2; i++ ) {
			list = styleList->list[i]; 
			combineStyles(paramConfig, list, combinedStyleBuf);
		}
	}
	return 0;
}

	static int
sc_core_combine_style_debug(ParamConfig *paramConfig, Buffer *combinedStyleBuf[3],
		LinkedList *async_list_domain[DOMAINS_COUNT], LinkedList *sync_style_list)
{
	int i,ret = -1;

	if ( !paramConfig ||
			!combinedStyleBuf ||
			!async_list_domain ||
			!sync_style_list )
		return ret;

	combineStylesDebug(paramConfig, sync_style_list, combinedStyleBuf);
	for(i = 0; i < DOMAINS_COUNT; i++) {
		LinkedList *asyncList = async_list_domain[i];
		if(NULL != asyncList) {
			combineStylesDebug(paramConfig, asyncList, combinedStyleBuf);
		}
	}

	return 0;
}

/* sc_core scan whole HTML page then returns content block list and combined style buffer.
 *
 * Input: paramConfig  (global variables like memory pool, debug mode etc)
 *        html_page (html_page->ptr pointer to whole HTML page)
 *        combinedStyleBuf[3] (combined styles are saved in)
 *        blockList (content block list)
 * 
 * Output: how many styles has been combined.
 */
int sc_core(ParamConfig *paramConfig, Buffer *html_page, 
		Buffer *combinedStyleBuf[3], LinkedList *blockList)
{
	sc_pool_t *pool;
	LinkedList *style_lst;
	LinkedList *syncStyleList, *asyncStyleList;
	LinkedList *async_list_domain[DOMAINS_COUNT] = { NULL, NULL };
	int stylecount = -1;
	int ret = -1;

	if ( !paramConfig ||
			!html_page ||
			!combinedStyleBuf ||
			!blockList )
		return ret;

	pool = paramConfig->pool;

	style_lst = linked_list_create(pool);
	if ( !style_lst )
		return ret;
	syncStyleList = linked_list_create(pool);
	if ( !syncStyleList )
		return ret;
	asyncStyleList = linked_list_create(pool);
	if ( !asyncStyleList )
		return ret;

	/* 1. scan while HTML page */
	ret = sc_core_page_scan(pool, html_page, blockList, style_lst);
	if ( ret != 1 )
		return ret;

	/* 2. parse style list */
	stylecount = sc_core_style_parse(paramConfig, html_page, blockList, style_lst,
			syncStyleList, asyncStyleList);
	if ( stylecount <= 0 )
		return stylecount;

	/* 3. split async style by domain */
	if ( asyncStyleList->size ) {
		ret = sc_core_split_asynclist_by_domain(pool,
				asyncStyleList, (LinkedList **)async_list_domain);
		if ( ret ) 
			return ret;
	}

	/* 4. combine style list */
	if ( DEBUG_OFF == paramConfig->debugMode ) {
		if ( asyncStyleList->size ) {
			/* async list combine */
			ret = sc_core_combine_async_style(paramConfig,
					(LinkedList **)async_list_domain, combinedStyleBuf);
			if ( ret )
				return ret;
		}

		if ( syncStyleList->size ) {
			/* sync list combine */
			ret = sc_core_combine_sync_style(paramConfig, syncStyleList, combinedStyleBuf);
			if ( ret )
				return ret;
		}

	}else if ( DEBUG_STYLECOMBINE == paramConfig->debugMode ) {
		if ( syncStyleList->size ) {
			sc_core_combine_style_debug(paramConfig, combinedStyleBuf,
					async_list_domain, syncStyleList);
		}
	}

	return stylecount;
}
