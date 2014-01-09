#include "stylecombine_ngx_module.h"

void *nginx_sc_module_init(sc_pool_t *pool, ngx_http_stylecombine_conf_t *conf)
{
    CombineConfig **config;

    if ( NULL == pool || NULL == conf) 
        return NULL;

    config = &conf.sc_global_config->sc_config;
    *config = sc_pcalloc(pool, sizeof(CombineConfig));
    if ( NULL == *config )
        return NULL;
    combine_config_init(pool, *config);
    global_variable_init(pool, *config, &conf.sc_global_config);
    conf->styleParserTags = {NULL, NULL};
    style_tag_init(pool, conf->styleParserTags);

    return *config
}
