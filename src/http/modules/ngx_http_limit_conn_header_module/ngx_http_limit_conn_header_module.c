#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Structure representing a single node in the shared memory tracking concurrent connections */
typedef struct {
    u_char                          color;     /* Red-Black tree node color (required by ngx_rbtree) */
    u_char                          len;       /* Length of the identity key string (e.g., length of X-API-Key) */
    u_short                         conn;      /* Active concurrent connections counter for this specific key */
    u_char                          data[1];   /* Inline dynamic array to store the actual string key safely */
} ngx_http_limit_conn_node_t;

/* Structure passed to NGINX request pool cleanup handler when a connection terminates */
typedef struct {
    ngx_shm_zone_t                 *shm_zone;  /* Pointer to the shared memory zone being used */
    ngx_rbtree_node_t              *node;      /* Pointer to the RB-Tree node associated with this connection */
} ngx_http_limit_conn_cleanup_t;

/* Shared memory context containing the actual allocation of the Red-Black Tree */
typedef struct {
    ngx_rbtree_t                    rbtree;    /* The balanced Red-Black tree structure */
    ngx_rbtree_node_t               sentinel;  /* The leaf sentinel node for standard RB-Tree balancing boundary */
} ngx_http_limit_conn_shctx_t;

/* Module specific configuration context mapping keys to shared memory regions */
typedef struct {
    ngx_http_limit_conn_shctx_t    *sh;        /* Reference to the shared context within the memory zone */
    ngx_slab_pool_t                *shpool;    /* Slab allocator pool used for safe, fragmentation-free allocation */
    ngx_http_complex_value_t        key;       /* The compiled NGINX complex value variable definition (e.g., $http_x_api_key) */
} ngx_http_limit_conn_ctx_t;

/* Single rule constraint mapping a shared memory zone to a connection threshold limit */
typedef struct {
    ngx_shm_zone_t                 *shm_zone;  /* Target shared memory zone */
    ngx_uint_t                      conn;      /* Maximum number of allowed concurrent connections */
} ngx_http_limit_conn_limit_t;

/* Configuration structure matching the NGINX configuration block scopes (main, server, location) */
typedef struct {
    ngx_array_t                     limits;      /* Array containing all defined ngx_http_limit_conn_limit_t rules */
    ngx_uint_t                      log_level;   /* NGINX standard log level threshold for rejection logging */
    ngx_uint_t                      status_code; /* HTTP status code returned upon violation (default: 503) */
    ngx_flag_t                      dry_run;     /* Flag determining whether to block traffic or just log it */
} ngx_http_limit_conn_conf_t;

/* Forward declarations of module internal helper functions and handlers */
static ngx_rbtree_node_t *ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash);
static void ngx_http_limit_conn_cleanup(void *data);
static ngx_int_t ngx_http_limit_conn_header_status_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_limit_conn_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_limit_conn_header_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_limit_conn_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_limit_conn_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_limit_conn_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_limit_conn_header_handler(ngx_http_request_t *r);

/* Enum mapping string names in nginx.conf to NGINX native log level numeric bitmasks */
static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};

/* Validator bound constraints enforcing that HTTP response codes remain between 400 and 599 */
static ngx_conf_num_bounds_t  ngx_http_limit_conn_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};

/* Module directive configuration array defining how nginx.conf parameters map into structural handlers */
static ngx_command_t  ngx_http_limit_conn_header_commands[] = {
    { ngx_string("limit_conn_by_header_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_header_zone,
      0, 0, NULL },
    { ngx_string("limit_conn_by_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_header,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("limit_conn_header_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, log_level),
      &ngx_http_limit_conn_log_levels },
    { ngx_string("limit_conn_header_status_code"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, status_code),
      &ngx_http_limit_conn_status_bounds },
    { ngx_string("limit_conn_header_dry_run"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, dry_run),
      NULL },
      ngx_null_command
};

/* Context setup defining phase hooks (variables initialization and master initialization injection) */
static ngx_http_module_t  ngx_http_limit_conn_module_ctx = {
    ngx_http_limit_conn_add_variables, ngx_http_limit_conn_init,
    NULL, NULL, NULL, NULL,
    ngx_http_limit_conn_create_conf, ngx_http_limit_conn_merge_conf
};

/* Official module definition structural interface exported to NGINX core engine */
ngx_module_t  ngx_http_limit_conn_header_module = {
    NGX_MODULE_V1, &ngx_http_limit_conn_module_ctx,
    ngx_http_limit_conn_header_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

/* Exposed HTTP variable configuration array */
static ngx_http_variable_t  limit_conn_header_status_vars[] = {
    { ngx_string("limit_conn_header_status"), NULL,
      ngx_http_limit_conn_header_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
      ngx_http_null_variable
};

/* Core Request interceptor running at NGX_HTTP_PREACCESS_PHASE */
static ngx_int_t
ngx_http_limit_conn_header_handler(ngx_http_request_t *r)
{
    size_t n; uint32_t hash; ngx_str_t key;
    ngx_uint_t i;
    ngx_rbtree_node_t *node; ngx_pool_cleanup_t *cln;
    ngx_http_limit_conn_ctx_t *ctx; ngx_http_limit_conn_node_t *lc;
    ngx_http_limit_conn_conf_t *lccf; ngx_http_limit_conn_limit_t *limits;
    ngx_http_limit_conn_cleanup_t *lccln;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Handler started!");

    /* Skip subrequests and internal redirects to avoid redundant counter increments */
    if (r->main->count > 1 && r != r->main) {
        return NGX_DECLINED;
    }
    
    /* Fetch location configuration module context */
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_limit_conn_header_module);
    if (lccf->limits.elts == NULL) return NGX_DECLINED;
    limits = lccf->limits.elts;

    /* Loop through all active connection limiting limits evaluated for this configuration scope */
    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;
        
        /* Evaluate the runtime value of the extracted complex key header */
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Fallback deny enforcement if the required client identifier header is completely missing */
        if (key.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                          "MICHAL_LOG: Missing identity header! Applying Fallback Deny.");
            return lccf->status_code; 
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Processing request for key: [%V]", &key);
        
        /* Compute optimized lookup hash key index via CRC32 hashing algorithm */
        hash = ngx_crc32_short(key.data, key.len);
        
        /* Lock inter-process shared memory mutex to ensure critical path race safety */
        ngx_shmtx_lock(&ctx->shpool->mutex);
        
        /* Query the shared memory Red-Black tree for a pre-existing matching client key entry */
        node = ngx_http_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);
        if (node == NULL) {
            /* Compute necessary node size byte footprint tracking padding offsets safely */
            n = offsetof(ngx_rbtree_node_t, color) + offsetof(ngx_http_limit_conn_node_t, data) + key.len;
            
            /* Allocate node dynamically inside the shared memory segment using the slab allocator */
            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node == NULL) { 
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return lccf->status_code; 
            }
            
            /* Structure structural mapping using pointer casting arithmetic */
            lc = (ngx_http_limit_conn_node_t *) &node->color;
            node->key = hash; lc->len = (u_char) key.len; lc->conn = 1;
            
            /* Secure native memory copy without terminating null requirements */
            ngx_memcpy(lc->data, key.data, key.len);
            
            /* Insert node securely into the tracking structure tree layout */
            ngx_rbtree_insert(&ctx->sh->rbtree, node);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] is NEW. Connection allowed. Count: %ui", &key, lc->conn);
        } else {
            /* Node match found; evaluate structural representation */
            lc = (ngx_http_limit_conn_node_t *) &node->color;
            
            /* Enforce connection blocking threshold limits */
            if ((ngx_uint_t) lc->conn >= limits[i].conn) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] EXCEEDED limit! Blocking request. Current: %ui, Max Allowed: %ui", &key, (ngx_uint_t) lc->conn, limits[i].conn);
                ngx_shmtx_unlock(&ctx->shpool->mutex); 
                return lccf->status_code; 
            }
            
            /* Increment active global thread connection metrics */
            lc->conn++;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] exists. Conn count incremented to: %d", &key, lc->conn);
        }

        /* Register cleanup handler routine to hook pool deallocations when client drops connection */
        cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_limit_conn_cleanup_t));
        if (cln == NULL) {
            lc->conn--; /* Fallback rollback strategy on extreme system allocation collapse */
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_limit_conn_cleanup;
        lccln = cln->data; 
        lccln->shm_zone = limits[i].shm_zone; 
        lccln->node = node;
        
        /* Unlock mutex context letting other worker execution streams process network threads */
        ngx_shmtx_unlock(&ctx->shpool->mutex);
    }
    return NGX_DECLINED;
}

/* Red-Black Tree custom insertion balancing algorithm supporting accurate hash hash collison key indexing */
static void
ngx_http_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_http_limit_conn_node_t *lcn, *lcnt;
    for ( ;; ) {
        if (node->key < temp->key) p = &temp->left;
        else if (node->key > temp->key) p = &temp->right;
        else {
            /* Resolving Hash matching collisions explicitly via string content validation */
            lcn = (ngx_http_limit_conn_node_t *) &node->color;
            lcnt = (ngx_http_limit_conn_node_t *) &temp->color;
            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0) ? &temp->left : &temp->right;
        }
        if (*p == sentinel) break;
        temp = *p;
    }
    *p = node; node->parent = temp; node->left = sentinel; node->right = sentinel; ngx_rbt_red(node);
}

/* Binary Search lookup optimization through structured Red-Black tree properties */
static ngx_rbtree_node_t *
ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t rc; ngx_rbtree_node_t *node, *sentinel; ngx_http_limit_conn_node_t *lcn;
    node = rbtree->root; sentinel = rbtree->sentinel;
    while (node != sentinel) {
        if (hash < node->key) { node = node->left; continue; }
        if (hash > node->key) { node = node->right; continue; }
        
        /* Direct secondary validation check verifying matching underlying key sequence values */
        lcn = (ngx_http_limit_conn_node_t *) &node->color;
        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);
        if (rc == 0) return node;
        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

/* Connection finalization cleanup callback decrements counters and garbage-collects idle memory structures */
static void
ngx_http_limit_conn_cleanup(void *data)
{
    ngx_http_limit_conn_cleanup_t *lccln = data;
    ngx_http_limit_conn_ctx_t *ctx; ngx_http_limit_conn_node_t *lc;
    ctx = lccln->shm_zone->data; 
    lc = (ngx_http_limit_conn_node_t *) &lccln->node->color;
    
    ngx_shmtx_lock(&ctx->shpool->mutex);
    lc->conn--;
    
    /* If no active requests remain for this specific header context identity, purge node entirely */
    if (lc->conn == 0) { 
        ngx_rbtree_delete(&ctx->sh->rbtree, lccln->node); 
        ngx_slab_free_locked(ctx->shpool, lccln->node);
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex);
}

/* Zone initialization logic executing right inside master process stack generation */
static ngx_int_t
ngx_http_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_conn_ctx_t *octx = data; size_t len;
    ngx_http_limit_conn_ctx_t *ctx = shm_zone->data;
    
    /* Reuse memory layouts across hot configuration reloads safely */
    if (octx) { ctx->sh = octx->sh; ctx->shpool = octx->shpool; return NGX_OK; }
    
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_conn_shctx_t));
    if (ctx->sh == NULL) return NGX_ERROR;
    
    ctx->shpool->data = ctx->sh;
    
    /* Initialize instance level shared Red Black tree properties */
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel, ngx_http_limit_conn_rbtree_insert_value);
    
    /* Create dedicated memory label identifiers for explicit debug profiling outputs */
    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z", &shm_zone->shm.name);
    return NGX_OK;
}

/* Static fallback placeholder variable logic matching custom metric definitions */
static ngx_int_t
ngx_http_limit_conn_header_status_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1; return NGX_OK;
}

/* Configuration memory allocator handling startup definitions */
static void *
ngx_http_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_conn_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_conf_t));
    if (conf == NULL) return NULL;
    conf->log_level = NGX_CONF_UNSET_UINT; conf->status_code = NGX_CONF_UNSET_UINT; conf->dry_run = NGX_CONF_UNSET;
    return conf;
}

/* Config block merge operations inheriting parent contexts into lower scoped server/locations variables */
static char *
ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_conn_conf_t *prev = parent;
    ngx_http_limit_conn_conf_t *conf = child;
    if (conf->limits.elts == NULL) conf->limits = prev->limits;
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code, 503);
    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);
    return NGX_CONF_OK;
}

/* Custom validation command string parser interpreting "limit_conn_by_header_zone" parameters */
static char *
ngx_http_limit_conn_header_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_limit_conn_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_ctx_t));
    ngx_http_compile_complex_value_t ccv;
    ngx_str_t name, size_str;
    ssize_t size;
    
    if (ctx == NULL) return NGX_CONF_ERROR;

    /* Parse and compile dynamic context variable targets */
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf; ccv.value = &value[1]; ccv.complex_value = &ctx->key;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    
    /* Standard parsing extracting zone variable identities and assigned limits footprints */
    u_char *p = (u_char *) ngx_strchr(value[2].data, '=');
    if (p == NULL) return "invalid zone parameter";
    name.data = p + 1;
    
    p = (u_char *) ngx_strchr(name.data, ':');
    if (p == NULL) return "invalid zone size specification";
    
    name.len = p - name.data;
    size_str.data = p + 1;
    size_str.len = value[2].data + value[2].len - size_str.data;
    
    /* Convert human readable size strings (e.g., 10m) to byte counters */
    size = ngx_parse_size(&size_str);
    if (size == NGX_ERROR) return "invalid zone size";

    /* Register and hook shared space boundary directly into NGINX kernel stack structures */
    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_limit_conn_header_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;
    
    shm_zone->init = ngx_http_limit_conn_init_zone;
    shm_zone->data = ctx;
    return NGX_CONF_OK;
}

/* Parser routine evaluating limit policy boundaries on directive "limit_conn_by_header" */
static char *
ngx_http_limit_conn_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_conn_conf_t *lccf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_limit_conn_limit_t *limit;
    ngx_int_t                   value_conn;

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_limit_conn_header_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;

    if (lccf->limits.elts == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1, sizeof(ngx_http_limit_conn_limit_t)) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) return NGX_CONF_ERROR;

    /* Extract integer concurrent upper boundaries limit */
    value_conn = ngx_atoi(value[2].data, value[2].len);
    if (value_conn == NGX_ERROR || value_conn == 0) return "invalid connections value";

    limit->conn = (ngx_uint_t) value_conn;
    limit->shm_zone = shm_zone;
    return NGX_CONF_OK;
}

/* Expose module internal telemetry trackers out to standard NGINX global lookup dictionary logs */
static ngx_int_t
ngx_http_limit_conn_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v;
    for (v = limit_conn_header_status_vars; v->name.len; v++) {
        ngx_http_add_variable(cf, &v->name, v->flags)->get_handler = v->get_handler;
    }
    return NGX_OK;
}

/* Setup routine attaching the interceptor handler straight into the PREACCESS runtime pipeline hook array */
static ngx_int_t
ngx_http_limit_conn_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_limit_conn_header_handler;
    return NGX_OK;
}