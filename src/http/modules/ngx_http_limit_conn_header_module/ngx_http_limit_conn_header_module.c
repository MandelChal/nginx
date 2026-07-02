#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Node structure stored in the shared memory Red-Black tree for each unique key (client) */
typedef struct {
    u_char                          color;     // Node color in the Rbtree (Red/Black) for balancing
    u_char                          len;       // Length of the custom header key string
    u_short                         conn;      // Active concurrent connection counter for this key
    u_char                          data[1];   // Flexible array member storing the actual key string
} ngx_http_limit_conn_node_t;

/* Structure passed to the pool cleanup handler when a connection is closed */
typedef struct {
    ngx_shm_zone_t                 *shm_zone;  // Pointer to the shared memory zone
    ngx_rbtree_node_t              *node;      // Pointer to the specific Rbtree node to decrement/delete
} ngx_http_limit_conn_cleanup_t;

/* Shared memory context containing the Red-Black tree and its sentinel node */
typedef struct {
    ngx_rbtree_t                    rbtree;    // The Rbtree structure for fast node lookups
    ngx_rbtree_node_t               sentinel;  // Boundary (leaf) node for the Rbtree
} ngx_http_limit_conn_shctx_t;

/* Module context tying together the shared state, memory allocation pool, and the key expression */
typedef struct {
    ngx_http_limit_conn_shctx_t    *sh;        // Pointer to the shared memory tree state
    ngx_slab_pool_t                *shpool;    // Slab allocator pool for dynamic shared memory allocations
    ngx_http_complex_value_t        key;       // Compiled evaluation expression (e.g., the Header)
} ngx_http_limit_conn_ctx_t;

/* Structure defining a specific limit rule (zone mapping and max allowed connections) */
typedef struct {
    ngx_shm_zone_t                 *shm_zone;  // Associated shared memory zone
    ngx_uint_t                      conn;      // Maximum allowed concurrent connections
} ngx_http_limit_conn_limit_t;

/* Location/Server configuration block structure holding all module directives */
typedef struct {
    ngx_array_t                     limits;    // Array of ngx_http_limit_conn_limit_t rules
    ngx_uint_t                      log_level; // Log level to use when a connection is rejected
    ngx_uint_t                      status_code;// HTTP status code returned on rejection (e.g., 503)
    ngx_flag_t                      dry_run;   // Flag to log connection limit breaches without blocking
} ngx_http_limit_conn_conf_t;

/* Forward declarations of internal functions */
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

/* Mapping string configurations in nginx.conf to Nginx internal log levels */
static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};

/* Boundaries ensuring the configured HTTP status code falls within standard error ranges */
static ngx_conf_num_bounds_t  ngx_http_limit_conn_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};

/* Array defining the module's directives available in nginx.conf */
static ngx_command_t  ngx_http_limit_conn_header_commands[] = {
    // Defines the tracking zone and key: limit_conn_by_header_zone
    { ngx_string("limit_conn_by_header_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_header_zone,
      0, 0, NULL },
    // Activates connection limiting in a block: limit_conn_by_header
    { ngx_string("limit_conn_by_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_header,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    // Sets custom log level on breach
    { ngx_string("limit_conn_header_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, log_level),
      &ngx_http_limit_conn_log_levels },
    // Sets custom HTTP status code on breach
    { ngx_string("limit_conn_header_status_code"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, status_code),
      &ngx_http_limit_conn_status_bounds },
    // Toggles dry run mode
    { ngx_string("limit_conn_header_dry_run"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, dry_run),
      NULL },
      ngx_null_command
};

/* Module context registration callbacks (config creation, merging, variables) */
static ngx_http_module_t  ngx_http_limit_conn_module_ctx = {
    ngx_http_limit_conn_add_variables, ngx_http_limit_conn_init,
    NULL, NULL, NULL, NULL,
    ngx_http_limit_conn_create_conf, ngx_http_limit_conn_merge_conf
};

/* Primary definition registering this module into Nginx core architecture */
ngx_module_t  ngx_http_limit_conn_header_module = {
    NGX_MODULE_V1, &ngx_http_limit_conn_module_ctx,
    ngx_http_limit_conn_header_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

/* Module variables declared and exposed to the broader Nginx ecosystem */
static ngx_http_variable_t  limit_conn_header_status_vars[] = {
    { ngx_string("limit_conn_header_status"), NULL,
      ngx_http_limit_conn_header_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
      ngx_http_null_variable
};

/* The main HTTP phase handler executing tracking and enforcement checks per request */
static ngx_int_t
ngx_http_limit_conn_header_handler(ngx_http_request_t *r)
{
    size_t n; uint32_t hash; ngx_str_t key;
    ngx_uint_t i;
    ngx_rbtree_node_t *node; ngx_pool_cleanup_t *cln;
    ngx_http_limit_conn_ctx_t *ctx; ngx_http_limit_conn_node_t *lc;
    ngx_http_limit_conn_conf_t *lccf; ngx_http_limit_conn_limit_t *limits;
    ngx_http_limit_conn_cleanup_t *lccln;

    // Custom debug statement logging execution start
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Handler started!");

    // Ignore Nginx internal subrequests to only intercept main browser requests
    if (r->main->count > 1 && r != r->main) {
        return NGX_DECLINED;
    }
    if (r != r->main) {
    return NGX_DECLINED;
}
    
    // Extract module configurations applied to the current processing Location block
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_limit_conn_header_module);
    if (lccf->limits.elts == NULL) return NGX_DECLINED; // Pass if no limit rules exist here
    limits = lccf->limits.elts;

    // Loop through each tracking zone assigned to this location configuration
    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;
        
        // Dynamic evaluation to parse and resolve the key (e.g. Header value)
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // Catch edge case: Key evaluates to empty string (Client omitted required tracking header)
        if (key.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                          "MICHAL_LOG: Missing identity header! Applying Fallback Deny.");
            return lccf->status_code; // Abort processing and deny connection with configured error code
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Processing request for key: [%V]", &key);
        
        // Calculate hash from the header value to look it up inside the Rbtree structure
        hash = ngx_crc32_short(key.data, key.len);
        
        // Multi-process safety lock: acquiring shared memory mutex lock
        ngx_shmtx_lock(&ctx->shpool->mutex);
        
        // Check if this specific key already exists inside the Red-Black lookup tree
        node = ngx_http_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);
        if (node == NULL) {
            /* KEY DOES NOT EXIST -> Brand new connection from this client */
            n = offsetof(ngx_rbtree_node_t, color) + offsetof(ngx_http_limit_conn_node_t, data) + key.len;
            node = ngx_slab_alloc_locked(ctx->shpool, n); // Allocate space out of locked Slab pool
            if (node == NULL) { 
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return lccf->status_code; // If shared memory space is saturated, block connection
            }
            
            // Populate data fields within the newly instantiated node
            lc = (ngx_http_limit_conn_node_t *) &node->color;
            node->key = hash; lc->len = (u_char) key.len; lc->conn = 1; // Initialize tracking count to 1
            ngx_memcpy(lc->data, key.data, key.len); // Copy literal string key
            ngx_rbtree_insert(&ctx->sh->rbtree, node); // Add new node into the active Rbtree structure
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] is NEW. Connection allowed. Count: %ui", &key, lc->conn);
        } else {
            /* KEY EXISTS -> Client has ongoing parallel connection states */
            lc = (ngx_http_limit_conn_node_t *) &node->color;
            
            // Check if current tracked value matches or exceeds maximum allowed configurations
            if ((ngx_uint_t) lc->conn >= limits[i].conn) { 
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] EXCEEDED limit! Blocking request. Current: %ui, Max Allowed: %ui", &key, (ngx_uint_t) lc->conn, limits[i].conn);
                ngx_shmtx_unlock(&ctx->shpool->mutex); // Release shm lock
                return lccf->status_code; // Enforce limit: drop connection by returning error code
            }
            
            // Limit is clear: safely increment counter tracking this customer
            lc->conn++;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MICHAL_LOG: Key [%V] exists. Conn count incremented to: %d", &key, lc->conn);
        }

        // Request a pool cleanup tracker hooks into Nginx system socket teardown process
cln = ngx_pool_cleanup_add(r->connection->pool, sizeof(ngx_http_limit_conn_cleanup_t));
        if (cln == NULL) {
            lc->conn--; // Rollback counter state if internal pool allocations fail
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // Attach hook bindings to decrement/cleanup tracker nodes when connection cuts out
        cln->handler = ngx_http_limit_conn_cleanup;
        lccln = cln->data; 
        lccln->shm_zone = limits[i].shm_zone; 
        lccln->node = node;
        ngx_shmtx_unlock(&ctx->shpool->mutex); // Safely unlock shared memory zone
    }
    return NGX_DECLINED; // Connection permitted: allow execution chain to proceed to core handlers
}

/* Red-Black tree node insertion worker providing string balance and sorting logic */
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
            // Handle Hash collisions by checking actual string values byte-by-byte
            lcn = (ngx_http_limit_conn_node_t *) &node->color;
            lcnt = (ngx_http_limit_conn_node_t *) &temp->color;
            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0) ? &temp->left : &temp->right;
        }
        if (*p == sentinel) break;
        temp = *p;
    }
    // Bind node to tree structures and color it Red following standard Rbtree algorithms
    *p = node; node->parent = temp; node->left = sentinel; node->right = sentinel; ngx_rbt_red(node);
}

/* Core lookup worker traversing the Rbtree to match keys using precalculated hash values */
static ngx_rbtree_node_t *
ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t rc; ngx_rbtree_node_t *node, *sentinel; ngx_http_limit_conn_node_t *lcn;
    node = rbtree->root; sentinel = rbtree->sentinel;
    while (node != sentinel) {
        if (hash < node->key) { node = node->left; continue; }
        if (hash > node->key) { node = node->right; continue; }
        
        // Exact string verification step to handle hash collisions smoothly
        lcn = (ngx_http_limit_conn_node_t *) &node->color;
        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);
        if (rc == 0) return node; // Key found!
        node = (rc < 0) ? node->left : node->right;
    }
    return NULL; // Key not present in the lookup map
}

/* Cleanup function auto-invoked by Nginx when a tracking client connection fully terminates */
static void
ngx_http_limit_conn_cleanup(void *data)
{
    ngx_http_limit_conn_cleanup_t *lccln = data;
    ngx_http_limit_conn_ctx_t *ctx; ngx_http_limit_conn_node_t *lc;
    ctx = lccln->shm_zone->data; 
    lc = (ngx_http_limit_conn_node_t *) &lccln->node->color;
    
    // Safely lock shared memory zone to decrement states across process workers
    ngx_shmtx_lock(&ctx->shpool->mutex);
    lc->conn--; // Decrement active connection counter for this specific identity key
    
    // If client has zero active requests, erase node from tree and free shared memory
    if (lc->conn == 0) { 
        ngx_rbtree_delete(&ctx->sh->rbtree, lccln->node); 
        ngx_slab_free_locked(ctx->shpool, lccln->node);
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex); // Release shared lock
}

/* Initializer allocating structure headers inside shared memory space on Nginx startup/reload */
static ngx_int_t
ngx_http_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_conn_ctx_t *octx = data; size_t len;
    ngx_http_limit_conn_ctx_t *ctx = shm_zone->data;
    if (octx) { ctx->sh = octx->sh; ctx->shpool = octx->shpool; return NGX_OK; }
    
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_conn_shctx_t));
    if (ctx->sh == NULL) return NGX_ERROR;
    
    ctx->shpool->data = ctx->sh;
    // Instantiate tree elements with custom string insert sorting algorithm
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel, ngx_http_limit_conn_rbtree_insert_value);
    
    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z", &shm_zone->shm.name);
    return NGX_OK;
}

/* Status evaluation mapping for the internal variables */
static ngx_int_t
ngx_http_limit_conn_header_status_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1; return NGX_OK;
}

/* Instantiates empty raw configurations struct and falls back default data fields as unset */
static void *
ngx_http_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_conn_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_conf_t));
    if (conf == NULL) return NULL;
    conf->log_level = NGX_CONF_UNSET_UINT; conf->status_code = NGX_CONF_UNSET_UINT; conf->dry_run = NGX_CONF_UNSET;
    return conf;
}

/* Inherits and merges configurations across Main, Server, and Location cascading levels */
static char *
ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_conn_conf_t *prev = parent;
    ngx_http_limit_conn_conf_t *conf = child;
    if (conf->limits.elts == NULL) conf->limits = prev->limits;
    // Apply standard fallback values if left explicitly unconfigured (Error level & status 503)
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code, 503);
    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);
    return NGX_CONF_OK;
}

/* Directive parsing handler executing limit_conn_by_header_zone definitions */
static char *
ngx_http_limit_conn_header_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_limit_conn_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_ctx_t));
    ngx_http_compile_complex_value_t ccv;
    ngx_str_t name, size_str;
    ssize_t size;
    
    if (ctx == NULL) return NGX_CONF_ERROR;

    // Compiles variable expression arguments for fast string runtime lookup evaluations
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf; ccv.value = &value[1]; ccv.complex_value = &ctx->key;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    
    // Parse arguments strings specifying zone layout profiles (e.g. zone=name:size)
    u_char *p = (u_char *) ngx_strchr(value[2].data, '=');
    if (p == NULL) return "invalid zone parameter";
    name.data = p + 1;
    
    p = (u_char *) ngx_strchr(name.data, ':');
    if (p == NULL) return "invalid zone size specification";
    
    name.len = p - name.data;
    size_str.data = p + 1;
    size_str.len = value[2].data + value[2].len - size_str.data;
    
    size = ngx_parse_size(&size_str); // Convert size units (e.g. 10m) to byte totals
    if (size == NGX_ERROR) return "invalid zone size";

    // Allocate and register the tracking shared memory zone with Nginx core
    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_limit_conn_header_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;
    
    shm_zone->init = ngx_http_limit_conn_init_zone;
    shm_zone->data = ctx;
    return NGX_CONF_OK;
}

/* Directive handler extracting and registering limit_conn_by_header rule metrics */
static char *
ngx_http_limit_conn_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_conn_conf_t *lccf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_limit_conn_limit_t *limit;
    ngx_int_t                   value_conn;

    // Fetch the target shared memory zone by its name string
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_limit_conn_header_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;

    if (lccf->limits.elts == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1, sizeof(ngx_http_limit_conn_limit_t)) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) return NGX_CONF_ERROR;

    // Convert string connection limit value to integer data type
    value_conn = ngx_atoi(value[2].data, value[2].len);
    if (value_conn == NGX_ERROR || value_conn == 0) return "invalid connections value";

    limit->conn = (ngx_uint_t) value_conn;
    limit->shm_zone = shm_zone;
    return NGX_CONF_OK;
}

/* Appends module custom variables to the central runtime engine of Nginx */
static ngx_int_t
ngx_http_limit_conn_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v;
    for (v = limit_conn_header_status_vars; v->name.len; v++) {
        ngx_http_add_variable(cf, &v->name, v->flags)->get_handler = v->get_handler;
    }
    return NGX_OK;
}

/* System entry initializations: registers our handler callback hook into HTTP PREACCESS phase */
static ngx_int_t
ngx_http_limit_conn_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    // Inject module intercept handler inside PREACCESS phase execution array
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_limit_conn_header_handler; // Assign module logic callback
    return NGX_OK;
}