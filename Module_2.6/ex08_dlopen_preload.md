# ex08: dlopen & LD_PRELOAD

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.16: Dynamic Loading (dlopen) (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | dlopen() | Load library at runtime |
| b | RTLD_LAZY | Lazy binding |
| c | RTLD_NOW | Immediate binding |
| d | RTLD_GLOBAL | Export symbols |
| e | RTLD_LOCAL | Don't export |
| f | dlsym() | Find symbol |
| g | RTLD_DEFAULT | Search all |
| h | RTLD_NEXT | Next occurrence |
| i | dlclose() | Unload library |
| j | dlerror() | Get error message |
| k | Plugin systems | Common use case |

### 2.6.17: LD_PRELOAD (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | LD_PRELOAD | Load before others |
| b | Symbol interposition | Override functions |
| c | Wrapping | Intercept calls |
| d | RTLD_NEXT | Call original |
| e | Use cases | Debugging, tracing |
| f | Security | setuid ignores |
| g | Example | Wrap malloc |

---

## Sujet

Maitriser le chargement dynamique et l'interposition de symboles.

### Structures

```c
#include <dlfcn.h>

// 2.6.16.k: Plugin interface
typedef struct {
    const char *name;
    const char *version;
    int (*init)(void);
    void (*cleanup)(void);
    void *(*get_interface)(const char *name);
} plugin_info_t;

// Plugin handle
typedef struct {
    void *handle;            // dlopen handle
    char *path;
    plugin_info_t *info;
    bool loaded;
} plugin_t;

// Plugin manager
typedef struct {
    plugin_t *plugins;
    int plugin_count;
    int capacity;
    char *search_path;
} plugin_manager_t;

// 2.6.17: Interposition wrapper
typedef struct {
    const char *function;
    void *wrapper;           // Our wrapper function
    void *original;          // d: Via RTLD_NEXT
    int call_count;
    double total_time_ns;
} interposition_t;
```

### API

```c
// ============== DLOPEN API ==============
// 2.6.16

// 2.6.16.a-e: Enhanced dlopen wrapper
typedef struct {
    bool lazy;               // b: RTLD_LAZY
    bool now;                // c: RTLD_NOW
    bool global;             // d: RTLD_GLOBAL
    bool local;              // e: RTLD_LOCAL
    bool noload;             // RTLD_NOLOAD
    bool nodelete;           // RTLD_NODELETE
    bool deepbind;           // RTLD_DEEPBIND
} dlopen_flags_t;

void *my_dlopen(const char *path, const dlopen_flags_t *flags);
int my_dlclose(void *handle);

// 2.6.16.f-h: Symbol lookup
void *my_dlsym(void *handle, const char *symbol);
void *dlsym_default(const char *symbol);   // g: RTLD_DEFAULT
void *dlsym_next(const char *symbol);      // h: RTLD_NEXT

// 2.6.16.j: Error handling
const char *my_dlerror(void);

// Get library info from handle
int dlinfo_get_name(void *handle, char **name);
int dlinfo_get_base(void *handle, void **base);

// ============== PLUGIN SYSTEM ==============
// 2.6.16.k

// Initialize plugin manager
int plugin_manager_init(plugin_manager_t *pm, const char *search_path);
void plugin_manager_cleanup(plugin_manager_t *pm);

// Load/unload plugins
int plugin_load(plugin_manager_t *pm, const char *name);
int plugin_unload(plugin_manager_t *pm, const char *name);

// Find plugin
plugin_t *plugin_find(plugin_manager_t *pm, const char *name);

// Call plugin function
void *plugin_call(plugin_t *plugin, const char *function, ...);

// List available plugins
int plugin_discover(const char *directory, char ***names, int *count);

// ============== LD_PRELOAD ==============
// 2.6.17

// 2.6.17.a: Set up preload
int preload_set(const char *library);
int preload_get(char ***libraries, int *count);
int preload_clear(void);

// 2.6.17.b-d: Create wrapper library
typedef struct {
    const char *original_function;
    const char *wrapper_code;
    bool call_original;      // d: Use RTLD_NEXT
    bool trace_calls;        // e: For debugging
} wrapper_spec_t;

int generate_preload_library(const wrapper_spec_t *specs, int count,
                             const char *output_path);

// 2.6.17.e: Built-in tracers
int trace_malloc(void);      // Track allocations
int trace_file_ops(void);    // Track open/read/write
int trace_network(void);     // Track socket operations

// 2.6.17.g: Common wrappers
// These are designed to be compiled into preload libraries:
// - malloc_wrapper: Track memory usage
// - time_wrapper: Speed up time-based operations
// - random_wrapper: Make random deterministic

// ============== INTERPOSITION ==============

// Register interposition
int interpose_register(const char *function, void *wrapper);

// Get original function
void *interpose_get_original(const char *function);

// Statistics
void interpose_print_stats(void);
```

---

## Exemple

```c
#include "dlopen_preload.h"

// ============== PLUGIN EXAMPLE ==============
// Example plugin: plugins/hello.so

// In plugins/hello.c:
/*
plugin_info_t plugin_info = {
    .name = "hello",
    .version = "1.0",
    .init = hello_init,
    .cleanup = hello_cleanup,
    .get_interface = hello_get_interface,
};

int hello_init(void) {
    printf("Hello plugin initialized!\n");
    return 0;
}

void say_hello(const char *name) {
    printf("Hello, %s!\n", name);
}
*/

void demo_dlopen(void) {
    printf("=== dlopen API ===\n");

    // 2.6.16.a: Load library
    void *handle = dlopen("./libexample.so", RTLD_LAZY);
    if (!handle) {
        printf("Error: %s\n", dlerror());  // j
        return;
    }
    printf("Library loaded successfully\n");

    // 2.6.16.f: Find symbol
    typedef int (*add_fn)(int, int);
    add_fn add = (add_fn)dlsym(handle, "add");

    char *error = dlerror();  // j: Clear/check error
    if (error) {
        printf("Symbol error: %s\n", error);
    } else {
        printf("add(2, 3) = %d\n", add(2, 3));
    }

    // 2.6.16.b-c: Lazy vs Now
    printf("\n=== RTLD_LAZY vs RTLD_NOW ===\n");
    printf("RTLD_LAZY (b): Symbols resolved on first use\n");
    printf("  - Faster load time\n");
    printf("  - Errors delayed until symbol access\n");

    printf("\nRTLD_NOW (c): All symbols resolved immediately\n");
    printf("  - Slower load time\n");
    printf("  - Errors detected at dlopen\n");

    // 2.6.16.d-e: Global vs Local
    printf("\n=== RTLD_GLOBAL vs RTLD_LOCAL ===\n");

    // RTLD_GLOBAL: Symbols available to other libraries
    void *h1 = dlopen("./libbase.so", RTLD_NOW | RTLD_GLOBAL);

    // RTLD_LOCAL: Symbols only available to this handle
    void *h2 = dlopen("./libprivate.so", RTLD_NOW | RTLD_LOCAL);

    printf("RTLD_GLOBAL (d): Symbols exported to dependency resolution\n");
    printf("RTLD_LOCAL (e): Symbols hidden from other libraries\n");

    // 2.6.16.g-h: Special handles
    printf("\n=== Special Handles ===\n");

    // g: RTLD_DEFAULT - search all loaded libraries
    void *printf_addr = dlsym(RTLD_DEFAULT, "printf");
    printf("printf via RTLD_DEFAULT: %p\n", printf_addr);

    // h: RTLD_NEXT - next occurrence (for wrapping)
    // Only works from within a shared library

    // 2.6.16.i: Unload
    dlclose(handle);
    dlclose(h1);
    dlclose(h2);
    printf("\nLibraries unloaded\n");
}

void demo_plugin_system(void) {
    printf("\n=== Plugin System (k) ===\n");

    plugin_manager_t pm;
    plugin_manager_init(&pm, "./plugins");

    // Discover plugins
    char **available;
    int count;
    plugin_discover("./plugins", &available, &count);
    printf("Found %d plugins:\n", count);
    for (int i = 0; i < count; i++) {
        printf("  - %s\n", available[i]);
    }

    // Load a plugin
    if (plugin_load(&pm, "hello") == 0) {
        plugin_t *hello = plugin_find(&pm, "hello");
        printf("\nLoaded: %s v%s\n",
               hello->info->name, hello->info->version);

        // Call plugin function
        typedef void (*say_hello_fn)(const char *);
        say_hello_fn say_hello = dlsym(hello->handle, "say_hello");
        if (say_hello) {
            say_hello("World");
        }

        plugin_unload(&pm, "hello");
    }

    plugin_manager_cleanup(&pm);
}

void demo_ld_preload(void) {
    printf("\n=== LD_PRELOAD ===\n");

    // 2.6.17.a: How LD_PRELOAD works
    printf("\nLD_PRELOAD loads libraries before others (a)\n");
    printf("  export LD_PRELOAD=./mywrapper.so\n");
    printf("  ./program\n");

    // 2.6.17.b-c: Symbol interposition
    printf("\n=== Symbol Interposition (b-c) ===\n");
    printf("Wrapper functions override library functions\n");

    // 2.6.17.g: Example malloc wrapper
    printf("\nExample: malloc wrapper\n");
    printf("---\n");
    printf("#define _GNU_SOURCE\n");
    printf("#include <dlfcn.h>\n");
    printf("#include <stdio.h>\n");
    printf("\n");
    printf("static void *(*real_malloc)(size_t) = NULL;\n");
    printf("static size_t total_allocated = 0;\n");
    printf("\n");
    printf("void *malloc(size_t size) {\n");
    printf("    // 2.6.17.d: Get original function\n");
    printf("    if (!real_malloc) {\n");
    printf("        real_malloc = dlsym(RTLD_NEXT, \"malloc\");\n");
    printf("    }\n");
    printf("    \n");
    printf("    // 2.6.17.c: Wrap the call\n");
    printf("    void *ptr = real_malloc(size);\n");
    printf("    total_allocated += size;\n");
    printf("    fprintf(stderr, \"malloc(%%zu) = %%p (total: %%zu)\\n\",\n");
    printf("            size, ptr, total_allocated);\n");
    printf("    return ptr;\n");
    printf("}\n");
    printf("---\n");

    // 2.6.17.e: Use cases
    printf("\n=== Use Cases (e) ===\n");
    printf("1. Memory debugging (track leaks)\n");
    printf("2. Performance profiling (time functions)\n");
    printf("3. Testing (mock functions)\n");
    printf("4. Logging (trace API calls)\n");
    printf("5. Security (audit operations)\n");

    // 2.6.17.f: Security
    printf("\n=== Security (f) ===\n");
    printf("LD_PRELOAD is IGNORED for:\n");
    printf("  - setuid/setgid programs\n");
    printf("  - Programs with capabilities\n");
    printf("This prevents privilege escalation attacks\n");

    // Generate preload library
    printf("\n=== Generate Preload Library ===\n");
    wrapper_spec_t specs[] = {
        {
            .original_function = "malloc",
            .call_original = true,
            .trace_calls = true,
        },
        {
            .original_function = "free",
            .call_original = true,
            .trace_calls = true,
        },
    };
    generate_preload_library(specs, 2, "./memtrace.so");
    printf("Generated memtrace.so\n");
    printf("Usage: LD_PRELOAD=./memtrace.so ./program\n");
}

void demo_practical_wrapper(void) {
    printf("\n=== Practical Example: Time Wrapper ===\n");

    printf("\n// Speed up sleep() for testing:\n");
    printf("unsigned int sleep(unsigned int seconds) {\n");
    printf("    static unsigned int (*real_sleep)(unsigned int) = NULL;\n");
    printf("    if (!real_sleep) real_sleep = dlsym(RTLD_NEXT, \"sleep\");\n");
    printf("    \n");
    printf("    // Sleep 1000x faster\n");
    printf("    return real_sleep(seconds / 1000 + 1);\n");
    printf("}\n");

    printf("\n=== Practical Example: File Redirect ===\n");
    printf("\n// Redirect file opens:\n");
    printf("int open(const char *path, int flags, ...) {\n");
    printf("    if (strcmp(path, \"/etc/passwd\") == 0) {\n");
    printf("        path = \"./fake_passwd\";  // Redirect!\n");
    printf("    }\n");
    printf("    // Call real open...\n");
    printf("}\n");
}

int main(int argc, char *argv[]) {
    demo_dlopen();
    demo_plugin_system();
    demo_ld_preload();
    demo_practical_wrapper();
    return 0;
}
```

---

## Tests Moulinette

```rust
// dlopen
#[test] fn test_dlopen_basic()          // 2.6.16.a
#[test] fn test_rtld_lazy()             // 2.6.16.b
#[test] fn test_rtld_now()              // 2.6.16.c
#[test] fn test_rtld_global_local()     // 2.6.16.d-e
#[test] fn test_dlsym()                 // 2.6.16.f
#[test] fn test_rtld_default()          // 2.6.16.g
#[test] fn test_rtld_next()             // 2.6.16.h
#[test] fn test_dlclose()               // 2.6.16.i
#[test] fn test_dlerror()               // 2.6.16.j
#[test] fn test_plugin_system()         // 2.6.16.k

// LD_PRELOAD
#[test] fn test_preload_basic()         // 2.6.17.a
#[test] fn test_interposition()         // 2.6.17.b-c
#[test] fn test_rtld_next_wrapper()     // 2.6.17.d
#[test] fn test_security_restrictions() // 2.6.17.f
```

---

## Bareme

| Critere | Points |
|---------|--------|
| dlopen/dlclose (2.6.16.a,i) | 15 |
| Flags (2.6.16.b-e) | 20 |
| dlsym (2.6.16.f-h) | 20 |
| Plugin system (2.6.16.j-k) | 15 |
| LD_PRELOAD (2.6.17.a-d) | 20 |
| Security & use cases (2.6.17.e-g) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex08/
├── dlopen_preload.h
├── dlopen.c
├── plugin_manager.c
├── preload.c
├── wrappers.c
├── plugins/
│   └── hello.c
└── Makefile
```
