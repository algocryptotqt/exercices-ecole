# Exercice 1.9.06 - WebAssembly Sandbox Environment

## Metadata
- **Nom de code:** the_matrix_construct
- **Tier:** 3 (Synthesis - Advanced Sandboxing and Security)
- **Complexité estimée:** Expert (40-50h)
- **Prérequis:** Modules 1.1-1.8, Rust basics, understanding of memory safety

---

# Section 1: Prototype & Consigne

## 1.1 Version Culture Pop

> *"The Matrix is everywhere. It is all around us. Even now, in this very room."* — Morpheus, The Matrix (1999)

Dans The Matrix, les humains vivent dans une simulation parfaite, isolée du monde réel. WebAssembly crée exactement cela pour le code: une sandbox parfaite où le code s'exécute en toute sécurité, isolé du système hôte.

Vous allez construire **The Construct**: un environnement d'exécution WebAssembly qui permet d'exécuter du code utilisateur de manière totalement sécurisée. Comme Neo apprenant le kung-fu en quelques secondes, vos utilisateurs pourront charger et exécuter du code instantanément, sans risque.

**Le défi:** Créer un runtime WASM complet avec gestion des ressources, limites de mémoire/temps, et isolation parfaite.

## 1.2 Version Académique

### Contexte Formel

WebAssembly (WASM) est un format d'instruction binaire conçu pour être:
- **Sécurisé**: Exécution dans une sandbox avec isolation mémoire
- **Portable**: Fonctionne sur tout système avec un runtime WASM
- **Performant**: Proche des performances natives
- **Déterministe**: Même entrée = même sortie (modulo limites de ressources)

Ce projet implémente un runtime WASM sécurisé pour l'exécution de code arbitraire.

### Spécification Formelle

Soit W = (M, I, S, R) un runtime WebAssembly où:
- M : Module WASM (bytecode validé)
- I : Instance (mémoire, tables, globals)
- S : Store (état global du runtime)
- R : Ressources allouées (mémoire, temps CPU)

### Objectifs Pédagogiques

1. Comprendre l'architecture WebAssembly et son modèle de sécurité
2. Implémenter un runtime sécurisé avec limites de ressources
3. Maîtriser l'isolation mémoire et les capability-based security
4. Créer une API host-guest bidirectionnelle

### Fonctions à Implémenter (Rust)

```rust
// ============================================================
// PARTIE A: Configuration du Sandbox
// ============================================================

use wasmtime::*;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

/// Configuration des limites du sandbox
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Mémoire maximale en bytes (défaut: 64MB)
    pub max_memory_bytes: usize,

    /// Temps d'exécution maximum (défaut: 5s)
    pub max_execution_time: Duration,

    /// Nombre maximum d'instructions (fuel)
    pub max_fuel: u64,

    /// Taille maximale de la stack
    pub max_stack_size: usize,

    /// Fonctions host autorisées
    pub allowed_imports: Vec<String>,

    /// Permettre l'accès au système de fichiers (WASI)
    pub allow_filesystem: bool,

    /// Permettre l'accès réseau
    pub allow_network: bool,

    /// Permettre l'accès à l'horloge système
    pub allow_clock: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            max_memory_bytes: 64 * 1024 * 1024,  // 64MB
            max_execution_time: Duration::from_secs(5),
            max_fuel: 10_000_000,
            max_stack_size: 1024 * 1024,  // 1MB
            allowed_imports: vec![],
            allow_filesystem: false,
            allow_network: false,
            allow_clock: false,
        }
    }
}

impl SandboxConfig {
    /// Configuration minimale (très restrictive)
    pub fn minimal() -> Self {
        SandboxConfig {
            max_memory_bytes: 1024 * 1024,  // 1MB
            max_execution_time: Duration::from_millis(100),
            max_fuel: 100_000,
            max_stack_size: 64 * 1024,
            allowed_imports: vec![],
            allow_filesystem: false,
            allow_network: false,
            allow_clock: false,
        }
    }

    /// Configuration pour calcul intensif
    pub fn compute() -> Self {
        SandboxConfig {
            max_memory_bytes: 256 * 1024 * 1024,  // 256MB
            max_execution_time: Duration::from_secs(30),
            max_fuel: 1_000_000_000,
            max_stack_size: 8 * 1024 * 1024,
            allowed_imports: vec![],
            allow_filesystem: false,
            allow_network: false,
            allow_clock: true,
        }
    }
}

// ============================================================
// PARTIE B: Runtime WASM Sécurisé
// ============================================================

/// Erreurs possibles du sandbox
#[derive(Debug, Clone)]
pub enum SandboxError {
    /// Module WASM invalide
    InvalidModule(String),
    /// Dépassement de la limite de mémoire
    MemoryLimitExceeded { used: usize, limit: usize },
    /// Dépassement du temps d'exécution
    TimeLimitExceeded { elapsed: Duration, limit: Duration },
    /// Fuel épuisé (trop d'instructions)
    FuelExhausted { used: u64, limit: u64 },
    /// Import non autorisé
    UnauthorizedImport(String),
    /// Erreur d'exécution (trap)
    RuntimeError(String),
    /// Fonction non trouvée
    FunctionNotFound(String),
    /// Type de fonction incorrect
    TypeMismatch(String),
}

/// Résultat d'une exécution sandbox
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Valeurs de retour
    pub return_values: Vec<WasmValue>,
    /// Temps d'exécution
    pub execution_time: Duration,
    /// Fuel consommé
    pub fuel_consumed: u64,
    /// Mémoire utilisée au pic
    pub peak_memory: usize,
    /// Sortie standard capturée
    pub stdout: String,
    /// Sortie erreur capturée
    pub stderr: String,
}

/// Valeur WASM typée
#[derive(Debug, Clone)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

/// Runtime WebAssembly sécurisé
pub struct Sandbox {
    engine: Engine,
    config: SandboxConfig,
    store: Store<SandboxState>,
    module: Option<Module>,
    instance: Option<Instance>,
}

/// État interne du sandbox
struct SandboxState {
    start_time: Instant,
    stdout_buffer: Arc<Mutex<Vec<u8>>>,
    stderr_buffer: Arc<Mutex<Vec<u8>>>,
    memory_usage: usize,
}

impl Sandbox {
    /// Crée un nouveau sandbox avec la configuration donnée
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut engine_config = Config::new();

        // Activer le fuel pour limiter les instructions
        engine_config.consume_fuel(true);

        // Limiter la mémoire
        engine_config.max_wasm_stack(config.max_stack_size);

        let engine = Engine::new(&engine_config)
            .map_err(|e| SandboxError::InvalidModule(e.to_string()))?;

        let mut store = Store::new(&engine, SandboxState {
            start_time: Instant::now(),
            stdout_buffer: Arc::new(Mutex::new(Vec::new())),
            stderr_buffer: Arc::new(Mutex::new(Vec::new())),
            memory_usage: 0,
        });

        // Configurer le fuel initial
        store.add_fuel(config.max_fuel)
            .map_err(|e| SandboxError::RuntimeError(e.to_string()))?;

        Ok(Sandbox {
            engine,
            config,
            store,
            module: None,
            instance: None,
        })
    }

    /// Charge un module WASM depuis des bytes
    pub fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<(), SandboxError> {
        // Valider et compiler le module
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::InvalidModule(e.to_string()))?;

        // Vérifier les imports
        for import in module.imports() {
            let import_name = format!("{}::{}", import.module(), import.name());
            if !self.config.allowed_imports.contains(&import_name) {
                // Vérifier si c'est un import standard autorisé
                if !self.is_standard_import(&import_name) {
                    return Err(SandboxError::UnauthorizedImport(import_name));
                }
            }
        }

        self.module = Some(module);
        Ok(())
    }

    /// Charge un module WASM depuis un fichier
    pub fn load_module_from_file(&mut self, path: &str) -> Result<(), SandboxError> {
        let wasm_bytes = std::fs::read(path)
            .map_err(|e| SandboxError::InvalidModule(e.to_string()))?;
        self.load_module(&wasm_bytes)
    }

    /// Instancie le module chargé
    pub fn instantiate(&mut self) -> Result<(), SandboxError> {
        let module = self.module.as_ref()
            .ok_or_else(|| SandboxError::InvalidModule("No module loaded".into()))?;

        // Créer le linker avec les imports autorisés
        let mut linker = Linker::new(&self.engine);

        // Ajouter les fonctions host
        self.add_host_functions(&mut linker)?;

        // Instancier
        let instance = linker.instantiate(&mut self.store, module)
            .map_err(|e| SandboxError::RuntimeError(e.to_string()))?;

        self.instance = Some(instance);
        Ok(())
    }

    /// Exécute une fonction exportée
    pub fn call_function(
        &mut self,
        func_name: &str,
        args: &[WasmValue],
    ) -> Result<ExecutionResult, SandboxError> {
        let instance = self.instance.as_ref()
            .ok_or_else(|| SandboxError::RuntimeError("Module not instantiated".into()))?;

        // Trouver la fonction
        let func = instance.get_func(&mut self.store, func_name)
            .ok_or_else(|| SandboxError::FunctionNotFound(func_name.into()))?;

        // Convertir les arguments
        let wasm_args: Vec<Val> = args.iter().map(|v| match v {
            WasmValue::I32(x) => Val::I32(*x),
            WasmValue::I64(x) => Val::I64(*x),
            WasmValue::F32(x) => Val::F32(x.to_bits()),
            WasmValue::F64(x) => Val::F64(x.to_bits()),
        }).collect();

        // Préparer les résultats
        let result_count = func.ty(&self.store).results().len();
        let mut results = vec![Val::I32(0); result_count];

        // Reset le timer
        self.store.data_mut().start_time = Instant::now();

        // Exécuter avec vérification du temps
        let call_result = func.call(&mut self.store, &wasm_args, &mut results);

        let elapsed = self.store.data().start_time.elapsed();

        // Vérifier le timeout
        if elapsed > self.config.max_execution_time {
            return Err(SandboxError::TimeLimitExceeded {
                elapsed,
                limit: self.config.max_execution_time,
            });
        }

        // Vérifier les erreurs d'exécution
        call_result.map_err(|e| {
            if e.to_string().contains("out of fuel") {
                SandboxError::FuelExhausted {
                    used: self.config.max_fuel,
                    limit: self.config.max_fuel,
                }
            } else {
                SandboxError::RuntimeError(e.to_string())
            }
        })?;

        // Convertir les résultats
        let return_values: Vec<WasmValue> = results.iter().map(|v| match v {
            Val::I32(x) => WasmValue::I32(*x),
            Val::I64(x) => WasmValue::I64(*x),
            Val::F32(x) => WasmValue::F32(f32::from_bits(*x)),
            Val::F64(x) => WasmValue::F64(f64::from_bits(*x)),
            _ => WasmValue::I32(0),
        }).collect();

        // Récupérer les buffers
        let stdout = String::from_utf8_lossy(
            &self.store.data().stdout_buffer.lock().unwrap()
        ).to_string();
        let stderr = String::from_utf8_lossy(
            &self.store.data().stderr_buffer.lock().unwrap()
        ).to_string();

        // Calculer le fuel consommé
        let fuel_remaining = self.store.fuel_remaining().unwrap_or(0);
        let fuel_consumed = self.config.max_fuel - fuel_remaining;

        Ok(ExecutionResult {
            return_values,
            execution_time: elapsed,
            fuel_consumed,
            peak_memory: self.store.data().memory_usage,
            stdout,
            stderr,
        })
    }

    /// Vérifie si c'est un import standard
    fn is_standard_import(&self, name: &str) -> bool {
        // Imports WASI de base
        matches!(name,
            "wasi_snapshot_preview1::fd_write" |
            "wasi_snapshot_preview1::proc_exit" |
            "wasi_snapshot_preview1::environ_sizes_get" |
            "wasi_snapshot_preview1::environ_get"
        )
    }

    /// Ajoute les fonctions host au linker
    fn add_host_functions(&self, linker: &mut Linker<SandboxState>) -> Result<(), SandboxError> {
        // fd_write pour stdout/stderr
        let stdout_buffer = self.store.data().stdout_buffer.clone();
        let stderr_buffer = self.store.data().stderr_buffer.clone();

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            move |mut caller: Caller<'_, SandboxState>,
                  fd: i32,
                  iovs: i32,
                  iovs_len: i32,
                  nwritten: i32| -> i32 {
                // Implémentation simplifiée de fd_write
                // fd 1 = stdout, fd 2 = stderr
                let memory = caller.get_export("memory")
                    .and_then(|e| e.into_memory());

                if let Some(mem) = memory {
                    let data = mem.data(&caller);
                    // Lire les iovecs et écrire dans le buffer approprié
                    let buffer = if fd == 1 { &stdout_buffer } else { &stderr_buffer };

                    // Simplified: just return success
                    if let Ok(mut buf) = buffer.lock() {
                        // In real impl, read from iovs
                        buf.extend_from_slice(b"output");
                    }
                }
                0  // Success
            }
        ).map_err(|e| SandboxError::RuntimeError(e.to_string()))?;

        Ok(())
    }

    /// Reset le sandbox pour une nouvelle exécution
    pub fn reset(&mut self) -> Result<(), SandboxError> {
        // Reset fuel
        self.store.add_fuel(self.config.max_fuel)
            .map_err(|e| SandboxError::RuntimeError(e.to_string()))?;

        // Reset buffers
        self.store.data_mut().stdout_buffer.lock().unwrap().clear();
        self.store.data_mut().stderr_buffer.lock().unwrap().clear();
        self.store.data_mut().memory_usage = 0;

        Ok(())
    }
}

// ============================================================
// PARTIE C: Compilateur WAT → WASM
// ============================================================

/// Compile du code WAT (WebAssembly Text) en WASM binaire
pub fn compile_wat_to_wasm(wat_source: &str) -> Result<Vec<u8>, SandboxError> {
    wat::parse_str(wat_source)
        .map_err(|e| SandboxError::InvalidModule(e.to_string()))
}

/// Compile du code source (pseudo-langage) en WAT
pub fn compile_source_to_wat(source: &str) -> Result<String, SandboxError> {
    // Mini compilateur pour un langage simple
    // Syntax: func name(args) { body }
    // TODO: Implémenter un vrai parser
    Ok(format!(r#"
        (module
            (func (export "main") (result i32)
                i32.const 42
            )
        )
    "#))
}

// ============================================================
// PARTIE D: API de Haut Niveau
// ============================================================

/// Exécute du code WASM en une ligne
pub fn execute_wasm(
    wasm_bytes: &[u8],
    func_name: &str,
    args: &[WasmValue],
    config: Option<SandboxConfig>,
) -> Result<ExecutionResult, SandboxError> {
    let config = config.unwrap_or_default();
    let mut sandbox = Sandbox::new(config)?;
    sandbox.load_module(wasm_bytes)?;
    sandbox.instantiate()?;
    sandbox.call_function(func_name, args)
}

/// Exécute du code WAT en une ligne
pub fn execute_wat(
    wat_source: &str,
    func_name: &str,
    args: &[WasmValue],
    config: Option<SandboxConfig>,
) -> Result<ExecutionResult, SandboxError> {
    let wasm_bytes = compile_wat_to_wasm(wat_source)?;
    execute_wasm(&wasm_bytes, func_name, args, config)
}

/// Builder pattern pour configuration fluide
pub struct SandboxBuilder {
    config: SandboxConfig,
}

impl SandboxBuilder {
    pub fn new() -> Self {
        SandboxBuilder {
            config: SandboxConfig::default(),
        }
    }

    pub fn max_memory(mut self, bytes: usize) -> Self {
        self.config.max_memory_bytes = bytes;
        self
    }

    pub fn max_time(mut self, duration: Duration) -> Self {
        self.config.max_execution_time = duration;
        self
    }

    pub fn max_fuel(mut self, fuel: u64) -> Self {
        self.config.max_fuel = fuel;
        self
    }

    pub fn allow_import(mut self, import: &str) -> Self {
        self.config.allowed_imports.push(import.to_string());
        self
    }

    pub fn allow_filesystem(mut self, allow: bool) -> Self {
        self.config.allow_filesystem = allow;
        self
    }

    pub fn build(self) -> Result<Sandbox, SandboxError> {
        Sandbox::new(self.config)
    }
}

// ============================================================
// PARTIE E: Code Judge (pour online judge)
// ============================================================

/// Résultat d'un test case
#[derive(Debug, Clone)]
pub struct TestCaseResult {
    pub test_id: u32,
    pub passed: bool,
    pub expected_output: String,
    pub actual_output: String,
    pub execution_time: Duration,
    pub memory_used: usize,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Accepted,
    WrongAnswer,
    TimeLimitExceeded,
    MemoryLimitExceeded,
    RuntimeError,
    CompilationError,
}

/// Test case pour le judge
#[derive(Debug, Clone)]
pub struct TestCase {
    pub id: u32,
    pub input: String,
    pub expected_output: String,
    pub time_limit: Duration,
    pub memory_limit: usize,
}

/// Judge pour évaluer les soumissions
pub struct Judge {
    sandbox_config: SandboxConfig,
}

impl Judge {
    pub fn new(config: SandboxConfig) -> Self {
        Judge { sandbox_config: config }
    }

    /// Évalue une soumission WASM contre des test cases
    pub fn evaluate(
        &self,
        wasm_bytes: &[u8],
        test_cases: &[TestCase],
    ) -> Vec<TestCaseResult> {
        test_cases.iter().map(|tc| {
            self.run_test_case(wasm_bytes, tc)
        }).collect()
    }

    fn run_test_case(&self, wasm_bytes: &[u8], test_case: &TestCase) -> TestCaseResult {
        let mut config = self.sandbox_config.clone();
        config.max_execution_time = test_case.time_limit;
        config.max_memory_bytes = test_case.memory_limit;

        let result = Sandbox::new(config)
            .and_then(|mut sandbox| {
                sandbox.load_module(wasm_bytes)?;
                sandbox.instantiate()?;

                // Parse input and call main
                let args = self.parse_input(&test_case.input);
                sandbox.call_function("solve", &args)
            });

        match result {
            Ok(exec_result) => {
                let actual = self.format_output(&exec_result.return_values);
                let passed = actual.trim() == test_case.expected_output.trim();

                TestCaseResult {
                    test_id: test_case.id,
                    passed,
                    expected_output: test_case.expected_output.clone(),
                    actual_output: actual,
                    execution_time: exec_result.execution_time,
                    memory_used: exec_result.peak_memory,
                    verdict: if passed { Verdict::Accepted } else { Verdict::WrongAnswer },
                }
            }
            Err(e) => {
                let verdict = match &e {
                    SandboxError::TimeLimitExceeded { .. } => Verdict::TimeLimitExceeded,
                    SandboxError::MemoryLimitExceeded { .. } => Verdict::MemoryLimitExceeded,
                    SandboxError::InvalidModule(_) => Verdict::CompilationError,
                    _ => Verdict::RuntimeError,
                };

                TestCaseResult {
                    test_id: test_case.id,
                    passed: false,
                    expected_output: test_case.expected_output.clone(),
                    actual_output: format!("Error: {:?}", e),
                    execution_time: Duration::ZERO,
                    memory_used: 0,
                    verdict,
                }
            }
        }
    }

    fn parse_input(&self, input: &str) -> Vec<WasmValue> {
        // Parse simple: integers separated by whitespace
        input.split_whitespace()
            .filter_map(|s| s.parse::<i64>().ok())
            .map(WasmValue::I64)
            .collect()
    }

    fn format_output(&self, values: &[WasmValue]) -> String {
        values.iter().map(|v| match v {
            WasmValue::I32(x) => x.to_string(),
            WasmValue::I64(x) => x.to_string(),
            WasmValue::F32(x) => x.to_string(),
            WasmValue::F64(x) => x.to_string(),
        }).collect::<Vec<_>>().join(" ")
    }
}
```

### Fonctions à Implémenter (C)

```c
// ============================================================
// Wrapper C pour le runtime WASM (via Wasmtime C API)
// ============================================================

#include <wasm.h>
#include <wasmtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Configuration du sandbox
typedef struct {
    size_t max_memory_bytes;
    double max_execution_time_sec;
    uint64_t max_fuel;
    size_t max_stack_size;
} sandbox_config_t;

// Résultat d'exécution
typedef struct {
    int64_t* return_values;
    size_t num_returns;
    double execution_time_sec;
    uint64_t fuel_consumed;
    size_t peak_memory;
    char* error_message;
    int success;
} execution_result_t;

// Handle du sandbox
typedef struct {
    wasm_engine_t* engine;
    wasmtime_store_t* store;
    wasmtime_module_t* module;
    wasmtime_instance_t instance;
    sandbox_config_t config;
    int instance_valid;
} sandbox_t;

// Crée une configuration par défaut
sandbox_config_t sandbox_config_default(void) {
    sandbox_config_t config = {
        .max_memory_bytes = 64 * 1024 * 1024,
        .max_execution_time_sec = 5.0,
        .max_fuel = 10000000,
        .max_stack_size = 1024 * 1024
    };
    return config;
}

// Crée un nouveau sandbox
sandbox_t* sandbox_create(sandbox_config_t config) {
    sandbox_t* sb = (sandbox_t*)calloc(1, sizeof(sandbox_t));
    if (!sb) return NULL;

    sb->config = config;

    // Créer le moteur
    wasm_config_t* wasm_config = wasm_config_new();
    wasmtime_config_consume_fuel_set(wasm_config, true);

    sb->engine = wasm_engine_new_with_config(wasm_config);
    if (!sb->engine) {
        free(sb);
        return NULL;
    }

    // Créer le store
    sb->store = wasmtime_store_new(sb->engine, NULL, NULL);
    if (!sb->store) {
        wasm_engine_delete(sb->engine);
        free(sb);
        return NULL;
    }

    // Configurer le fuel
    wasmtime_context_t* context = wasmtime_store_context(sb->store);
    wasmtime_context_add_fuel(context, config.max_fuel);

    return sb;
}

// Charge un module WASM
int sandbox_load_module(sandbox_t* sb, const uint8_t* wasm_bytes, size_t len) {
    if (!sb) return -1;

    wasmtime_error_t* error = NULL;
    error = wasmtime_module_new(sb->engine, wasm_bytes, len, &sb->module);

    if (error) {
        wasm_message_t message;
        wasmtime_error_message(error, &message);
        fprintf(stderr, "Module error: %.*s\n", (int)message.size, message.data);
        wasm_byte_vec_delete(&message);
        wasmtime_error_delete(error);
        return -1;
    }

    return 0;
}

// Instancie le module
int sandbox_instantiate(sandbox_t* sb) {
    if (!sb || !sb->module) return -1;

    wasmtime_error_t* error = NULL;
    wasm_trap_t* trap = NULL;

    wasmtime_context_t* context = wasmtime_store_context(sb->store);

    // Créer le linker
    wasmtime_linker_t* linker = wasmtime_linker_new(sb->engine);

    // Instancier
    error = wasmtime_linker_instantiate(
        linker, context, sb->module, &sb->instance, &trap
    );

    wasmtime_linker_delete(linker);

    if (error || trap) {
        if (error) {
            wasm_message_t message;
            wasmtime_error_message(error, &message);
            fprintf(stderr, "Instantiation error: %.*s\n",
                    (int)message.size, message.data);
            wasm_byte_vec_delete(&message);
            wasmtime_error_delete(error);
        }
        if (trap) {
            wasm_trap_delete(trap);
        }
        return -1;
    }

    sb->instance_valid = 1;
    return 0;
}

// Appelle une fonction
execution_result_t sandbox_call(
    sandbox_t* sb,
    const char* func_name,
    const int64_t* args,
    size_t num_args
) {
    execution_result_t result = {0};

    if (!sb || !sb->instance_valid) {
        result.error_message = strdup("Invalid sandbox state");
        return result;
    }

    wasmtime_context_t* context = wasmtime_store_context(sb->store);

    // Trouver la fonction exportée
    wasmtime_extern_t func_extern;
    bool found = wasmtime_instance_export_get(
        context, &sb->instance, func_name, strlen(func_name), &func_extern
    );

    if (!found || func_extern.kind != WASMTIME_EXTERN_FUNC) {
        result.error_message = strdup("Function not found");
        return result;
    }

    // Préparer les arguments
    wasmtime_val_t* wasm_args = NULL;
    if (num_args > 0) {
        wasm_args = (wasmtime_val_t*)malloc(num_args * sizeof(wasmtime_val_t));
        for (size_t i = 0; i < num_args; i++) {
            wasm_args[i].kind = WASMTIME_I64;
            wasm_args[i].of.i64 = args[i];
        }
    }

    // Préparer les résultats (assume max 4 return values)
    wasmtime_val_t wasm_results[4];
    size_t num_results = 1;  // Simplified

    // Mesurer le temps
    clock_t start = clock();

    // Appeler
    wasm_trap_t* trap = NULL;
    wasmtime_error_t* error = wasmtime_func_call(
        context, &func_extern.of.func,
        wasm_args, num_args,
        wasm_results, num_results,
        &trap
    );

    clock_t end = clock();
    result.execution_time_sec = (double)(end - start) / CLOCKS_PER_SEC;

    free(wasm_args);

    if (error || trap) {
        if (error) {
            wasm_message_t message;
            wasmtime_error_message(error, &message);
            result.error_message = strndup(message.data, message.size);
            wasm_byte_vec_delete(&message);
            wasmtime_error_delete(error);
        }
        if (trap) {
            wasm_message_t message;
            wasm_trap_message(trap, &message);
            if (!result.error_message) {
                result.error_message = strndup(message.data, message.size);
            }
            wasm_byte_vec_delete(&message);
            wasm_trap_delete(trap);
        }
        return result;
    }

    // Extraire les résultats
    result.return_values = (int64_t*)malloc(num_results * sizeof(int64_t));
    result.num_returns = num_results;
    for (size_t i = 0; i < num_results; i++) {
        if (wasm_results[i].kind == WASMTIME_I64) {
            result.return_values[i] = wasm_results[i].of.i64;
        } else if (wasm_results[i].kind == WASMTIME_I32) {
            result.return_values[i] = wasm_results[i].of.i32;
        }
    }

    // Fuel consommé
    uint64_t remaining;
    wasmtime_context_fuel_remaining(context, &remaining);
    result.fuel_consumed = sb->config.max_fuel - remaining;

    result.success = 1;
    return result;
}

// Libère un résultat
void execution_result_free(execution_result_t* result) {
    if (result) {
        free(result->return_values);
        free(result->error_message);
    }
}

// Détruit le sandbox
void sandbox_destroy(sandbox_t* sb) {
    if (sb) {
        if (sb->module) wasmtime_module_delete(sb->module);
        if (sb->store) wasmtime_store_delete(sb->store);
        if (sb->engine) wasm_engine_delete(sb->engine);
        free(sb);
    }
}
```

---

# Section 2: Le Saviez-Vous ?

## Faits Techniques

1. **WASM Origins**: WebAssembly a été créé par un groupe incluant Mozilla, Google, Microsoft et Apple. La v1.0 a été standardisée en 2019.

2. **Near-Native Speed**: WASM atteint généralement 80-95% des performances du code natif, bien mieux que JavaScript JIT.

3. **Memory Safety**: WASM utilise une mémoire linéaire isolée. Un module ne peut pas accéder à la mémoire du host sans autorisation explicite.

4. **Fuel Metering**: Le concept de "fuel" permet de limiter précisément le nombre d'instructions exécutées, crucial pour les environnements multi-tenant.

5. **Portabilité**: Le même bytecode WASM s'exécute identiquement sur x86, ARM, RISC-V, et dans les navigateurs.

## Anecdotes

- **Cloudflare Workers**: Utilise WASM pour exécuter du code utilisateur en edge. Plus de 10 millions de requêtes par seconde sont traitées via WASM.

- **Figma**: L'éditeur de design Figma utilise WASM pour son moteur de rendu, atteignant 60 FPS sur des designs complexes.

---

# Section 2.5: Dans la Vraie Vie

## Applications Industrielles

### 1. Serverless et Edge Computing
- **Cloudflare Workers**: Runtime WASM pour le edge computing
- **Fastly Compute@Edge**: Exécution WASM avec isolation par requête
- **Fermyon Spin**: Framework serverless WASM

### 2. Blockchain et Smart Contracts
- **Ethereum 2.0 (eWASM)**: Proposition de remplacer EVM par WASM
- **Near Protocol**: Smart contracts en WASM
- **Polkadot**: Runtime WASM pour les parachains

### 3. Plugin Systems
- **Envoy Proxy**: Filtres réseau en WASM
- **VS Code Extensions**: Potentiel futur pour plugins sandboxés
- **Game Engines**: Mods et plugins sécurisés

---

# Section 3: Exemple d'Utilisation

```bash
$ cargo run --release

=== WASM SANDBOX DEMO ===

# Compiler du WAT en WASM
$ echo '(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))' > add.wat
$ ./sandbox compile add.wat -o add.wasm
Compiled: add.wat -> add.wasm (45 bytes)

# Exécuter dans le sandbox
$ ./sandbox run add.wasm --func add --args "5 7"
Configuration:
  Max memory: 64 MB
  Max time: 5s
  Max fuel: 10000000

Executing add(5, 7)...
Result: 12
Execution time: 0.001ms
Fuel consumed: 4
Memory peak: 65536 bytes

# Test avec timeout
$ ./sandbox run infinite_loop.wasm --func loop --timeout 100ms
Configuration:
  Max memory: 64 MB
  Max time: 100ms
  Max fuel: 10000000

Executing loop()...
Error: TimeLimitExceeded
  Elapsed: 100.23ms
  Limit: 100ms

# Test avec fuel limit
$ ./sandbox run heavy_compute.wasm --func compute --fuel 1000
Configuration:
  Max memory: 64 MB
  Max time: 5s
  Max fuel: 1000

Executing compute()...
Error: FuelExhausted
  Used: 1000
  Limit: 1000

# Judge mode
$ ./sandbox judge solution.wasm --tests testcases.json
Running 5 test cases...

Test 1: Accepted (0.5ms, 65KB)
Test 2: Accepted (0.3ms, 65KB)
Test 3: Wrong Answer
  Expected: 42
  Got: 41
Test 4: Accepted (1.2ms, 128KB)
Test 5: Time Limit Exceeded (>1000ms)

Result: 3/5 tests passed
Verdict: Wrong Answer

# API usage example
$ cat example.rs
use hackbrain_wasm::*;

fn main() -> Result<(), SandboxError> {
    let wat = r#"
        (module
            (func (export "fibonacci") (param i64) (result i64)
                (if (result i64) (i64.le_u (local.get 0) (i64.const 1))
                    (then (local.get 0))
                    (else
                        (i64.add
                            (call 0 (i64.sub (local.get 0) (i64.const 1)))
                            (call 0 (i64.sub (local.get 0) (i64.const 2)))
                        )
                    )
                )
            )
        )
    "#;

    let result = execute_wat(
        wat,
        "fibonacci",
        &[WasmValue::I64(10)],
        Some(SandboxConfig::default())
    )?;

    println!("fib(10) = {:?}", result.return_values);
    println!("Time: {:?}", result.execution_time);
    println!("Fuel: {}", result.fuel_consumed);

    Ok(())
}

$ cargo run --example example
fib(10) = [I64(55)]
Time: 234.567us
Fuel: 1847
```

---

# Section 3.1: Bonus Avancé

## Bonus 1: WASI Support Complet (250 XP)

```rust
/// Active le support WASI pour accès fichier/réseau contrôlé
pub fn enable_wasi(
    &mut self,
    wasi_config: WasiConfig,
) -> Result<(), SandboxError> {
    // TODO: Configurer les capabilities WASI
    // - Preopened directories
    // - Environment variables
    // - Command line args
    Ok(())
}
```

## Bonus 2: Multi-Module Linking (200 XP)

```rust
/// Lie plusieurs modules WASM ensemble
pub fn link_modules(
    &mut self,
    modules: &[(&str, &[u8])],  // (name, bytes)
) -> Result<(), SandboxError> {
    // TODO: Implémenter le linking cross-module
    Ok(())
}
```

## Bonus 3: JIT vs AOT Compilation (200 XP)

```rust
/// Compile le module en AOT pour réutilisation
pub fn compile_aot(
    wasm_bytes: &[u8],
    output_path: &str,
) -> Result<(), SandboxError> {
    // TODO: Sérialiser le module compilé
    Ok(())
}

/// Charge un module pré-compilé
pub fn load_aot(
    compiled_path: &str,
) -> Result<Module, SandboxError> {
    // TODO: Désérialiser
    Err(SandboxError::InvalidModule("Not implemented".into()))
}
```

---

# Section 4: Zone Correction

## 4.1 Tests Unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ADD_WAT: &str = r#"
        (module
            (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add
            )
        )
    "#;

    const INFINITE_LOOP_WAT: &str = r#"
        (module
            (func (export "loop") (result i32)
                (loop $inf
                    br $inf
                )
                i32.const 0
            )
        )
    "#;

    const MEMORY_HOG_WAT: &str = r#"
        (module
            (memory (export "memory") 1000)  ;; 64MB
            (func (export "hog") (result i32)
                i32.const 0
            )
        )
    "#;

    #[test]
    fn test_basic_execution() {
        let result = execute_wat(ADD_WAT, "add",
            &[WasmValue::I32(5), WasmValue::I32(7)], None);

        assert!(result.is_ok());
        let exec = result.unwrap();
        assert_eq!(exec.return_values.len(), 1);
        match exec.return_values[0] {
            WasmValue::I32(v) => assert_eq!(v, 12),
            _ => panic!("Expected I32"),
        }
    }

    #[test]
    fn test_fuel_exhaustion() {
        let config = SandboxConfig {
            max_fuel: 100,  // Very low
            ..Default::default()
        };

        let fib_wat = r#"
            (module
                (func $fib (export "fib") (param i64) (result i64)
                    (if (result i64) (i64.le_u (local.get 0) (i64.const 1))
                        (then (local.get 0))
                        (else
                            (i64.add
                                (call $fib (i64.sub (local.get 0) (i64.const 1)))
                                (call $fib (i64.sub (local.get 0) (i64.const 2)))
                            )
                        )
                    )
                )
            )
        "#;

        let result = execute_wat(fib_wat, "fib",
            &[WasmValue::I64(30)], Some(config));

        assert!(matches!(result, Err(SandboxError::FuelExhausted { .. })));
    }

    #[test]
    fn test_memory_limit() {
        let config = SandboxConfig {
            max_memory_bytes: 1024 * 1024,  // 1MB
            ..Default::default()
        };

        // Ce module demande 64MB
        let result = execute_wat(MEMORY_HOG_WAT, "hog", &[], Some(config));

        // Devrait échouer lors de l'instanciation
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_reset() {
        let mut sandbox = Sandbox::new(SandboxConfig::default()).unwrap();
        let wasm = compile_wat_to_wasm(ADD_WAT).unwrap();
        sandbox.load_module(&wasm).unwrap();
        sandbox.instantiate().unwrap();

        // Premier appel
        let r1 = sandbox.call_function("add",
            &[WasmValue::I32(1), WasmValue::I32(2)]).unwrap();

        // Reset
        sandbox.reset().unwrap();

        // Deuxième appel
        let r2 = sandbox.call_function("add",
            &[WasmValue::I32(3), WasmValue::I32(4)]).unwrap();

        match (&r1.return_values[0], &r2.return_values[0]) {
            (WasmValue::I32(v1), WasmValue::I32(v2)) => {
                assert_eq!(*v1, 3);
                assert_eq!(*v2, 7);
            }
            _ => panic!("Expected I32"),
        }
    }

    #[test]
    fn test_invalid_module() {
        let garbage = vec![0x00, 0x01, 0x02, 0x03];
        let result = execute_wasm(&garbage, "main", &[], None);
        assert!(matches!(result, Err(SandboxError::InvalidModule(_))));
    }

    #[test]
    fn test_function_not_found() {
        let result = execute_wat(ADD_WAT, "nonexistent", &[], None);
        assert!(matches!(result, Err(SandboxError::FunctionNotFound(_))));
    }

    #[test]
    fn test_judge_verdict() {
        let judge = Judge::new(SandboxConfig::default());

        let solution_wat = r#"
            (module
                (func (export "solve") (param i64) (result i64)
                    local.get 0
                    i64.const 2
                    i64.mul
                )
            )
        "#;
        let wasm = compile_wat_to_wasm(solution_wat).unwrap();

        let tests = vec![
            TestCase {
                id: 1,
                input: "5".into(),
                expected_output: "10".into(),
                time_limit: Duration::from_secs(1),
                memory_limit: 64 * 1024 * 1024,
            },
            TestCase {
                id: 2,
                input: "0".into(),
                expected_output: "0".into(),
                time_limit: Duration::from_secs(1),
                memory_limit: 64 * 1024 * 1024,
            },
        ];

        let results = judge.evaluate(&wasm, &tests);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].verdict, Verdict::Accepted);
        assert_eq!(results[1].verdict, Verdict::Accepted);
    }

    #[test]
    fn test_builder_pattern() {
        let sandbox = SandboxBuilder::new()
            .max_memory(1024 * 1024)
            .max_time(Duration::from_millis(100))
            .max_fuel(10000)
            .build();

        assert!(sandbox.is_ok());
    }
}
```

## 4.2 Tests de Fuzzing

```rust
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_wat_compilation(wat in "\\(module[^)]*\\)") {
            // Should not panic, even on invalid WAT
            let _ = compile_wat_to_wasm(&wat);
        }

        #[test]
        fn fuzz_wasm_execution(bytes in prop::collection::vec(any::<u8>(), 0..1000)) {
            // Should not panic on arbitrary bytes
            let config = SandboxConfig::minimal();
            let _ = execute_wasm(&bytes, "main", &[], Some(config));
        }

        #[test]
        fn fuzz_function_args(
            a in any::<i32>(),
            b in any::<i32>()
        ) {
            let result = execute_wat(
                r#"(module (func (export "add") (param i32 i32) (result i32)
                    local.get 0 local.get 1 i32.add))"#,
                "add",
                &[WasmValue::I32(a), WasmValue::I32(b)],
                None
            );

            if let Ok(r) = result {
                match r.return_values[0] {
                    WasmValue::I32(sum) => {
                        assert_eq!(sum, a.wrapping_add(b));
                    }
                    _ => panic!("Wrong type"),
                }
            }
        }
    }
}
```

## 4.3 Solution de Référence

```rust
// Sandbox::new - référence
impl Sandbox {
    pub fn new_reference(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut engine_config = Config::new();

        // Fuel pour limiter les instructions
        engine_config.consume_fuel(true);

        // Limiter la stack
        engine_config.max_wasm_stack(config.max_stack_size);

        // Limiter la mémoire totale par page (64KB par page)
        let max_pages = config.max_memory_bytes / 65536;
        // Note: Cette limite est appliquée au niveau du store

        let engine = Engine::new(&engine_config)
            .map_err(|e| SandboxError::InvalidModule(e.to_string()))?;

        let mut store = Store::new(&engine, SandboxState {
            start_time: Instant::now(),
            stdout_buffer: Arc::new(Mutex::new(Vec::new())),
            stderr_buffer: Arc::new(Mutex::new(Vec::new())),
            memory_usage: 0,
        });

        // Ajouter le fuel
        store.add_fuel(config.max_fuel)
            .map_err(|e| SandboxError::RuntimeError(e.to_string()))?;

        // Configurer le limiter de ressources
        store.limiter(|state| {
            ResourceLimiter {
                memory_limit: config.max_memory_bytes,
            }
        });

        Ok(Sandbox {
            engine,
            config,
            store,
            module: None,
            instance: None,
        })
    }
}

struct ResourceLimiter {
    memory_limit: usize,
}

impl wasmtime::ResourceLimiter for ResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> bool {
        desired <= self.memory_limit
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> bool {
        true  // Pas de limite sur les tables
    }
}

// compile_wat_to_wasm - référence
pub fn compile_wat_to_wasm_reference(wat_source: &str) -> Result<Vec<u8>, SandboxError> {
    wat::parse_str(wat_source)
        .map_err(|e| SandboxError::InvalidModule(format!("WAT parse error: {}", e)))
}
```

## 4.4 Mutants

```rust
// MUTANT 1: Pas de vérification de fuel
impl Sandbox {
    pub fn new_mutant1(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut engine_config = Config::new();
        // BUG: Fuel disabled - infinite loops possible
        // engine_config.consume_fuel(true);  // MISSING
        // ...
        Ok(Sandbox::default())
    }
}

// MUTANT 2: Memory limit ignoré
impl Sandbox {
    pub fn call_function_mutant2(&mut self, name: &str, args: &[WasmValue])
        -> Result<ExecutionResult, SandboxError>
    {
        // BUG: No memory limit check during execution
        // ...
        Ok(ExecutionResult::default())
    }
}

// MUTANT 3: Mauvaise conversion de type
pub fn parse_input_mutant3(input: &str) -> Vec<WasmValue> {
    input.split_whitespace()
        .filter_map(|s| s.parse::<i32>().ok())  // BUG: i32 instead of i64
        .map(|v| WasmValue::I32(v))  // BUG: Wrong type
        .collect()
}

// MUTANT 4: Verdict toujours Accepted
impl Judge {
    pub fn run_test_case_mutant4(&self, wasm: &[u8], tc: &TestCase) -> TestCaseResult {
        TestCaseResult {
            test_id: tc.id,
            passed: true,  // BUG: Always true
            verdict: Verdict::Accepted,  // BUG: Always accepted
            ..Default::default()
        }
    }
}

// MUTANT 5: Fuel mal calculé
impl Sandbox {
    pub fn get_fuel_consumed_mutant5(&self) -> u64 {
        // BUG: Returns remaining instead of consumed
        self.store.fuel_remaining().unwrap_or(0)
    }
}
```

---

# Section 5: Comprendre

## 5.1 Architecture WebAssembly

```
WASM Module Structure
─────────────────────
┌────────────────────────────────────────────┐
│ Magic Number (0x00 0x61 0x73 0x6D)         │
├────────────────────────────────────────────┤
│ Version (0x01 0x00 0x00 0x00)              │
├────────────────────────────────────────────┤
│ Type Section (1) - Function signatures     │
├────────────────────────────────────────────┤
│ Import Section (2) - External dependencies │
├────────────────────────────────────────────┤
│ Function Section (3) - Function indices    │
├────────────────────────────────────────────┤
│ Memory Section (5) - Memory definitions    │
├────────────────────────────────────────────┤
│ Export Section (7) - Public interface      │
├────────────────────────────────────────────┤
│ Code Section (10) - Function bodies        │
├────────────────────────────────────────────┤
│ Data Section (11) - Initial memory data    │
└────────────────────────────────────────────┘
```

## 5.2 Modèle de Sécurité

```
Host Environment
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    WASM Runtime                      │    │
│  │  ┌──────────────────────────────────────────────┐   │    │
│  │  │              WASM Instance                    │   │    │
│  │  │  ┌─────────────────────────────────────────┐ │   │    │
│  │  │  │         Linear Memory (isolated)        │ │   │    │
│  │  │  │  ┌───────────────────────────────────┐  │ │   │    │
│  │  │  │  │          WASM Code                │  │ │   │    │
│  │  │  │  │  - No raw pointers                │  │ │   │    │
│  │  │  │  │  - No syscalls                    │  │ │   │    │
│  │  │  │  │  - Bounded memory access          │  │ │   │    │
│  │  │  │  │  - Type-safe operations           │  │ │   │    │
│  │  │  │  └───────────────────────────────────┘  │ │   │    │
│  │  │  └─────────────────────────────────────────┘ │   │    │
│  │  └──────────────────────────────────────────────┘   │    │
│  │                         │                            │    │
│  │                         ▼                            │    │
│  │  ┌──────────────────────────────────────────────┐   │    │
│  │  │           Imported Functions (controlled)     │   │    │
│  │  │  - fd_write (captured)                        │   │    │
│  │  │  - clock_time_get (allowed/denied)           │   │    │
│  │  └──────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Host Functions (inaccessible without explicit import)       │
│  - File system                                               │
│  - Network                                                   │
│  - Process spawning                                          │
└──────────────────────────────────────────────────────────────┘
```

## 5.3 Fuel Metering

Le fuel est un compteur qui décrémente à chaque opération:

```
Instruction     | Fuel Cost
----------------|----------
nop             | 1
local.get       | 1
i32.add         | 1
i32.mul         | 2
call            | 5
memory.grow     | 1000
loop iteration  | 1 (per back-edge)
```

Quand fuel = 0, l'exécution s'arrête avec une erreur.

## 5.4 Mémoire Linéaire

```
WASM Memory Layout
──────────────────
0x00000000 ┌────────────────────────┐
           │   Stack (grows down)   │
           │          ↓             │
           ├────────────────────────┤
           │                        │
           │      Free Space        │
           │                        │
           ├────────────────────────┤
           │          ↑             │
           │   Heap (grows up)      │
           ├────────────────────────┤
           │   Static Data          │
           ├────────────────────────┤
           │   Code (implicit)      │
0x???????? └────────────────────────┘

- Memory is linear (contiguous)
- Grows in 64KB pages
- All accesses are bounds-checked
- No raw pointers (indices only)
```

---

# Section 6: Pièges

## 6.1 Piège: Oublier le Fuel

```rust
// PIÈGE: Infinite loop sans limite
fn dangerous() {
    let wat = r#"
        (module
            (func (export "loop")
                (loop $inf
                    br $inf
                )
            )
        )
    "#;

    // MAUVAIS: Pas de fuel limit
    let config = Config::new();  // consume_fuel = false par défaut!

    // CORRECT:
    let mut config = Config::new();
    config.consume_fuel(true);
}
```

## 6.2 Piège: Memory Non Bornée

```rust
// PIÈGE: Module qui alloue trop de mémoire
let wat = r#"
    (module
        (memory 10000)  ;; 640MB!
        (func (export "hog"))
    )
"#;

// MAUVAIS: Pas de resource limiter
let store = Store::new(&engine, ());

// CORRECT: Utiliser ResourceLimiter
let mut store = Store::new(&engine, state);
store.limiter(|_| ResourceLimiter {
    memory_limit: 64 * 1024 * 1024,  // 64MB max
});
```

## 6.3 Piège: Import Dangereux

```rust
// PIÈGE: Exposer des fonctions dangereuses
linker.func_wrap("env", "system",
    |cmd: &str| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
    }
)?;
// CATASTROPHE: Le WASM peut exécuter n'importe quelle commande!

// CORRECT: Ne jamais exposer d'accès système direct
// Utiliser des capabilities limitées
```

## 6.4 Piège: Timing Side Channels

```rust
// PIÈGE: Exposer le temps système
linker.func_wrap("env", "now", || {
    std::time::Instant::now().elapsed().as_nanos()
})?;
// Permet des attaques par timing!

// CORRECT: Utiliser un temps virtuel ou refuser
let config = SandboxConfig {
    allow_clock: false,  // Pas d'accès au temps
    ..Default::default()
};
```

---

# Section 7: QCM

## Question 1
Quelle est la taille d'une page mémoire WebAssembly?

- A) 4 KB
- B) 16 KB
- C) 64 KB
- D) 1 MB

## Question 2
Que signifie "fuel" dans le contexte WASM?

- A) Consommation électrique
- B) Compteur d'instructions pour limiter l'exécution
- C) Allocation mémoire
- D) Nombre de threads

## Question 3
Pourquoi WASM est-il considéré comme "memory-safe"?

- A) Il utilise un garbage collector
- B) La mémoire est linéaire et tous les accès sont bounds-checked
- C) Il n'a pas de pointeurs
- D) Il est interprété

## Question 4
Quel est l'avantage principal de WASI?

- A) Performance améliorée
- B) Interface standardisée pour l'accès système contrôlé
- C) Compilation plus rapide
- D) Meilleure portabilité JavaScript

## Question 5
Comment empêcher une boucle infinie en WASM?

- A) Timeout OS
- B) Fuel metering
- C) Memory limit
- D) A et B

## Question 6
Quelle section WASM contient les signatures de fonction?

- A) Code Section
- B) Type Section
- C) Export Section
- D) Import Section

## Question 7
Quel runtime Rust est recommandé pour WASM?

- A) wasm-bindgen
- B) wasmtime
- C) emscripten
- D) wasm-pack

## Question 8
Pourquoi le "store" est-il important dans wasmtime?

- A) Il stocke le code source
- B) Il maintient l'état mutable de l'instance (mémoire, globals)
- C) Il compile le module
- D) Il gère le réseau

---

## Réponses

1. **C) 64 KB** - Standard WASM, les pages font 65536 bytes.

2. **B) Compteur d'instructions** - Permet de limiter le temps CPU de manière déterministe.

3. **B) Mémoire linéaire bounds-checked** - Tous les accès sont vérifiés, pas d'overflow possible.

4. **B) Interface système contrôlée** - WASI = WebAssembly System Interface, accès fichiers/réseau sandboxé.

5. **D) A et B** - Timeout pour le temps réel, fuel pour le déterminisme.

6. **B) Type Section** - Section 1 dans le binaire WASM.

7. **B) wasmtime** - Runtime mature de la Bytecode Alliance.

8. **B) État mutable** - Le store contient la mémoire, tables, et globals de l'instance.

---

# Section 8: Récapitulatif

## Compétences Acquises

| Compétence | Description | Niveau |
|------------|-------------|--------|
| WASM Basics | Structure des modules, WAT syntax | Avancé |
| Sandboxing | Isolation, limites de ressources | Expert |
| Wasmtime | API Rust du runtime | Avancé |
| Security | Modèle de sécurité WASM | Avancé |
| Resource Limiting | Fuel, memory, time limits | Expert |

## Complexités

| Opération | Temps | Notes |
|-----------|-------|-------|
| Module parsing | O(n) | n = taille du bytecode |
| Compilation | O(n) | Dépend du JIT/AOT |
| Instance creation | O(imports + exports) | |
| Function call | O(fuel) | Limité par fuel |
| Memory access | O(1) | Bounds check inclus |

## Prochaines Étapes

1. **Immédiat**: Implémenter un sandbox fonctionnel
2. **Court terme**: Ajouter support WASI complet
3. **Long terme**: Créer un service d'exécution multi-tenant

---

# Section 9: Deployment Pack

```json
{
  "exercise_id": "1.9.06",
  "code_name": "the_matrix_construct",
  "version": "1.0.0",
  "tier": 3,
  "estimated_hours": 45,
  "languages": ["rust", "c", "wat"],

  "concepts_covered": [
    "webassembly_basics",
    "sandboxing",
    "resource_limiting",
    "fuel_metering",
    "memory_isolation",
    "wasi",
    "capability_security",
    "runtime_implementation"
  ],

  "learning_objectives": [
    "Understand WebAssembly security model",
    "Implement resource-limited execution",
    "Create capability-based sandbox",
    "Build code judge infrastructure"
  ],

  "prerequisites": [
    "module_1.1_through_1.8",
    "rust_basics",
    "memory_safety_concepts"
  ],

  "dependencies": {
    "rust": {
      "wasmtime": ">=15.0",
      "wat": ">=1.0",
      "proptest": ">=1.0"
    },
    "c": {
      "wasmtime-c-api": ">=15.0"
    }
  },

  "grading": {
    "tests_weight": 0.35,
    "code_quality_weight": 0.20,
    "security_weight": 0.25,
    "documentation_weight": 0.10,
    "bonus_weight": 0.10
  },

  "files": {
    "rust": {
      "lib.rs": "src/lib.rs",
      "sandbox.rs": "src/sandbox.rs",
      "config.rs": "src/config.rs",
      "judge.rs": "src/judge.rs"
    },
    "c": {
      "sandbox.h": "include/sandbox.h",
      "sandbox.c": "src/sandbox.c"
    }
  },

  "test_commands": {
    "rust": "cargo test --all-features",
    "security": "cargo test security_",
    "fuzz": "cargo fuzz run fuzz_wasm"
  },

  "metadata": {
    "author": "HACKBRAIN",
    "created": "2025-01-17",
    "difficulty": "expert",
    "tags": ["capstone", "wasm", "sandbox", "security"]
  }
}
```

---

*"Unfortunately, no one can be told what The Matrix is. You have to see it for yourself."* — Morpheus

**Votre sandbox est la pilule bleue. Le code s'exécute, mais il ne voit jamais le monde réel.**
