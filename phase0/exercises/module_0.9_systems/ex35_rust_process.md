# Exercice 0.9.35 : rust_process_commander

**Module :**
0.9 — Systems Programming

**Concept :**
std::process::Command, spawn, wait, output capture

**Difficulte :**
5/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
Rust Edition 2024

**Prerequis :**
- Syntaxe Rust de base
- Result et Option
- Ownership basics

**Domaines :**
Process, Rust, Sys

**Duree estimee :**
50 min

**XP Base :**
140

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs`, `Cargo.toml` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `std::process::*`, `std::io::*`, `std::env::*` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `libc::fork`, `libc::exec*` (utilise les abstractions Rust !) |

---

### 1.2 Consigne

#### Section Culture : "The Orchestrator"

**INCEPTION - "We need to go deeper... into subprocesses"**

Comme Dom Cobb qui orchestre des reves dans des reves, tu vas orchestrer des processus dans des processus. Rust te donne `Command`, un constructeur elegant qui encapsule toute la complexite de fork/exec dans une API fluide.

*"You mustn't be afraid to dream a little bigger, darling."* - Utilise spawn, output, et status pour controler tes processus enfants.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un module de gestion de processus en Rust utilisant `std::process::Command` :

1. **run_command** : Execute une commande et retourne son code de sortie
2. **capture_output** : Execute et capture stdout/stderr
3. **run_with_input** : Execute avec donnees sur stdin
4. **run_pipeline** : Chaine de commandes pipees

**Entree (Rust) :**

```rust
use std::process::ExitStatus;
use std::io;

/// Execute une commande avec arguments
/// Retourne le code de sortie ou une erreur
pub fn run_command(program: &str, args: &[&str]) -> io::Result<i32>;

/// Execute et capture la sortie (stdout et stderr)
pub fn capture_output(program: &str, args: &[&str]) -> io::Result<ProcessOutput>;

/// Execute avec donnees envoyees sur stdin
pub fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> io::Result<ProcessOutput>;

/// Execute une pipeline de commandes (cmd1 | cmd2 | ...)
pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput>;

#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

impl ProcessOutput {
    pub fn stdout_str(&self) -> Result<&str, std::str::Utf8Error>;
    pub fn stderr_str(&self) -> Result<&str, std::str::Utf8Error>;
    pub fn success(&self) -> bool;
}
```

**Sortie :**
- `run_command` : Code de sortie (0 = succes)
- `capture_output` : Struct avec stdout, stderr, exit_code
- `run_with_input` : Struct avec output apres envoi d'input
- `run_pipeline` : Output de la derniere commande

**Contraintes :**
- Utiliser les types standard de std::process
- Gerer correctement les erreurs avec Result
- Ne pas bloquer indefiniment (timeout optionnel en bonus)
- Support des arguments avec espaces (quoting automatique)

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `run_command("true", &[])` | - | Ok(0) | true retourne 0 |
| `run_command("false", &[])` | - | Ok(1) | false retourne 1 |
| `capture_output("echo", &["hello"])` | - | stdout="hello\n" | Capture stdout |
| `run_with_input("cat", &[], b"test")` | "test" | stdout="test" | Echo stdin |
| `run_pipeline(&[("echo", &["hi"]), ("wc", &["-c"])])` | - | stdout="3\n" | Pipeline |

---

### 1.3 Prototype

**Rust :**
```rust
use std::process::{Command, Stdio, Child, Output, ExitStatus};
use std::io::{self, Write, Read};

pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

pub fn run_command(program: &str, args: &[&str]) -> io::Result<i32>;
pub fn capture_output(program: &str, args: &[&str]) -> io::Result<ProcessOutput>;
pub fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> io::Result<ProcessOutput>;
pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Command est un builder pattern !**

Rust utilise le pattern builder pour `Command`, permettant une configuration fluide :

```rust
Command::new("ls")
    .arg("-la")
    .current_dir("/tmp")
    .env("LANG", "C")
    .stdout(Stdio::piped())
    .spawn()?;
```

**spawn() vs output() vs status()**

- `spawn()` : Lance le processus et retourne immediatement (Child)
- `output()` : Lance et attend, capture stdout/stderr
- `status()` : Lance et attend, retourne juste le code de sortie

**Rust protege contre les injections shell !**

Contrairement a `system()` en C, Rust n'invoque pas de shell par defaut. Les arguments sont passes directement au programme, empechant les injections.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps Engineer** | Scripts d'automatisation en Rust |
| **CLI Developer** | Outils qui orchestrent d'autres outils |
| **Build System Developer** | Compilation, tests, packaging |
| **Container Runtime Developer** | Gestion des processus conteneurises |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat src/main.rs
use process_lib::{run_command, capture_output, run_with_input, run_pipeline};

fn main() -> std::io::Result<()> {
    // Simple command
    let code = run_command("ls", &["-la"])?;
    println!("ls returned: {}", code);

    // Capture output
    let out = capture_output("echo", &["Hello, World!"])?;
    println!("Captured: {}", out.stdout_str().unwrap());

    // With input
    let out = run_with_input("cat", &[], b"Test input")?;
    assert_eq!(out.stdout, b"Test input");

    // Pipeline: echo "hello" | tr 'a-z' 'A-Z'
    let out = run_pipeline(&[
        ("echo", &["hello"]),
        ("tr", &["a-z", "A-Z"]),
    ])?;
    println!("Pipeline result: {}", out.stdout_str().unwrap());
    // Output: "HELLO\n"

    Ok(())
}

$ cargo run
ls returned: 0
Captured: Hello, World!
Pipeline result: HELLO
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
6/10

**Recompense :**
XP x2

**Consigne Bonus :**

Implementer un systeme de timeout et execution asynchrone :

```rust
use std::time::Duration;

/// Execute avec timeout
pub fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration
) -> io::Result<Option<ProcessOutput>>;

/// Execute plusieurs commandes en parallele
pub async fn run_parallel(
    commands: &[(&str, &[&str])]
) -> Vec<io::Result<ProcessOutput>>;

/// Streaming output (callback a chaque ligne)
pub fn run_streaming<F>(
    program: &str,
    args: &[&str],
    on_line: F
) -> io::Result<i32>
where F: FnMut(&str);
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | run_true | run_command("true", &[]) | Ok(0) | 5 | Basic |
| 2 | run_false | run_command("false", &[]) | Ok(1) | 5 | Basic |
| 3 | capture_echo | capture_output("echo", &["hi"]) | stdout="hi\n" | 10 | Capture |
| 4 | capture_stderr | capture_output("ls", &["/nonexistent"]) | stderr non-vide | 10 | Capture |
| 5 | invalid_program | run_command("nonexistent123", &[]) | Err | 10 | Error |
| 6 | with_input | run_with_input("cat", &[], b"test") | stdout="test" | 15 | Input |
| 7 | pipeline_simple | echo hi \| wc -c | stdout="3\n" | 15 | Pipeline |
| 8 | args_with_spaces | echo "hello world" | stdout correct | 10 | Edge |
| 9 | exit_code_42 | sh -c "exit 42" | Ok(42) | 10 | Exit code |
| 10 | env_inherited | env | contains PATH | 10 | Env |

**Total : 100 points**

---

### 4.2 Tests Rust

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_true() {
        let result = run_command("true", &[]).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_run_false() {
        let result = run_command("false", &[]).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_capture_echo() {
        let out = capture_output("echo", &["hello"]).unwrap();
        assert_eq!(out.stdout_str().unwrap(), "hello\n");
        assert!(out.success());
    }

    #[test]
    fn test_capture_stderr() {
        let out = capture_output("ls", &["/nonexistent_path_12345"]).unwrap();
        assert!(!out.stderr.is_empty());
        assert!(!out.success());
    }

    #[test]
    fn test_invalid_program() {
        let result = run_command("nonexistent_program_xyz", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_input() {
        let out = run_with_input("cat", &[], b"hello world").unwrap();
        assert_eq!(out.stdout, b"hello world");
    }

    #[test]
    fn test_pipeline() {
        let out = run_pipeline(&[
            ("echo", &["hello"]),
            ("tr", &["a-z", "A-Z"]),
        ]).unwrap();
        assert_eq!(out.stdout_str().unwrap().trim(), "HELLO");
    }

    #[test]
    fn test_exit_code() {
        let code = run_command("sh", &["-c", "exit 42"]).unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn test_args_with_spaces() {
        let out = capture_output("echo", &["hello world"]).unwrap();
        assert_eq!(out.stdout_str().unwrap(), "hello world\n");
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
use std::process::{Command, Stdio, Child};
use std::io::{self, Write, Read};

#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

impl ProcessOutput {
    pub fn stdout_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.stdout)
    }

    pub fn stderr_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.stderr)
    }

    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

pub fn run_command(program: &str, args: &[&str]) -> io::Result<i32> {
    let status = Command::new(program)
        .args(args)
        .status()?;

    Ok(status.code().unwrap_or(-1))
}

pub fn capture_output(program: &str, args: &[&str]) -> io::Result<ProcessOutput> {
    let output = Command::new(program)
        .args(args)
        .output()?;

    Ok(ProcessOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
    })
}

pub fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> io::Result<ProcessOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }

    let output = child.wait_with_output()?;

    Ok(ProcessOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
    })
}

pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput> {
    if commands.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty pipeline"));
    }

    if commands.len() == 1 {
        return capture_output(commands[0].0, commands[0].1);
    }

    let mut previous_stdout: Option<std::process::ChildStdout> = None;
    let mut children: Vec<Child> = Vec::new();

    for (i, (program, args)) in commands.iter().enumerate() {
        let stdin = if let Some(stdout) = previous_stdout.take() {
            Stdio::from(stdout)
        } else {
            Stdio::null()
        };

        let stdout = if i == commands.len() - 1 {
            Stdio::piped()
        } else {
            Stdio::piped()
        };

        let mut child = Command::new(program)
            .args(*args)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()?;

        previous_stdout = child.stdout.take();
        children.push(child);
    }

    // Wait for all children and get last output
    let mut last_output = ProcessOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_code: 0,
    };

    for (i, mut child) in children.into_iter().enumerate() {
        let output = child.wait_with_output()?;
        if i == commands.len() - 1 {
            last_output = ProcessOutput {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code: output.status.code().unwrap_or(-1),
            };
        }
    }

    Ok(last_output)
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Utilisation de shell pour pipeline**

```rust
pub fn run_pipeline_shell(pipeline: &str) -> io::Result<ProcessOutput> {
    capture_output("sh", &["-c", pipeline])
}
// Accepte mais moins securise contre les injections
```

**Alternative 2 : Utilisation de os_pipe crate**

```rust
// Avec la crate os_pipe pour une gestion plus fine
use os_pipe::pipe;
// ... implementation similaire mais avec plus de controle
```

---

### 4.5 Solutions refusees

**Refus 1 : Utilisation de libc directement**

```rust
// REFUSE : L'exercice demande d'utiliser std::process !
use libc::{fork, execvp};
unsafe {
    if fork() == 0 {
        execvp(...);
    }
}
```
**Pourquoi refuse :** L'objectif est d'apprendre l'API Rust safe pour les processus.

**Refus 2 : Pas de gestion d'erreur**

```rust
pub fn run_command(program: &str, args: &[&str]) -> i32 {
    Command::new(program).args(args).status().unwrap().code().unwrap()
}
// REFUSE : unwrap() partout = panic sur erreur
```
**Pourquoi refuse :** Pas de gestion propre des erreurs.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Pas de gestion pipeline vide**

```rust
/* Mutant A (Boundary) : Pipeline vide panic */
pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput> {
    let (first_prog, first_args) = commands[0]; // PANIC si vide !
    // ...
}
// Pourquoi c'est faux : Index out of bounds si commands est vide
```

**Mutant B (Safety) : stdin non ferme**

```rust
/* Mutant B (Safety) : Deadlock potentiel */
pub fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> io::Result<ProcessOutput> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(input)?;
    // OUBLI: drop(child.stdin.take()) - stdin reste ouvert !

    let output = child.wait_with_output()?; // Peut deadlock
    // ...
}
// Pourquoi c'est faux : Le processus attend la fermeture de stdin
```

**Mutant C (Resource) : Children non attendus**

```rust
/* Mutant C (Resource) : Zombies en pipeline */
pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput> {
    let mut children: Vec<Child> = Vec::new();
    for (prog, args) in commands {
        children.push(Command::new(prog).args(*args).spawn()?);
    }
    // OUBLI: wait sur tous les children sauf le dernier
    Ok(children.last_mut().unwrap().wait_with_output()?.into())
}
// Pourquoi c'est faux : Les processus intermediaires deviennent zombies
```

**Mutant D (Logic) : Mauvaise connection des pipes**

```rust
/* Mutant D (Logic) : Pipes mal connectes */
pub fn run_pipeline(commands: &[(&str, &[&str])]) -> io::Result<ProcessOutput> {
    for (prog, args) in commands {
        Command::new(prog)
            .args(*args)
            .stdout(Stdio::piped()) // Chaque commande lit de null !
            .spawn()?;
    }
    // Les pipes ne sont pas connectes entre eux
}
// Pourquoi c'est faux : Pas de vrai pipeline, chaque commande est isolee
```

**Mutant E (Return) : Code de sortie ignore**

```rust
/* Mutant E (Return) : Toujours succes */
pub fn run_command(program: &str, args: &[&str]) -> io::Result<i32> {
    Command::new(program).args(args).status()?;
    Ok(0) // FAUX: retourne toujours 0 !
}
// Pourquoi c'est faux : Le vrai code de sortie est ignore
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Command builder | API fluide pour processus | Fondamental |
| spawn vs output | Asynchrone vs synchrone | Important |
| Stdio redirection | Pipes et captures | Essentiel |
| Error handling | Result pour les erreurs I/O | Fondamental |

---

### 5.2 LDA - Traduction litterale

```
FONCTION capture_output QUI PREND program ET args
DEBUT FONCTION
    CREER UN Command AVEC program
    AJOUTER args AU Command
    EXECUTER output() QUI LANCE ET ATTEND
    SI ERREUR ALORS
        RETOURNER Err(erreur)
    FIN SI
    CONSTRUIRE ProcessOutput AVEC stdout, stderr, exit_code
    RETOURNER Ok(output)
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
std::process::Command - Builder Pattern
=======================================

Command::new("ls")
     │
     ├──.arg("-l")──────────────┐
     │                          │
     ├──.arg("-a")──────────────┤
     │                          │
     ├──.current_dir("/tmp")────┤
     │                          │
     ├──.env("LANG", "C")───────┤
     │                          │
     └──.stdout(Stdio::piped())─┘
                │
     ┌──────────┴──────────┐
     │                     │
     ▼                     ▼
 .spawn()              .output()
     │                     │
     ▼                     ▼
  Child                 Output
(non-blocking)       (blocking)


Pipeline Architecture:
======================

echo "hello" | tr 'a-z' 'A-Z' | wc -c

┌─────────┐    ┌─────────┐    ┌─────────┐
│  echo   │───►│   tr    │───►│   wc    │
└─────────┘    └─────────┘    └─────────┘
  stdout        stdin/out      stdin/out
  piped         piped          captured
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | unwrap partout | Panic sur erreur | Utiliser ? |
| 2 | stdin non ferme | Deadlock | drop(stdin) |
| 3 | Zombies en pipeline | Fuite ressources | wait tous |
| 4 | Code de sortie ignore | Faux succes | Verifier status |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle methode de Command execute et attend la fin du processus ?

- A) spawn()
- B) output()
- C) status()
- D) B et C

**Reponse : D** - output() et status() sont tous deux bloquants.

### Question 2 (4 points)
Pourquoi Rust est plus sur que system() en C pour executer des commandes ?

- A) Il est plus rapide
- B) Il n'invoque pas de shell par defaut, evitant les injections
- C) Il utilise des threads
- D) Il compile les commandes

**Reponse : B** - Command passe les arguments directement sans shell.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.9.35 |
| **Nom** | rust_process_commander |
| **Difficulte** | 5/10 |
| **Duree** | 50 min |
| **XP Base** | 140 |
| **Langage** | Rust Edition 2024 |
| **Concepts cles** | Command, spawn, output, Stdio |

---

*Document genere selon HACKBRAIN v5.5.2*
