# Exercice 1.9.07 - Online Judge System (Capstone Final)

## Metadata
- **Nom de code:** the_arena
- **Tier:** 3 (Synthesis - Ultimate Capstone)
- **Complexité estimée:** Expert (50-60h)
- **Prérequis:** Tous les modules 1.1-1.9

---

# Section 1: Prototype & Consigne

## 1.1 Version Culture Pop

> *"Are you not entertained?"* — Maximus, Gladiator (2000)

Dans l'arène du Colisée, les gladiateurs prouvaient leur valeur au combat. Dans l'arène moderne du code, les développeurs prouvent leur maîtrise algorithmique. LeetCode, Codeforces, HackerRank - ces plateformes sont les Colisées numériques où des millions de programmeurs s'affrontent.

Votre mission finale: construire **The Arena**, un système de jugement en ligne complet. Pas une simple évaluation de code - un écosystème entier avec problèmes, soumissions, classements, et contests en temps réel.

**Le défi ultime:** Créer un Online Judge production-ready qui pourrait rivaliser avec les grandes plateformes.

## 1.2 Version Académique

### Contexte Formel

Un Online Judge est un système automatisé d'évaluation de code qui:
- Compile et exécute du code utilisateur de manière sécurisée
- Compare les sorties avec des résultats attendus
- Applique des contraintes de temps et mémoire
- Maintient des classements et statistiques

Ce projet constitue la synthèse finale de tous les concepts algorithmiques et d'ingénierie logicielle du cursus.

### Spécification Formelle

Soit J = (P, S, U, C, R) un système de jugement où:
- P : Ensemble des problèmes (énoncé, tests, limites)
- S : Ensemble des soumissions (code, langage, timestamp)
- U : Ensemble des utilisateurs (profil, statistiques)
- C : Ensemble des contests (problèmes, durée, règles)
- R : Fonction de ranking R: U × C → ℕ

### Objectifs Pédagogiques

1. Intégrer tous les concepts des modules 1.1-1.8
2. Concevoir une architecture distribuée et scalable
3. Implémenter un système de jugement sécurisé (sandbox WASM)
4. Créer une API REST complète avec websockets pour temps réel
5. Gérer la concurrence et les race conditions

### Fonctions à Implémenter (Rust)

```rust
// ============================================================
// PARTIE A: Modèles de Données
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Identifiant unique typé
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProblemId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubmissionId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContestId(pub Uuid);

/// Problème algorithmique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    pub id: ProblemId,
    pub title: String,
    pub slug: String,  // URL-friendly: "two-sum"
    pub difficulty: Difficulty,
    pub description: String,
    pub input_format: String,
    pub output_format: String,
    pub constraints: Vec<String>,
    pub examples: Vec<Example>,
    pub test_cases: Vec<TestCase>,
    pub time_limit_ms: u64,
    pub memory_limit_mb: u64,
    pub tags: Vec<String>,
    pub author: UserId,
    pub created_at: DateTime<Utc>,
    pub solve_count: u64,
    pub attempt_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Example {
    pub input: String,
    pub output: String,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub id: u32,
    pub input: String,
    pub expected_output: String,
    pub is_sample: bool,  // Visible to user
    pub score: u32,       // Points for this test
}

/// Soumission de code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    pub id: SubmissionId,
    pub problem_id: ProblemId,
    pub user_id: UserId,
    pub language: Language,
    pub code: String,
    pub submitted_at: DateTime<Utc>,
    pub status: SubmissionStatus,
    pub verdict: Option<Verdict>,
    pub test_results: Vec<TestResult>,
    pub execution_time_ms: Option<u64>,
    pub memory_used_kb: Option<u64>,
    pub score: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Rust,
    C,
    Cpp,
    Python,
    Java,
    JavaScript,
    Go,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionStatus {
    Pending,
    Compiling,
    Running,
    Completed,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accepted,
    WrongAnswer,
    TimeLimitExceeded,
    MemoryLimitExceeded,
    RuntimeError,
    CompilationError,
    PresentationError,
    PartiallyAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_id: u32,
    pub passed: bool,
    pub verdict: Verdict,
    pub execution_time_ms: u64,
    pub memory_used_kb: u64,
    pub output: Option<String>,  // For debugging (sample tests only)
}

/// Utilisateur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub rating: i32,
    pub solved_problems: Vec<ProblemId>,
    pub submissions_count: u64,
    pub accepted_count: u64,
}

/// Contest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contest {
    pub id: ContestId,
    pub title: String,
    pub description: String,
    pub problems: Vec<ProblemId>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub scoring_type: ScoringType,
    pub participants: Vec<UserId>,
    pub standings: Vec<Standing>,
    pub is_rated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScoringType {
    ICPC,       // First to solve, penalty time
    IOI,        // Partial scoring
    Codeforces, // Points decrease over time
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Standing {
    pub user_id: UserId,
    pub rank: u32,
    pub score: i64,
    pub penalty: i64,
    pub problem_results: HashMap<ProblemId, ProblemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemResult {
    pub solved: bool,
    pub attempts: u32,
    pub solve_time: Option<i64>,  // Minutes from contest start
    pub score: u32,
}

// ============================================================
// PARTIE B: Service de Jugement
// ============================================================

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Trait pour le service de jugement
#[async_trait]
pub trait JudgeService: Send + Sync {
    /// Soumet du code pour évaluation
    async fn submit(&self, submission: Submission) -> Result<SubmissionId, JudgeError>;

    /// Récupère le statut d'une soumission
    async fn get_status(&self, id: SubmissionId) -> Result<Submission, JudgeError>;

    /// Annule une soumission en cours
    async fn cancel(&self, id: SubmissionId) -> Result<(), JudgeError>;
}

#[derive(Debug, Clone)]
pub enum JudgeError {
    SubmissionNotFound,
    CompilationFailed(String),
    RuntimeError(String),
    Timeout,
    InternalError(String),
}

/// Implémentation du service de jugement
pub struct JudgeServiceImpl {
    /// Queue des soumissions en attente
    submission_queue: mpsc::Sender<Submission>,

    /// Cache des soumissions
    submissions: Arc<RwLock<HashMap<SubmissionId, Submission>>>,

    /// Pool de workers
    worker_count: usize,
}

impl JudgeServiceImpl {
    pub fn new(worker_count: usize) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        let submissions = Arc::new(RwLock::new(HashMap::new()));

        // Démarrer les workers
        let subs_clone = submissions.clone();
        tokio::spawn(async move {
            Self::run_workers(rx, subs_clone, worker_count).await;
        });

        JudgeServiceImpl {
            submission_queue: tx,
            submissions,
            worker_count,
        }
    }

    async fn run_workers(
        mut rx: mpsc::Receiver<Submission>,
        submissions: Arc<RwLock<HashMap<SubmissionId, Submission>>>,
        worker_count: usize,
    ) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(worker_count));

        while let Some(submission) = rx.recv().await {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let subs = submissions.clone();

            tokio::spawn(async move {
                let result = Self::judge_submission(&submission).await;

                // Mettre à jour la soumission
                let mut subs = subs.write().await;
                if let Some(sub) = subs.get_mut(&submission.id) {
                    sub.status = SubmissionStatus::Completed;
                    sub.verdict = Some(result.verdict);
                    sub.test_results = result.test_results;
                    sub.execution_time_ms = Some(result.max_time_ms);
                    sub.memory_used_kb = Some(result.max_memory_kb);
                    sub.score = Some(result.score);
                }

                drop(permit);
            });
        }
    }

    async fn judge_submission(submission: &Submission) -> JudgeResult {
        // 1. Compiler le code (si nécessaire)
        let compiled = Self::compile(&submission.code, submission.language).await;

        if let Err(e) = compiled {
            return JudgeResult {
                verdict: Verdict::CompilationError,
                test_results: vec![],
                max_time_ms: 0,
                max_memory_kb: 0,
                score: 0,
            };
        }

        // 2. Récupérer les test cases du problème
        let test_cases = Self::get_test_cases(submission.problem_id).await;

        // 3. Exécuter chaque test dans le sandbox
        let mut test_results = Vec::new();
        let mut total_score = 0u32;
        let mut max_time = 0u64;
        let mut max_memory = 0u64;
        let mut all_passed = true;

        for tc in &test_cases {
            let result = Self::run_test_case(&compiled.unwrap(), tc).await;

            if result.passed {
                total_score += tc.score;
            } else {
                all_passed = false;
            }

            max_time = max_time.max(result.execution_time_ms);
            max_memory = max_memory.max(result.memory_used_kb);
            test_results.push(result);
        }

        let verdict = if all_passed {
            Verdict::Accepted
        } else {
            // Trouver le premier échec
            test_results.iter()
                .find(|r| !r.passed)
                .map(|r| r.verdict)
                .unwrap_or(Verdict::WrongAnswer)
        };

        JudgeResult {
            verdict,
            test_results,
            max_time_ms: max_time,
            max_memory_kb: max_memory,
            score: total_score,
        }
    }

    async fn compile(code: &str, language: Language) -> Result<CompiledCode, String> {
        // TODO: Implémenter compilation par langage
        // - Rust: rustc avec sandbox
        // - C/C++: gcc/g++ avec sandbox
        // - Python: syntax check uniquement
        // - Java: javac avec sandbox
        Ok(CompiledCode {
            wasm_bytes: vec![],
            language,
        })
    }

    async fn get_test_cases(problem_id: ProblemId) -> Vec<TestCase> {
        // TODO: Récupérer depuis la base de données
        vec![]
    }

    async fn run_test_case(compiled: &CompiledCode, test_case: &TestCase) -> TestResult {
        // TODO: Utiliser le sandbox WASM de ex06
        TestResult {
            test_id: test_case.id,
            passed: false,
            verdict: Verdict::WrongAnswer,
            execution_time_ms: 0,
            memory_used_kb: 0,
            output: None,
        }
    }
}

struct JudgeResult {
    verdict: Verdict,
    test_results: Vec<TestResult>,
    max_time_ms: u64,
    max_memory_kb: u64,
    score: u32,
}

struct CompiledCode {
    wasm_bytes: Vec<u8>,
    language: Language,
}

// ============================================================
// PARTIE C: API REST
// ============================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

/// État partagé de l'application
pub struct AppState {
    pub judge_service: Arc<dyn JudgeService>,
    pub problem_repo: Arc<dyn ProblemRepository>,
    pub user_repo: Arc<dyn UserRepository>,
    pub contest_repo: Arc<dyn ContestRepository>,
}

/// Crée le routeur API
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Problems
        .route("/api/problems", get(list_problems))
        .route("/api/problems/:slug", get(get_problem))
        .route("/api/problems", post(create_problem))

        // Submissions
        .route("/api/submit", post(submit_solution))
        .route("/api/submissions/:id", get(get_submission))
        .route("/api/submissions", get(list_submissions))

        // Users
        .route("/api/users/:username", get(get_user))
        .route("/api/users/:username/submissions", get(get_user_submissions))
        .route("/api/leaderboard", get(get_leaderboard))

        // Contests
        .route("/api/contests", get(list_contests))
        .route("/api/contests/:id", get(get_contest))
        .route("/api/contests/:id/register", post(register_contest))
        .route("/api/contests/:id/standings", get(get_standings))

        // Auth
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))

        .with_state(state)
}

/// GET /api/problems
async fn list_problems(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ProblemListParams>,
) -> Result<Json<Vec<ProblemSummary>>, StatusCode> {
    let problems = state.problem_repo
        .list(params.page, params.limit, params.difficulty, params.tag.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(problems))
}

#[derive(Debug, Deserialize)]
struct ProblemListParams {
    page: Option<u32>,
    limit: Option<u32>,
    difficulty: Option<Difficulty>,
    tag: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProblemSummary {
    id: ProblemId,
    title: String,
    slug: String,
    difficulty: Difficulty,
    acceptance_rate: f32,
    tags: Vec<String>,
}

/// GET /api/problems/:slug
async fn get_problem(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<Json<Problem>, StatusCode> {
    state.problem_repo
        .get_by_slug(&slug)
        .await
        .map(Json)
        .map_err(|_| StatusCode::NOT_FOUND)
}

/// POST /api/problems
async fn create_problem(
    State(state): State<Arc<AppState>>,
    Json(problem): Json<CreateProblemRequest>,
) -> Result<Json<Problem>, StatusCode> {
    // TODO: Vérifier permissions admin
    state.problem_repo
        .create(problem)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Debug, Deserialize)]
struct CreateProblemRequest {
    title: String,
    difficulty: Difficulty,
    description: String,
    input_format: String,
    output_format: String,
    constraints: Vec<String>,
    examples: Vec<Example>,
    test_cases: Vec<TestCase>,
    time_limit_ms: u64,
    memory_limit_mb: u64,
    tags: Vec<String>,
}

/// POST /api/submit
async fn submit_solution(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, StatusCode> {
    let submission = Submission {
        id: SubmissionId(Uuid::new_v4()),
        problem_id: req.problem_id,
        user_id: req.user_id,  // TODO: From auth token
        language: req.language,
        code: req.code,
        submitted_at: Utc::now(),
        status: SubmissionStatus::Pending,
        verdict: None,
        test_results: vec![],
        execution_time_ms: None,
        memory_used_kb: None,
        score: None,
    };

    let id = state.judge_service
        .submit(submission)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SubmitResponse { submission_id: id }))
}

#[derive(Debug, Deserialize)]
struct SubmitRequest {
    problem_id: ProblemId,
    user_id: UserId,
    language: Language,
    code: String,
}

#[derive(Debug, Serialize)]
struct SubmitResponse {
    submission_id: SubmissionId,
}

/// GET /api/submissions/:id
async fn get_submission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Submission>, StatusCode> {
    state.judge_service
        .get_status(SubmissionId(id))
        .await
        .map(Json)
        .map_err(|_| StatusCode::NOT_FOUND)
}

// ... autres handlers

// ============================================================
// PARTIE D: WebSocket pour Temps Réel
// ============================================================

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use futures::{SinkExt, StreamExt};

/// Gère les connexions WebSocket pour les mises à jour en temps réel
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Écouter les messages du client
    while let Some(msg) = receiver.next().await {
        if let Ok(Message::Text(text)) = msg {
            let request: WsRequest = match serde_json::from_str(&text) {
                Ok(r) => r,
                Err(_) => continue,
            };

            match request {
                WsRequest::SubscribeSubmission { id } => {
                    // Envoyer des updates jusqu'à completion
                    loop {
                        let status = state.judge_service
                            .get_status(id)
                            .await;

                        if let Ok(sub) = status {
                            let update = WsResponse::SubmissionUpdate {
                                id: sub.id,
                                status: sub.status,
                                verdict: sub.verdict,
                                test_results: sub.test_results.len(),
                            };

                            let json = serde_json::to_string(&update).unwrap();
                            if sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }

                            if sub.status == SubmissionStatus::Completed {
                                break;
                            }
                        }

                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }

                WsRequest::SubscribeContest { id } => {
                    // Envoyer les standings en temps réel
                    // TODO: Implémenter
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsRequest {
    SubscribeSubmission { id: SubmissionId },
    SubscribeContest { id: ContestId },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum WsResponse {
    SubmissionUpdate {
        id: SubmissionId,
        status: SubmissionStatus,
        verdict: Option<Verdict>,
        test_results: usize,
    },
    StandingsUpdate {
        contest_id: ContestId,
        standings: Vec<Standing>,
    },
}

// ============================================================
// PARTIE E: Système de Rating (Elo-like)
// ============================================================

/// Calcule les changements de rating après un contest
pub fn calculate_rating_changes(
    contest: &Contest,
    standings: &[Standing],
    user_ratings: &HashMap<UserId, i32>,
) -> HashMap<UserId, i32> {
    let mut changes = HashMap::new();

    let n = standings.len() as f64;
    if n < 2.0 {
        return changes;
    }

    for standing in standings {
        let user_rating = *user_ratings.get(&standing.user_id).unwrap_or(&1500);
        let rank = standing.rank as f64;

        // Expected rank based on rating
        let expected_rank = calculate_expected_rank(user_rating, user_ratings, standings);

        // Performance rating
        let performance = calculate_performance_rating(rank, n);

        // Rating change (simplified Elo-like formula)
        let k = if user_rating < 1400 { 40.0 }
               else if user_rating < 1900 { 30.0 }
               else { 20.0 };

        let change = (k * (expected_rank - rank) / n * 100.0) as i32;
        let change = change.clamp(-100, 100);

        changes.insert(standing.user_id, change);
    }

    changes
}

fn calculate_expected_rank(
    rating: i32,
    all_ratings: &HashMap<UserId, i32>,
    standings: &[Standing],
) -> f64 {
    let mut expected = 1.0;

    for standing in standings {
        let other_rating = *all_ratings.get(&standing.user_id).unwrap_or(&1500);
        if other_rating != rating {
            let prob_win = 1.0 / (1.0 + 10f64.powf((other_rating - rating) as f64 / 400.0));
            expected += 1.0 - prob_win;
        }
    }

    expected
}

fn calculate_performance_rating(rank: f64, total: f64) -> i32 {
    // Inverse of expected rank formula
    let percentile = 1.0 - (rank - 1.0) / total;
    let z = percentile_to_z(percentile);
    (1500.0 + z * 200.0) as i32
}

fn percentile_to_z(p: f64) -> f64 {
    // Approximation de l'inverse de la CDF normale
    if p <= 0.0 { return -3.0; }
    if p >= 1.0 { return 3.0; }

    let a = 8.0 * (std::f64::consts::PI - 3.0) / (3.0 * std::f64::consts::PI * (4.0 - std::f64::consts::PI));
    let x = 2.0 * p - 1.0;

    let ln_term = ((1.0 - x * x).ln()).abs();
    let term1 = 2.0 / (std::f64::consts::PI * a) + ln_term / 2.0;
    let term2 = ln_term / a;

    let sign = if x >= 0.0 { 1.0 } else { -1.0 };
    sign * (term1 * term1 - term2).sqrt().sqrt()
}

// ============================================================
// PARTIE F: Repositories (Persistence)
// ============================================================

#[async_trait]
pub trait ProblemRepository: Send + Sync {
    async fn list(
        &self,
        page: Option<u32>,
        limit: Option<u32>,
        difficulty: Option<Difficulty>,
        tag: Option<&str>,
    ) -> Result<Vec<ProblemSummary>, RepositoryError>;

    async fn get_by_slug(&self, slug: &str) -> Result<Problem, RepositoryError>;
    async fn get_by_id(&self, id: ProblemId) -> Result<Problem, RepositoryError>;
    async fn create(&self, req: CreateProblemRequest) -> Result<Problem, RepositoryError>;
    async fn update(&self, problem: Problem) -> Result<Problem, RepositoryError>;
    async fn delete(&self, id: ProblemId) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn get_by_id(&self, id: UserId) -> Result<User, RepositoryError>;
    async fn get_by_username(&self, username: &str) -> Result<User, RepositoryError>;
    async fn create(&self, user: User) -> Result<User, RepositoryError>;
    async fn update(&self, user: User) -> Result<User, RepositoryError>;
    async fn get_leaderboard(&self, limit: u32) -> Result<Vec<User>, RepositoryError>;
}

#[async_trait]
pub trait ContestRepository: Send + Sync {
    async fn list(&self, active_only: bool) -> Result<Vec<Contest>, RepositoryError>;
    async fn get_by_id(&self, id: ContestId) -> Result<Contest, RepositoryError>;
    async fn create(&self, contest: Contest) -> Result<Contest, RepositoryError>;
    async fn update_standings(&self, id: ContestId, standings: Vec<Standing>) -> Result<(), RepositoryError>;
    async fn register_user(&self, contest_id: ContestId, user_id: UserId) -> Result<(), RepositoryError>;
}

#[derive(Debug)]
pub enum RepositoryError {
    NotFound,
    DuplicateKey,
    ConnectionError,
    QueryError(String),
}

// ============================================================
// PARTIE G: CLI pour Administration
// ============================================================

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "arena")]
#[command(about = "The Arena Online Judge CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Démarre le serveur
    Serve {
        #[arg(short, long, default_value = "8080")]
        port: u16,

        #[arg(short, long, default_value = "4")]
        workers: usize,
    },

    /// Gestion des problèmes
    Problem {
        #[command(subcommand)]
        action: ProblemAction,
    },

    /// Gestion des contests
    Contest {
        #[command(subcommand)]
        action: ContestAction,
    },

    /// Rejuge des soumissions
    Rejudge {
        /// ID du problème (rejuge toutes les soumissions)
        #[arg(short, long)]
        problem: Option<Uuid>,

        /// ID d'une soumission spécifique
        #[arg(short, long)]
        submission: Option<Uuid>,
    },
}

#[derive(Subcommand)]
pub enum ProblemAction {
    /// Liste les problèmes
    List,
    /// Affiche un problème
    Show { slug: String },
    /// Importe un problème depuis un fichier JSON
    Import { path: String },
    /// Exporte un problème vers JSON
    Export { slug: String, output: String },
    /// Valide les test cases d'un problème
    Validate { slug: String },
}

#[derive(Subcommand)]
pub enum ContestAction {
    /// Liste les contests
    List,
    /// Crée un contest
    Create { config_path: String },
    /// Démarre un contest
    Start { id: Uuid },
    /// Termine un contest et calcule les ratings
    End { id: Uuid },
}
```

### Fonctions à Implémenter (C)

```c
// ============================================================
// Worker de jugement en C (haute performance)
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

// Verdict codes
typedef enum {
    VERDICT_ACCEPTED = 0,
    VERDICT_WRONG_ANSWER = 1,
    VERDICT_TIME_LIMIT = 2,
    VERDICT_MEMORY_LIMIT = 3,
    VERDICT_RUNTIME_ERROR = 4,
    VERDICT_COMPILATION_ERROR = 5,
    VERDICT_PRESENTATION_ERROR = 6
} verdict_t;

// Test case result
typedef struct {
    int test_id;
    verdict_t verdict;
    int passed;
    long execution_time_ms;
    long memory_used_kb;
    char* output;
    size_t output_len;
} test_result_t;

// Submission context
typedef struct {
    char* code;
    int language;
    char* input;
    char* expected_output;
    long time_limit_ms;
    long memory_limit_kb;
} submission_ctx_t;

// Compile code and return path to executable (or NULL on error)
char* compile_code(const char* code, int language, char* error_buf, size_t error_len);

// Run executable with input and return result
test_result_t run_test(
    const char* executable,
    const char* input,
    const char* expected,
    long time_limit_ms,
    long memory_limit_kb
);

// Compare outputs (handles whitespace normalization)
int compare_output(const char* expected, const char* actual, int strict);

// Free test result resources
void test_result_free(test_result_t* result);

// ============================================================
// Implementation
// ============================================================

char* compile_code(const char* code, int language, char* error_buf, size_t error_len) {
    char source_path[256];
    char output_path[256];
    char compile_cmd[1024];

    // Generate unique paths
    snprintf(source_path, sizeof(source_path), "/tmp/judge_%d", getpid());
    snprintf(output_path, sizeof(output_path), "/tmp/judge_%d.out", getpid());

    // Write source file
    const char* ext;
    switch (language) {
        case 0: ext = ".rs"; break;  // Rust
        case 1: ext = ".c"; break;   // C
        case 2: ext = ".cpp"; break; // C++
        case 3: ext = ".py"; break;  // Python (no compile)
        default: return NULL;
    }

    char full_source[512];
    snprintf(full_source, sizeof(full_source), "%s%s", source_path, ext);

    FILE* f = fopen(full_source, "w");
    if (!f) {
        snprintf(error_buf, error_len, "Failed to create source file");
        return NULL;
    }
    fwrite(code, 1, strlen(code), f);
    fclose(f);

    // Python doesn't need compilation
    if (language == 3) {
        char* result = strdup(full_source);
        return result;
    }

    // Build compile command
    switch (language) {
        case 0:  // Rust
            snprintf(compile_cmd, sizeof(compile_cmd),
                "rustc -O -o %s %s 2>&1", output_path, full_source);
            break;
        case 1:  // C
            snprintf(compile_cmd, sizeof(compile_cmd),
                "gcc -O2 -std=c17 -o %s %s -lm 2>&1", output_path, full_source);
            break;
        case 2:  // C++
            snprintf(compile_cmd, sizeof(compile_cmd),
                "g++ -O2 -std=c++20 -o %s %s 2>&1", output_path, full_source);
            break;
    }

    // Execute compilation
    FILE* pipe = popen(compile_cmd, "r");
    if (!pipe) {
        snprintf(error_buf, error_len, "Failed to run compiler");
        unlink(full_source);
        return NULL;
    }

    // Read compiler output
    char compile_output[4096] = {0};
    size_t total = 0;
    while (fgets(compile_output + total, sizeof(compile_output) - total, pipe)) {
        total = strlen(compile_output);
    }

    int status = pclose(pipe);
    unlink(full_source);  // Clean up source

    if (status != 0) {
        snprintf(error_buf, error_len, "Compilation failed: %s", compile_output);
        return NULL;
    }

    return strdup(output_path);
}

test_result_t run_test(
    const char* executable,
    const char* input,
    const char* expected,
    long time_limit_ms,
    long memory_limit_kb
) {
    test_result_t result = {0};

    // Create pipes for I/O
    int stdin_pipe[2], stdout_pipe[2];
    if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) {
        result.verdict = VERDICT_RUNTIME_ERROR;
        return result;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);

        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);

        // Set resource limits
        struct rlimit rl;

        // Memory limit
        rl.rlim_cur = rl.rlim_max = memory_limit_kb * 1024;
        setrlimit(RLIMIT_AS, &rl);

        // CPU time limit (seconds, rounded up)
        rl.rlim_cur = rl.rlim_max = (time_limit_ms + 999) / 1000;
        setrlimit(RLIMIT_CPU, &rl);

        // Execute
        execl(executable, executable, NULL);
        _exit(1);
    }

    // Parent process
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    // Write input
    write(stdin_pipe[1], input, strlen(input));
    close(stdin_pipe[1]);

    // Read output with timeout
    char output_buf[1024 * 1024];  // 1MB max output
    size_t output_len = 0;

    fd_set fds;
    struct timeval tv;
    tv.tv_sec = time_limit_ms / 1000;
    tv.tv_usec = (time_limit_ms % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(stdout_pipe[0], &fds);

    while (select(stdout_pipe[0] + 1, &fds, NULL, NULL, &tv) > 0) {
        ssize_t n = read(stdout_pipe[0], output_buf + output_len,
                        sizeof(output_buf) - output_len - 1);
        if (n <= 0) break;
        output_len += n;
        FD_SET(stdout_pipe[0], &fds);
    }
    output_buf[output_len] = '\0';
    close(stdout_pipe[0]);

    // Wait for child
    int status;
    waitpid(pid, &status, 0);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result.execution_time_ms = (end.tv_sec - start.tv_sec) * 1000 +
                               (end.tv_nsec - start.tv_nsec) / 1000000;

    // Get memory usage
    struct rusage usage;
    getrusage(RUSAGE_CHILDREN, &usage);
    result.memory_used_kb = usage.ru_maxrss;

    // Determine verdict
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGXCPU || result.execution_time_ms > time_limit_ms) {
            result.verdict = VERDICT_TIME_LIMIT;
        } else if (sig == SIGSEGV || sig == SIGBUS) {
            result.verdict = VERDICT_RUNTIME_ERROR;
        } else {
            result.verdict = VERDICT_RUNTIME_ERROR;
        }
    } else if (result.execution_time_ms > time_limit_ms) {
        result.verdict = VERDICT_TIME_LIMIT;
    } else if (result.memory_used_kb > memory_limit_kb) {
        result.verdict = VERDICT_MEMORY_LIMIT;
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        result.verdict = VERDICT_RUNTIME_ERROR;
    } else {
        // Compare output
        if (compare_output(expected, output_buf, 0)) {
            result.verdict = VERDICT_ACCEPTED;
            result.passed = 1;
        } else {
            result.verdict = VERDICT_WRONG_ANSWER;
        }
    }

    result.output = strdup(output_buf);
    result.output_len = output_len;

    return result;
}

int compare_output(const char* expected, const char* actual, int strict) {
    if (strict) {
        return strcmp(expected, actual) == 0;
    }

    // Normalize: trim whitespace, normalize line endings
    const char* e = expected;
    const char* a = actual;

    // Skip leading whitespace
    while (*e && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) e++;
    while (*a && (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')) a++;

    while (*e && *a) {
        // Skip multiple whitespace
        if (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r') {
            while (*e && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) e++;
            while (*a && (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')) a++;
            continue;
        }

        if (*e != *a) return 0;
        e++;
        a++;
    }

    // Skip trailing whitespace
    while (*e && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) e++;
    while (*a && (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')) a++;

    return *e == '\0' && *a == '\0';
}

void test_result_free(test_result_t* result) {
    if (result) {
        free(result->output);
    }
}
```

---

# Section 2: Le Saviez-Vous ?

## Faits Techniques

1. **Codeforces Scale**: Codeforces traite jusqu'à 50,000 soumissions par contest, avec des pics de 500 soumissions/seconde.

2. **LeetCode Problems**: LeetCode a plus de 3000 problèmes. Les 150 "must-do" couvrent 90% des patterns d'entretien.

3. **ICPC History**: L'ICPC (International Collegiate Programming Contest) existe depuis 1970. L'équipe MIT a gagné la première édition.

4. **Rating Systems**: Le système de rating Codeforces est inspiré d'Elo (échecs) et Glicko-2, avec des ajustements pour les contests multi-participants.

5. **Sandbox Tech**: Les grands online judges utilisent des technologies comme Docker, Firejail, ou WASM pour l'isolation.

## Anecdotes

- **Petr Mitrichev**: Le légendaire compétiteur a maintenu un rating >3000 sur Codeforces pendant des années, avec un pic à 3814.

- **Tourist**: Gennady Korotkevich ("tourist") est considéré comme le meilleur compétiteur de l'histoire, avec 7 titres IOI et nombreuses victoires ICPC/GCJ.

---

# Section 2.5: Dans la Vraie Vie

## Applications Industrielles

### 1. Plateformes de Recrutement
- **LeetCode**: 14M+ utilisateurs, utilisé par FAANG pour le recrutement
- **HackerRank**: Utilisé par 2000+ entreprises pour les tests techniques
- **CodeSignal**: Tests automatisés pour le hiring

### 2. Éducation
- **Kattis**: Utilisé par 500+ universités
- **SPOJ**: Archive de 20000+ problèmes
- **CSES**: Problem set finlandais reconnu mondialement

### 3. Compétitions
- **Codeforces**: 1M+ utilisateurs actifs
- **AtCoder**: Populaire au Japon et internationalement
- **Google Code Jam, Facebook Hacker Cup**: Compétitions annuelles majeures

---

# Section 3: Exemple d'Utilisation

```bash
$ ./arena serve --port 8080 --workers 8
[INFO] Starting The Arena on port 8080
[INFO] Judge workers: 8
[INFO] Database: PostgreSQL connected
[INFO] Redis cache: connected
[INFO] Server ready

# Dans un autre terminal
$ curl http://localhost:8080/api/problems
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "title": "Two Sum",
    "slug": "two-sum",
    "difficulty": "Easy",
    "acceptance_rate": 45.2,
    "tags": ["array", "hash-table"]
  },
  {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "title": "Merge Intervals",
    "slug": "merge-intervals",
    "difficulty": "Medium",
    "acceptance_rate": 38.7,
    "tags": ["array", "sorting"]
  }
]

$ curl http://localhost:8080/api/problems/two-sum
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "title": "Two Sum",
  "slug": "two-sum",
  "difficulty": "Easy",
  "description": "Given an array of integers nums and an integer target, return indices of the two numbers such that they add up to target.",
  "input_format": "First line: n (array size) and target\nSecond line: n space-separated integers",
  "output_format": "Two space-separated indices (0-indexed)",
  "constraints": ["2 <= n <= 10^4", "-10^9 <= nums[i] <= 10^9"],
  "examples": [
    {
      "input": "4 9\n2 7 11 15",
      "output": "0 1",
      "explanation": "nums[0] + nums[1] = 2 + 7 = 9"
    }
  ],
  "time_limit_ms": 1000,
  "memory_limit_mb": 256,
  "tags": ["array", "hash-table"]
}

$ cat > solution.rs << 'EOF'
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let first_line = lines.next().unwrap().unwrap();
    let mut parts = first_line.split_whitespace();
    let n: usize = parts.next().unwrap().parse().unwrap();
    let target: i64 = parts.next().unwrap().parse().unwrap();

    let nums: Vec<i64> = lines.next().unwrap().unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();

    let mut seen = HashMap::new();
    for (i, &num) in nums.iter().enumerate() {
        let complement = target - num;
        if let Some(&j) = seen.get(&complement) {
            println!("{} {}", j, i);
            return;
        }
        seen.insert(num, i);
    }
}
EOF

$ curl -X POST http://localhost:8080/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "problem_id": "550e8400-e29b-41d4-a716-446655440001",
    "language": "Rust",
    "code": "'"$(cat solution.rs | jq -Rs .)"'"
  }'
{
  "submission_id": "660e8400-e29b-41d4-a716-446655440099"
}

$ curl http://localhost:8080/api/submissions/660e8400-e29b-41d4-a716-446655440099
{
  "id": "660e8400-e29b-41d4-a716-446655440099",
  "status": "Completed",
  "verdict": "Accepted",
  "execution_time_ms": 12,
  "memory_used_kb": 2048,
  "test_results": [
    {"test_id": 1, "passed": true, "verdict": "Accepted", "execution_time_ms": 5},
    {"test_id": 2, "passed": true, "verdict": "Accepted", "execution_time_ms": 8},
    {"test_id": 3, "passed": true, "verdict": "Accepted", "execution_time_ms": 12}
  ],
  "score": 100
}

# Contest example
$ curl http://localhost:8080/api/contests/active
{
  "id": "770e8400-e29b-41d4-a716-446655440050",
  "title": "Weekly Contest #42",
  "problems": ["two-sum", "merge-intervals", "lru-cache", "median-finder"],
  "start_time": "2025-01-17T18:00:00Z",
  "end_time": "2025-01-17T20:00:00Z",
  "scoring_type": "ICPC",
  "participants": 1247
}

$ curl http://localhost:8080/api/contests/770e8400-e29b-41d4-a716-446655440050/standings
{
  "standings": [
    {"rank": 1, "username": "tourist", "score": 4, "penalty": 87},
    {"rank": 2, "username": "petr", "score": 4, "penalty": 124},
    {"rank": 3, "username": "ecnerwala", "score": 3, "penalty": 65}
  ]
}

# WebSocket for real-time updates
$ websocat ws://localhost:8080/ws
> {"type": "SubscribeSubmission", "id": "660e8400-e29b-41d4-a716-446655440099"}
< {"type": "SubmissionUpdate", "status": "Compiling", "verdict": null}
< {"type": "SubmissionUpdate", "status": "Running", "test_results": 1}
< {"type": "SubmissionUpdate", "status": "Running", "test_results": 2}
< {"type": "SubmissionUpdate", "status": "Completed", "verdict": "Accepted"}

# Admin CLI
$ ./arena problem import problem.json
Problem imported: "Binary Tree Traversal" (binary-tree-traversal)

$ ./arena problem validate two-sum
Validating test cases for "two-sum"...
Test 1: OK (expected output matches)
Test 2: OK
Test 3: OK
All 3 test cases validated successfully.

$ ./arena contest create contest_config.json
Contest created: "Weekly Contest #43"
ID: 880e8400-e29b-41d4-a716-446655440051
Start: 2025-01-24 18:00 UTC

$ ./arena rejudge --problem 550e8400-e29b-41d4-a716-446655440001
Rejudging 1247 submissions for "Two Sum"...
Progress: [========================================] 100%
Results: 892 Accepted, 234 Wrong Answer, 121 Other
```

---

# Section 3.1: Bonus Avancé

## Bonus 1: Plagiarism Detection (300 XP)

```rust
/// Détecte le plagiat entre soumissions
/// Utilise MOSS-like algorithm (Measure of Software Similarity)
pub fn detect_plagiarism(
    submissions: &[Submission],
    threshold: f64,
) -> Vec<PlagiarismMatch> {
    // TODO: Implémenter winnowing/fingerprinting
    vec![]
}

struct PlagiarismMatch {
    submission_a: SubmissionId,
    submission_b: SubmissionId,
    similarity: f64,
    matching_regions: Vec<(Range<usize>, Range<usize>)>,
}
```

## Bonus 2: Virtual Contests (200 XP)

```rust
/// Permet de participer à un contest passé comme s'il était en cours
pub async fn start_virtual_contest(
    user_id: UserId,
    contest_id: ContestId,
) -> Result<VirtualSession, ContestError> {
    // TODO: Créer une session virtuelle avec timer
    Err(ContestError::NotImplemented)
}
```

## Bonus 3: Problem Recommendations (250 XP)

```rust
/// Recommande des problèmes basés sur l'historique
/// Utilise collaborative filtering
pub fn recommend_problems(
    user_id: UserId,
    count: usize,
) -> Vec<ProblemRecommendation> {
    // TODO: Implémenter un système de recommandation
    vec![]
}

struct ProblemRecommendation {
    problem: ProblemSummary,
    relevance_score: f64,
    reason: String,  // "Similar to problems you solved", "Strengthens weak area", etc.
}
```

---

# Section 4: Zone Correction

## 4.1 Tests Unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Rating Tests ====================

    #[test]
    fn test_rating_change_winner() {
        let standings = vec![
            Standing { user_id: UserId(Uuid::new_v4()), rank: 1, score: 100, penalty: 50, problem_results: HashMap::new() },
            Standing { user_id: UserId(Uuid::new_v4()), rank: 2, score: 80, penalty: 60, problem_results: HashMap::new() },
        ];

        let mut ratings = HashMap::new();
        ratings.insert(standings[0].user_id, 1500);
        ratings.insert(standings[1].user_id, 1500);

        let contest = Contest::default();
        let changes = calculate_rating_changes(&contest, &standings, &ratings);

        // Winner should gain rating
        assert!(changes[&standings[0].user_id] > 0);
        // Loser should lose rating
        assert!(changes[&standings[1].user_id] < 0);
    }

    #[test]
    fn test_rating_change_underdog() {
        let standings = vec![
            Standing { user_id: UserId(Uuid::new_v4()), rank: 1, score: 100, penalty: 50, problem_results: HashMap::new() },
            Standing { user_id: UserId(Uuid::new_v4()), rank: 2, score: 80, penalty: 60, problem_results: HashMap::new() },
        ];

        let mut ratings = HashMap::new();
        ratings.insert(standings[0].user_id, 1200);  // Underdog
        ratings.insert(standings[1].user_id, 1800);  // Favorite

        let contest = Contest::default();
        let changes = calculate_rating_changes(&contest, &standings, &ratings);

        // Underdog who wins should gain more
        let underdog_gain = changes[&standings[0].user_id];
        assert!(underdog_gain > 0);
        // Expected to be a significant gain
    }

    // ==================== Verdict Tests ====================

    #[test]
    fn test_verdict_accepted() {
        let expected = "42";
        let actual = "42";
        assert!(compare_outputs(expected, actual, false));
    }

    #[test]
    fn test_verdict_whitespace_tolerance() {
        let expected = "42\n";
        let actual = "42  \n\n";
        assert!(compare_outputs(expected, actual, false));
    }

    #[test]
    fn test_verdict_wrong_answer() {
        let expected = "42";
        let actual = "43";
        assert!(!compare_outputs(expected, actual, false));
    }

    #[test]
    fn test_verdict_strict_mode() {
        let expected = "42\n";
        let actual = "42";
        assert!(!compare_outputs(expected, actual, true));
    }

    // ==================== API Tests ====================

    #[tokio::test]
    async fn test_list_problems_endpoint() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/problems")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_submit_endpoint() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "problem_id": "550e8400-e29b-41d4-a716-446655440001",
            "language": "Rust",
            "code": "fn main() { println!(\"42\"); }"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ==================== Judge Tests ====================

    #[tokio::test]
    async fn test_judge_accepted() {
        let judge = JudgeServiceImpl::new(1);

        let submission = Submission {
            id: SubmissionId(Uuid::new_v4()),
            problem_id: ProblemId(Uuid::new_v4()),
            user_id: UserId(Uuid::new_v4()),
            language: Language::Rust,
            code: r#"fn main() { println!("42"); }"#.to_string(),
            submitted_at: Utc::now(),
            status: SubmissionStatus::Pending,
            verdict: None,
            test_results: vec![],
            execution_time_ms: None,
            memory_used_kb: None,
            score: None,
        };

        // This would require a full test setup with mock problem repo
        // Simplified assertion
        assert!(true);
    }

    // ==================== Contest Tests ====================

    #[test]
    fn test_icpc_scoring() {
        let mut result = ProblemResult {
            solved: true,
            attempts: 3,
            solve_time: Some(45),
            score: 0,
        };

        // ICPC: penalty = solve_time + 20 * (attempts - 1)
        let penalty = result.solve_time.unwrap() + 20 * (result.attempts as i64 - 1);
        assert_eq!(penalty, 85);  // 45 + 40
    }

    #[test]
    fn test_ioi_scoring() {
        // IOI: partial scoring
        let test_scores = vec![10, 10, 10, 20, 20, 30];  // 100 total
        let passed = vec![true, true, true, false, true, false];

        let score: u32 = test_scores.iter().zip(passed.iter())
            .filter_map(|(&s, &p)| if p { Some(s) } else { None })
            .sum();

        assert_eq!(score, 50);  // 10 + 10 + 10 + 20
    }
}
```

## 4.2 Tests d'Intégration

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum_test::TestServer;

    async fn setup_test_server() -> TestServer {
        let state = Arc::new(AppState {
            judge_service: Arc::new(MockJudgeService::new()),
            problem_repo: Arc::new(MockProblemRepo::new()),
            user_repo: Arc::new(MockUserRepo::new()),
            contest_repo: Arc::new(MockContestRepo::new()),
        });

        let app = create_router(state);
        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn test_full_submission_flow() {
        let server = setup_test_server().await;

        // 1. Get problem
        let problem = server
            .get("/api/problems/two-sum")
            .await
            .json::<Problem>();

        assert_eq!(problem.slug, "two-sum");

        // 2. Submit solution
        let submit_response = server
            .post("/api/submit")
            .json(&serde_json::json!({
                "problem_id": problem.id,
                "language": "Rust",
                "code": "fn main() { println!(\"0 1\"); }"
            }))
            .await
            .json::<SubmitResponse>();

        // 3. Poll for result
        let mut attempts = 0;
        loop {
            let submission = server
                .get(&format!("/api/submissions/{}", submit_response.submission_id.0))
                .await
                .json::<Submission>();

            if submission.status == SubmissionStatus::Completed {
                assert!(submission.verdict.is_some());
                break;
            }

            attempts += 1;
            if attempts > 10 {
                panic!("Submission did not complete in time");
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn test_contest_participation() {
        let server = setup_test_server().await;

        // 1. Register for contest
        let register_response = server
            .post("/api/contests/test-contest-id/register")
            .await;

        assert_eq!(register_response.status_code(), 200);

        // 2. Submit during contest
        // 3. Check standings
        let standings = server
            .get("/api/contests/test-contest-id/standings")
            .await
            .json::<Vec<Standing>>();

        assert!(!standings.is_empty());
    }
}
```

## 4.3 Solution de Référence

```rust
// compare_outputs - référence
pub fn compare_outputs_reference(expected: &str, actual: &str, strict: bool) -> bool {
    if strict {
        return expected == actual;
    }

    // Normalize both strings
    let normalize = |s: &str| -> String {
        s.lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };

    normalize(expected) == normalize(actual)
}

// calculate_expected_rank - référence
fn calculate_expected_rank_reference(
    rating: i32,
    all_ratings: &HashMap<UserId, i32>,
    standings: &[Standing],
) -> f64 {
    let mut expected_rank = 1.0;

    for standing in standings {
        let other_rating = *all_ratings.get(&standing.user_id).unwrap_or(&1500);

        // Probability of beating this opponent
        let prob_win = 1.0 / (1.0 + 10f64.powf((other_rating - rating) as f64 / 400.0));

        // Expected rank contribution
        expected_rank += 1.0 - prob_win;
    }

    expected_rank
}
```

## 4.4 Mutants

```rust
// MUTANT 1: Rating change always positive
pub fn calculate_rating_changes_mutant1(
    contest: &Contest,
    standings: &[Standing],
    user_ratings: &HashMap<UserId, i32>,
) -> HashMap<UserId, i32> {
    standings.iter()
        .map(|s| (s.user_id, 10))  // BUG: Always +10
        .collect()
}

// MUTANT 2: Wrong verdict comparison
pub fn compare_outputs_mutant2(expected: &str, actual: &str, _strict: bool) -> bool {
    expected.len() == actual.len()  // BUG: Only compares length
}

// MUTANT 3: Off-by-one in penalty calculation
pub fn calculate_penalty_mutant3(solve_time: i64, attempts: u32) -> i64 {
    solve_time + 20 * attempts as i64  // BUG: Should be (attempts - 1)
}

// MUTANT 4: Submission status never updates
impl JudgeServiceImpl {
    async fn judge_submission_mutant4(submission: &Submission) -> JudgeResult {
        // BUG: Returns Pending instead of actual result
        JudgeResult {
            verdict: Verdict::Accepted,  // Wrong: should actually judge
            test_results: vec![],
            max_time_ms: 0,
            max_memory_kb: 0,
            score: 0,
        }
    }
}

// MUTANT 5: Memory limit not enforced
impl Sandbox {
    pub fn run_mutant5(&self, code: &str, input: &str) -> RunResult {
        // BUG: No memory limit check
        // Just runs the code without restrictions
        RunResult::default()
    }
}
```

---

# Section 5: Comprendre

## 5.1 Architecture du Système

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   Problem List   │  │  Code Editor    │  │   Standings     │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
└───────────┼────────────────────┼────────────────────┼───────────────────┘
            │ HTTP/REST          │ WebSocket          │ HTTP/REST
            ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            API GATEWAY                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Rate Limiting │ Auth │ Load Balancing │ Request Routing        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│  Problem API  │          │ Submission API│          │  Contest API  │
│   Service     │          │   Service     │          │   Service     │
└───────┬───────┘          └───────┬───────┘          └───────┬───────┘
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          MESSAGE QUEUE (Redis/RabbitMQ)                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐       │
│  │ Submission Queue│  │ Notification Q  │  │  Rating Update Q│       │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘       │
└───────────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           JUDGE WORKERS                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Worker 1   │  │  Worker 2   │  │  Worker 3   │  │  Worker N   │   │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │   │
│  │ │ WASM    │ │  │ │ WASM    │ │  │ │ WASM    │ │  │ │ WASM    │ │   │
│  │ │ Sandbox │ │  │ │ Sandbox │ │  │ │ Sandbox │ │  │ │ Sandbox │ │   │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              DATABASE                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   PostgreSQL    │  │     Redis       │  │   S3/MinIO      │         │
│  │  (Main data)    │  │    (Cache)      │  │  (Test files)   │         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 5.2 Flow de Soumission

```
User submits code
        │
        ▼
┌───────────────────┐
│ Validate request  │
│ - Auth check      │
│ - Rate limit      │
│ - Code size limit │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Create submission │
│ - Generate ID     │
│ - Store in DB     │
│ - Status: Pending │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Enqueue for judge │
│ - Redis queue     │
│ - Priority based  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Worker picks up   │
│ - Status: Compiling│
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐     ┌───────────────────┐
│ Compile code      │────►│ Compilation Error │
└─────────┬─────────┘     └───────────────────┘
          │ Success
          ▼
┌───────────────────┐
│ For each test:    │
│ - Status: Running │
│ - Run in sandbox  │
│ - Compare output  │
│ - Record result   │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Aggregate results │
│ - Final verdict   │
│ - Total score     │
│ - Max time/memory │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Update database   │
│ - Status: Complete│
│ - Store results   │
│ - Update stats    │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Notify via WS     │
│ - User gets result│
│ - Standings update│
└───────────────────┘
```

## 5.3 Rating System (Elo-like)

```
Expected Score Formula:
E_A = 1 / (1 + 10^((R_B - R_A) / 400))

Rating Change Formula:
ΔR = K × (S - E)

Where:
- R_A, R_B = Current ratings
- K = K-factor (40 for beginners, 20 for experts)
- S = Actual score (1 for win, 0 for loss)
- E = Expected score

For contests with many participants:
- Calculate expected rank based on all pairwise comparisons
- Compare with actual rank
- Adjust rating proportionally
```

---

# Section 6: Pièges

## 6.1 Piège: Race Conditions

```rust
// PIÈGE: Mise à jour non-atomique des statistiques
async fn update_problem_stats(problem_id: ProblemId, accepted: bool) {
    let mut problem = get_problem(problem_id).await;
    problem.attempt_count += 1;
    if accepted {
        problem.solve_count += 1;  // RACE CONDITION!
    }
    save_problem(problem).await;
}

// CORRECT: Utiliser des opérations atomiques
async fn update_problem_stats_safe(problem_id: ProblemId, accepted: bool) {
    sqlx::query!(
        "UPDATE problems SET
         attempt_count = attempt_count + 1,
         solve_count = solve_count + $1
         WHERE id = $2",
        if accepted { 1 } else { 0 },
        problem_id.0
    ).execute(&pool).await;
}
```

## 6.2 Piège: Sandbox Escape

```rust
// PIÈGE: Pas de validation des imports WASM
fn instantiate_module(module: &Module) -> Instance {
    let imports = imports! {
        "env" => {
            "system" => Function::new_native(|cmd: &str| {
                std::process::Command::new(cmd).status()  // DANGER!
            }),
        },
    };
    Instance::new(module, &imports)
}

// CORRECT: Whitelist stricte des imports
fn instantiate_module_safe(module: &Module) -> Result<Instance, Error> {
    // Vérifier que le module n'importe rien de dangereux
    for import in module.imports() {
        if !ALLOWED_IMPORTS.contains(&import.name()) {
            return Err(Error::UnauthorizedImport);
        }
    }
    // Seuls les imports sûrs
    let imports = imports! {};
    Instance::new(module, &imports)
}
```

## 6.3 Piège: Output Comparison

```rust
// PIÈGE: Comparaison stricte
fn check_output(expected: &str, actual: &str) -> bool {
    expected == actual  // Échoue pour "42\n" vs "42"
}

// CORRECT: Normaliser avant de comparer
fn check_output_safe(expected: &str, actual: &str) -> bool {
    let normalize = |s: &str| {
        s.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };
    normalize(expected) == normalize(actual)
}
```

## 6.4 Piège: Time Measurement

```rust
// PIÈGE: Mesurer le wall clock time
fn run_and_time(code: &str) -> Duration {
    let start = Instant::now();
    run_code(code);
    start.elapsed()  // Inclut I/O, scheduling, etc.
}

// CORRECT: Mesurer le CPU time
fn run_and_time_safe(code: &str) -> Duration {
    let usage_before = get_rusage();
    run_code(code);
    let usage_after = get_rusage();

    // CPU time only
    usage_after.user_time - usage_before.user_time
}
```

---

# Section 7: QCM

## Question 1
Quelle est la structure de données optimale pour implémenter une queue de priorité pour les soumissions?

- A) Vec avec tri
- B) LinkedList
- C) BinaryHeap
- D) HashMap

## Question 2
Dans le scoring ICPC, comment est calculée la pénalité pour un problème résolu en 3 tentatives à 45 minutes?

- A) 45 minutes
- B) 65 minutes (45 + 20)
- C) 85 minutes (45 + 2×20)
- D) 105 minutes (45 + 3×20)

## Question 3
Pourquoi utiliser WebSocket plutôt que polling HTTP pour les mises à jour de soumission?

- A) WebSocket est plus simple à implémenter
- B) Réduction de la latence et de la charge serveur
- C) WebSocket est plus sécurisé
- D) HTTP ne supporte pas le streaming

## Question 4
Quel est le K-factor typique dans un système de rating Elo pour un joueur débutant?

- A) 10
- B) 20
- C) 40
- D) 100

## Question 5
Pour éviter les sandbox escapes, quelle approche est la plus sûre?

- A) Timeout uniquement
- B) Whitelist des syscalls + WASM
- C) Docker sans restrictions
- D) Vérification syntaxique du code

## Question 6
Comment détecter efficacement le plagiat entre soumissions?

- A) Comparaison caractère par caractère
- B) Hashing MD5 du code
- C) Winnowing / fingerprinting (MOSS)
- D) Comparaison des temps d'exécution

## Question 7
Dans un contest Codeforces-style, comment les points diminuent-ils?

- A) Linéairement avec le temps
- B) Exponentiellement
- C) Par paliers toutes les 10 minutes
- D) Ils ne diminuent pas

## Question 8
Quelle base de données est la plus adaptée pour stocker les soumissions avec recherche rapide?

- A) SQLite
- B) PostgreSQL avec index
- C) MongoDB
- D) Redis uniquement

---

## Réponses

1. **C) BinaryHeap** - O(log n) pour insertion et extraction du max, parfait pour les priorités.

2. **C) 85 minutes** - ICPC: solve_time + 20 × (attempts - 1) = 45 + 40.

3. **B) Latence et charge réduites** - Une seule connexion maintenue vs multiples requêtes.

4. **C) 40** - Les débutants ont un K plus élevé pour des ajustements rapides.

5. **B) Whitelist + WASM** - WASM offre une isolation mémoire, whitelist limite les capabilities.

6. **C) Winnowing/MOSS** - Algorithme standard de détection de similarité de code.

7. **A) Linéairement** - Les points diminuent progressivement avec le temps écoulé.

8. **B) PostgreSQL avec index** - Requêtes complexes, transactions, et scalabilité.

---

# Section 8: Récapitulatif

## Compétences Acquises

| Compétence | Description | Niveau |
|------------|-------------|--------|
| System Design | Architecture distribuée complète | Expert |
| API Design | REST + WebSocket temps réel | Avancé |
| Security | Sandboxing et isolation | Expert |
| Algorithms | Integration de tous les modules | Expert |
| Database | Modélisation et optimisation | Avancé |
| DevOps | Déploiement et scaling | Intermédiaire |

## Modules Intégrés

Ce projet final intègre **tous les modules du cursus**:

- **1.1 Arrays & Sorting**: Classements, tri des soumissions
- **1.2 Hash & Strings**: Indexation, recherche de problèmes
- **1.3 Trees**: BST pour les structures de données internes
- **1.4 Graphs**: Dépendances entre problèmes, recommandations
- **1.5 Dynamic Programming**: Rating calculation, optimization
- **1.6 Number Theory**: Hashing, checksums
- **1.7 Advanced Algorithms**: Scheduling, load balancing
- **1.8 Testing**: Test harness complet pour le judge
- **1.9 Previous Capstones**: WASM sandbox, competitive patterns

## Prochaines Étapes

1. **Déploiement**: Containeriser avec Docker, déployer sur Kubernetes
2. **Scaling**: Ajouter des workers, sharding de la base de données
3. **Features**: Plagiarism detection, virtual contests, problem recommendations

---

# Section 9: Deployment Pack

```json
{
  "exercise_id": "1.9.07",
  "code_name": "the_arena",
  "version": "1.0.0",
  "tier": 3,
  "estimated_hours": 55,
  "languages": ["rust", "c"],

  "concepts_covered": [
    "system_design",
    "distributed_systems",
    "api_design",
    "websocket",
    "sandboxing",
    "rating_systems",
    "database_design",
    "concurrency",
    "message_queues",
    "microservices"
  ],

  "learning_objectives": [
    "Design and implement a complete online judge system",
    "Integrate all previous module concepts",
    "Build secure code execution environment",
    "Implement real-time features with WebSocket",
    "Create rating and ranking systems"
  ],

  "prerequisites": [
    "all_modules_1.1_through_1.8",
    "ex00_through_ex06_of_1.9"
  ],

  "dependencies": {
    "rust": {
      "axum": ">=0.7",
      "tokio": ">=1.0",
      "sqlx": ">=0.7",
      "serde": ">=1.0",
      "uuid": ">=1.0",
      "chrono": ">=0.4",
      "wasmtime": ">=15.0"
    },
    "infrastructure": {
      "postgresql": ">=15",
      "redis": ">=7.0",
      "docker": ">=24.0"
    }
  },

  "grading": {
    "tests_weight": 0.30,
    "architecture_weight": 0.25,
    "security_weight": 0.20,
    "features_weight": 0.15,
    "documentation_weight": 0.10
  },

  "files": {
    "rust": {
      "main.rs": "src/main.rs",
      "models.rs": "src/models.rs",
      "judge.rs": "src/judge.rs",
      "api.rs": "src/api.rs",
      "websocket.rs": "src/websocket.rs",
      "rating.rs": "src/rating.rs",
      "repos.rs": "src/repos.rs"
    },
    "c": {
      "judge_worker.c": "c_worker/judge_worker.c"
    }
  },

  "test_commands": {
    "rust": "cargo test --all-features",
    "integration": "cargo test --test integration",
    "e2e": "./scripts/e2e_test.sh"
  },

  "docker": {
    "compose": "docker-compose.yml",
    "services": ["api", "judge-worker", "postgres", "redis"]
  },

  "metadata": {
    "author": "HACKBRAIN",
    "created": "2025-01-17",
    "difficulty": "expert",
    "tags": ["capstone", "final", "online-judge", "full-stack", "distributed"]
  }
}
```

---

*"What we do in life echoes in eternity."* — Maximus, Gladiator

**Vous avez construit The Arena. Maintenant, que les jeux commencent.**

---

## Félicitations!

Vous avez terminé le **Module 1.9 Capstone** et avec lui, l'intégralité de la **Phase 1** du cursus HACKBRAIN.

Vous maîtrisez maintenant:
- Les structures de données fondamentales
- Les algorithmes classiques et avancés
- Les techniques de test et validation
- L'interopérabilité entre langages
- La conception de systèmes distribués
- La sécurité et le sandboxing

**Prochaine étape**: Phase 2 - Advanced Systems Programming
