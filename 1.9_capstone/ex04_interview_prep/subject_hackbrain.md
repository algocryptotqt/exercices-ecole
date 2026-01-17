# Exercice 1.9.04 - Interview Preparation System

## Metadata
- **Nom de code:** the_social_network
- **Tier:** 3 (Synthesis - Integration of all previous modules)
- **Complexité estimée:** Expert (40-50h)
- **Prérequis:** Modules 1.1-1.8, ex00-ex03 of 1.9

---

# Section 1: Prototype & Consigne

## 1.1 Version Culture Pop

> *"You don't get to 500 million users by making enemies. You get there by understanding what people want before they know they want it."*
> — The Social Network (2010)

Dans le monde impitoyable des entretiens techniques FAANG, chaque seconde compte. Mark Zuckerberg a codé FaceMash en une nuit. Eduardo Saverin a résolu le problème de l'algorithme de classement. Les Winklevoss ont eu l'idée. Mais seul celui qui pouvait **exécuter sous pression** a changé le monde.

Votre mission : construire un **système complet de préparation aux entretiens techniques** qui simule l'environnement exact d'un entretien FAANG - de la présentation personnelle au system design en passant par le live coding sous chronomètre.

**Le défi ultime:** Créer un simulateur qui génère des questions, évalue les réponses en temps réel, et fournit un feedback détaillé comparable à celui d'un interviewer senior de Google.

## 1.2 Version Académique

### Contexte Formel

La préparation aux entretiens techniques constitue un domaine d'étude combinant psychologie cognitive, algorithmique, et communication professionnelle. Ce projet implémente un système de simulation d'entretiens techniques basé sur les méthodologies documentées par les principales entreprises technologiques.

### Spécification Formelle

Soit I = (P, T, S, E) un système d'entretien où:
- P : Ensemble des profils candidats
- T : Ensemble des types de questions (behavioral, coding, system design)
- S : Fonction de scoring S: Response × Rubric → [0, 100]
- E : Fonction d'évaluation E: Session → Feedback

### Objectifs Pédagogiques

1. Maîtriser la méthode STAR (Situation, Task, Action, Result) pour les questions comportementales
2. Implémenter un simulateur de live coding avec contraintes temporelles
3. Concevoir un évaluateur de system design basé sur des rubriques formelles
4. Intégrer tous les algorithmes des modules précédents dans un contexte pratique

### Fonctions à Implémenter (Rust)

```rust
// ============================================================
// PARTIE A: Profil et Auto-Présentation (2-minute pitch)
// ============================================================

/// Représente le profil d'un candidat
#[derive(Debug, Clone)]
pub struct CandidateProfile {
    pub name: String,
    pub years_experience: u32,
    pub skills: Vec<Skill>,
    pub experiences: Vec<Experience>,
    pub education: Vec<Education>,
    pub projects: Vec<Project>,
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub level: SkillLevel,        // Beginner, Intermediate, Advanced, Expert
    pub years: f32,
    pub keywords: Vec<String>,    // Pour le matching avec job descriptions
}

#[derive(Debug, Clone)]
pub struct Experience {
    pub company: String,
    pub role: String,
    pub duration_months: u32,
    pub achievements: Vec<Achievement>,
    pub technologies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Achievement {
    pub description: String,
    pub impact: Impact,           // Quantified impact (%, $, users, etc.)
    pub star_story: Option<StarStory>,
}

#[derive(Debug, Clone)]
pub struct StarStory {
    pub situation: String,
    pub task: String,
    pub action: String,
    pub result: String,
}

/// Génère un pitch de 2 minutes personnalisé pour un poste donné
///
/// Complexité: O(n log n) où n = nombre d'expériences (tri par pertinence)
pub fn generate_elevator_pitch(
    profile: &CandidateProfile,
    job_description: &JobDescription,
    max_duration_seconds: u32,
) -> ElevatorPitch;

/// Analyse la pertinence du profil par rapport au poste
/// Retourne un score et des suggestions d'amélioration
pub fn analyze_profile_fit(
    profile: &CandidateProfile,
    job_description: &JobDescription,
) -> ProfileAnalysis;

// ============================================================
// PARTIE B: Questions Comportementales (Behavioral)
// ============================================================

#[derive(Debug, Clone)]
pub struct BehavioralQuestion {
    pub id: u32,
    pub category: BehavioralCategory,  // Leadership, Teamwork, Conflict, Failure, etc.
    pub question: String,
    pub follow_ups: Vec<String>,
    pub evaluation_rubric: BehavioralRubric,
}

#[derive(Debug, Clone)]
pub enum BehavioralCategory {
    Leadership,
    Teamwork,
    ConflictResolution,
    FailureAndLearning,
    Innovation,
    CustomerObsession,      // Amazon LP
    Ownership,              // Amazon LP
    BiasForAction,          // Amazon LP
    DeliverResults,         // Amazon LP
    Googleyness,            // Google
    DriveForExcellence,     // Meta
}

#[derive(Debug, Clone)]
pub struct BehavioralRubric {
    pub star_completeness: RubricItem,    // All STAR components present
    pub specificity: RubricItem,          // Concrete details vs vague
    pub impact_quantification: RubricItem, // Numbers, metrics
    pub relevance: RubricItem,            // Matches the question
    pub authenticity: RubricItem,         // Sounds genuine
}

/// Évalue une réponse STAR selon la rubrique
///
/// Utilise NLP basique pour détecter les composants STAR
pub fn evaluate_star_response(
    response: &str,
    question: &BehavioralQuestion,
) -> StarEvaluation;

/// Génère des questions de suivi basées sur la réponse
pub fn generate_follow_up_questions(
    response: &str,
    original_question: &BehavioralQuestion,
) -> Vec<FollowUpQuestion>;

/// Détecte les red flags dans une réponse (blâme, négativité, vague)
pub fn detect_response_red_flags(response: &str) -> Vec<RedFlag>;

// ============================================================
// PARTIE C: Live Coding Simulation
// ============================================================

#[derive(Debug, Clone)]
pub struct CodingProblem {
    pub id: u32,
    pub title: String,
    pub difficulty: Difficulty,
    pub category: ProblemCategory,
    pub description: String,
    pub examples: Vec<Example>,
    pub constraints: Vec<Constraint>,
    pub hints: Vec<Hint>,
    pub solutions: Vec<ReferenceSolution>,
    pub time_limit_minutes: u32,
    pub evaluation_criteria: CodingRubric,
}

#[derive(Debug, Clone)]
pub enum ProblemCategory {
    ArraysAndStrings,
    LinkedLists,
    TreesAndGraphs,
    DynamicProgramming,
    Sorting,
    Searching,
    Recursion,
    BitManipulation,
    Math,
    Design,
}

#[derive(Debug, Clone)]
pub struct CodingSession {
    pub problem: CodingProblem,
    pub start_time: Instant,
    pub time_limit: Duration,
    pub submissions: Vec<Submission>,
    pub hints_used: Vec<u32>,
    pub clarifying_questions: Vec<ClarifyingQA>,
    pub thought_process: Vec<ThoughtNote>,
}

#[derive(Debug, Clone)]
pub struct Submission {
    pub code: String,
    pub language: Language,
    pub timestamp: Instant,
    pub test_results: Vec<TestResult>,
    pub complexity_analysis: ComplexityAnalysis,
}

#[derive(Debug, Clone)]
pub struct CodingRubric {
    pub correctness: RubricItem,           // Passes all test cases
    pub complexity_optimal: RubricItem,    // Matches expected Big-O
    pub code_quality: RubricItem,          // Clean, readable
    pub edge_cases: RubricItem,            // Handles edge cases
    pub communication: RubricItem,         // Explained approach
    pub testing: RubricItem,               // Wrote/suggested tests
}

/// Lance une session de live coding avec timer
pub fn start_coding_session(
    problem: CodingProblem,
    time_limit: Duration,
) -> CodingSession;

/// Évalue une soumission de code
///
/// - Exécute les tests (sandbox requis)
/// - Analyse la complexité
/// - Évalue la qualité du code
pub fn evaluate_submission(
    session: &CodingSession,
    submission: &Submission,
) -> SubmissionEvaluation;

/// Simule les questions de clarification d'un interviewer
pub fn generate_clarifying_prompt(
    session: &CodingSession,
    candidate_statement: &str,
) -> InterviewerResponse;

/// Analyse le processus de pensée du candidat
pub fn evaluate_thought_process(
    session: &CodingSession,
) -> ThoughtProcessEvaluation;

// ============================================================
// PARTIE D: System Design Interview
// ============================================================

#[derive(Debug, Clone)]
pub struct SystemDesignProblem {
    pub id: u32,
    pub title: String,
    pub description: String,
    pub requirements: Requirements,
    pub scale: ScaleRequirements,
    pub time_limit_minutes: u32,
    pub evaluation_rubric: SystemDesignRubric,
    pub reference_design: ReferenceDesign,
}

#[derive(Debug, Clone)]
pub struct Requirements {
    pub functional: Vec<FunctionalRequirement>,
    pub non_functional: Vec<NonFunctionalRequirement>,
}

#[derive(Debug, Clone)]
pub struct ScaleRequirements {
    pub daily_active_users: u64,
    pub requests_per_second: u64,
    pub data_size_tb: f64,
    pub latency_p99_ms: u32,
    pub availability_nines: f32,  // 99.9 = 3 nines
}

#[derive(Debug, Clone)]
pub struct SystemDesignRubric {
    pub requirements_gathering: RubricItem,  // Asked good questions
    pub high_level_design: RubricItem,       // Solid architecture
    pub detailed_design: RubricItem,         // Deep dive quality
    pub scalability: RubricItem,             // Handles scale
    pub trade_offs: RubricItem,              // Discussed alternatives
    pub bottlenecks: RubricItem,             // Identified & addressed
}

/// Problèmes de system design classiques
pub enum ClassicSystemDesign {
    UrlShortener,           // TinyURL
    PasteService,           // Pastebin
    RateLimiter,
    KeyValueStore,
    UniqueIdGenerator,
    TwitterFeed,
    InstagramFeed,
    ChatSystem,             // WhatsApp
    NotificationSystem,
    SearchAutocomplete,
    WebCrawler,
    VideoStreaming,         // YouTube
    FileStorage,            // Dropbox
    TicketBooking,
}

/// Génère un problème de system design avec requirements
pub fn generate_system_design_problem(
    design_type: ClassicSystemDesign,
    scale: ScaleRequirements,
) -> SystemDesignProblem;

/// Évalue une conception de système
pub fn evaluate_system_design(
    problem: &SystemDesignProblem,
    design: &CandidateDesign,
) -> SystemDesignEvaluation;

/// Génère des questions de deep dive basées sur la conception
pub fn generate_deep_dive_questions(
    design: &CandidateDesign,
) -> Vec<DeepDiveQuestion>;

/// Calcule la capacité et les estimations
pub fn capacity_estimation(
    requirements: &ScaleRequirements,
) -> CapacityEstimate;

// ============================================================
// PARTIE E: Mock Interview Complet (1h)
// ============================================================

#[derive(Debug, Clone)]
pub struct MockInterview {
    pub candidate: CandidateProfile,
    pub position: JobDescription,
    pub format: InterviewFormat,
    pub sections: Vec<InterviewSection>,
    pub total_duration: Duration,
}

#[derive(Debug, Clone)]
pub enum InterviewFormat {
    PhoneScreen,           // 45 min, 1 coding problem
    Onsite {
        rounds: Vec<OnsiteRound>,
    },
    SystemDesign,          // 45-60 min
    Behavioral,            // 45 min
    BarRaiser,             // Amazon specific
}

#[derive(Debug, Clone)]
pub struct InterviewSection {
    pub section_type: SectionType,
    pub duration: Duration,
    pub content: SectionContent,
    pub evaluation: Option<SectionEvaluation>,
}

#[derive(Debug, Clone)]
pub enum SectionType {
    Introduction,          // 2-3 min
    BehavioralQuestions,   // 10-15 min
    CodingProblem,         // 20-25 min
    SystemDesign,          // 35-45 min
    CandidateQuestions,    // 5 min
}

/// Démarre un mock interview complet
pub fn start_mock_interview(
    candidate: CandidateProfile,
    position: JobDescription,
    format: InterviewFormat,
) -> MockInterview;

/// Génère le rapport final d'entretien
pub fn generate_interview_report(
    interview: &MockInterview,
) -> InterviewReport;

/// Calcule le score global avec pondération par section
pub fn calculate_overall_score(
    interview: &MockInterview,
    weights: &SectionWeights,
) -> OverallScore;

// ============================================================
// PARTIE F: Feedback et Amélioration
// ============================================================

#[derive(Debug, Clone)]
pub struct InterviewReport {
    pub overall_score: f32,
    pub decision: HiringDecision,
    pub section_scores: Vec<SectionScore>,
    pub strengths: Vec<Strength>,
    pub areas_for_improvement: Vec<Improvement>,
    pub recommended_practice: Vec<PracticeRecommendation>,
    pub comparison_to_benchmark: BenchmarkComparison,
}

#[derive(Debug, Clone)]
pub enum HiringDecision {
    StrongHire,
    Hire,
    Lean,
    NoHire,
    StrongNoHire,
}

/// Génère un plan de préparation personnalisé
pub fn generate_preparation_plan(
    report: &InterviewReport,
    available_time: Duration,
    target_company: Company,
) -> PreparationPlan;

/// Analyse les patterns de performance sur plusieurs interviews
pub fn analyze_performance_trends(
    interviews: &[MockInterview],
) -> PerformanceTrends;

/// Compare les performances aux benchmarks de l'industrie
pub fn compare_to_industry_benchmark(
    interviews: &[MockInterview],
    target_level: Level,  // L3, L4, L5, etc.
) -> BenchmarkComparison;
```

### Fonctions à Implémenter (C)

```c
// ============================================================
// Interview Timer et Session Management
// ============================================================

#include <time.h>
#include <signal.h>

typedef struct {
    time_t start_time;
    time_t end_time;
    int duration_seconds;
    int warning_at_seconds;  // When to show warning
    int is_running;
    void (*on_timeout)(void*);
    void (*on_warning)(void*);
    void* callback_data;
} interview_timer_t;

typedef struct {
    char* code;
    size_t code_len;
    time_t submission_time;
    int test_passed;
    int test_total;
    double execution_time_ms;
} submission_t;

typedef struct {
    submission_t* submissions;
    size_t num_submissions;
    size_t capacity;
    interview_timer_t timer;
    int hints_used;
    char** clarifying_questions;
    size_t num_questions;
} coding_session_t;

// Timer functions
interview_timer_t* timer_create(int duration_seconds, int warning_at);
int timer_start(interview_timer_t* timer);
int timer_remaining(interview_timer_t* timer);
void timer_destroy(interview_timer_t* timer);

// Session management
coding_session_t* session_create(int time_limit_seconds);
int session_add_submission(coding_session_t* session, const char* code);
int session_use_hint(coding_session_t* session);
void session_destroy(coding_session_t* session);

// ============================================================
// STAR Response Parser (Basic NLP)
// ============================================================

typedef enum {
    STAR_SITUATION = 0,
    STAR_TASK = 1,
    STAR_ACTION = 2,
    STAR_RESULT = 3,
    STAR_COMPONENT_COUNT = 4
} star_component_t;

typedef struct {
    char* text;
    star_component_t component;
    float confidence;
} star_segment_t;

typedef struct {
    star_segment_t* segments;
    size_t num_segments;
    float completeness_score;  // 0.0 - 1.0
    int has_quantified_result;
    int has_specific_actions;
} star_analysis_t;

// Keywords that indicate each STAR component
typedef struct {
    const char** situation_keywords;
    size_t num_situation;
    const char** task_keywords;
    size_t num_task;
    const char** action_keywords;
    size_t num_action;
    const char** result_keywords;
    size_t num_result;
} star_keywords_t;

// Initialize default keywords
star_keywords_t* star_keywords_default(void);

// Parse a response into STAR components
star_analysis_t* star_parse(const char* response, star_keywords_t* keywords);

// Score the response
float star_score(star_analysis_t* analysis);

// Free resources
void star_analysis_destroy(star_analysis_t* analysis);
void star_keywords_destroy(star_keywords_t* keywords);

// ============================================================
// System Design Components
// ============================================================

typedef struct {
    uint64_t daily_active_users;
    uint64_t requests_per_second;
    double data_size_tb;
    uint32_t latency_p99_ms;
    float availability_nines;
} scale_requirements_t;

typedef struct {
    uint64_t storage_bytes;
    uint64_t bandwidth_bps;
    uint32_t num_servers;
    uint32_t num_db_shards;
    uint64_t cache_size_bytes;
} capacity_estimate_t;

// Back-of-envelope calculations
capacity_estimate_t* estimate_capacity(scale_requirements_t* scale);

// Calculate required throughput
uint64_t calculate_qps(uint64_t daily_users, double avg_requests_per_user);

// Calculate storage requirements
uint64_t calculate_storage(
    uint64_t num_records,
    uint64_t record_size_bytes,
    int replication_factor,
    int years_retention
);

// Calculate number of servers needed
uint32_t calculate_servers(
    uint64_t qps,
    uint64_t qps_per_server,
    float headroom_factor  // e.g., 1.3 for 30% headroom
);

void capacity_estimate_destroy(capacity_estimate_t* estimate);

// ============================================================
// Code Analysis (for interview feedback)
// ============================================================

typedef struct {
    int num_functions;
    int num_loops;
    int max_nesting_depth;
    int num_variables;
    int lines_of_code;
    int num_comments;
    float comment_ratio;
} code_metrics_t;

typedef struct {
    char* issue;
    int line_number;
    char* suggestion;
    int severity;  // 1-5
} code_issue_t;

typedef struct {
    code_metrics_t metrics;
    code_issue_t* issues;
    size_t num_issues;
    float quality_score;  // 0-100
} code_review_t;

// Analyze code quality
code_review_t* review_code(const char* code, const char* language);

// Check for common interview code issues
int check_edge_cases_handled(const char* code);
int check_input_validation(const char* code);
int check_magic_numbers(const char* code);

void code_review_destroy(code_review_t* review);
```

---

# Section 2: Le Saviez-Vous ?

## Faits Techniques

1. **Google Interview Stats**: Google reçoit ~3 millions de candidatures par an et n'embauche que ~0.2%. Le taux d'acceptation est plus bas que Harvard (4.5%).

2. **STAR Method Origin**: La méthode STAR a été développée par DDI (Development Dimensions International) dans les années 1980 pour standardiser les entretiens comportementaux.

3. **LeetCode Economy**: LeetCode compte plus de 3000 problèmes. Les top performers ont résolu plus de 2000 problèmes. La plateforme a été fondée en 2015 par un ex-employé de Google.

4. **Amazon's Bar Raiser**: Amazon a un "Bar Raiser" dans chaque boucle d'entretiens - quelqu'un d'un autre département qui a un pouvoir de veto et doit s'assurer que le candidat est meilleur que 50% des employés actuels au même niveau.

5. **System Design Time**: Dans un entretien de 45 minutes de system design, les candidats qui passent les 5-10 premières minutes à poser des questions de clarification réussissent 40% mieux que ceux qui se lancent directement dans la solution.

## Anecdotes

- **Jeff Dean's Interview**: Jeff Dean (Google Fellow) a passé son entretien Google en 1999. Il a résolu un problème NP-complet en temps polynomial pendant l'entretien. L'interviewer pensait que c'était impossible jusqu'à ce qu'il vérifie.

- **Le rejet de Brian Acton**: Brian Acton a été rejeté par Twitter et Facebook avant de co-fonder WhatsApp (vendu à Facebook pour $19B).

---

# Section 2.5: Dans la Vraie Vie

## Applications Industrielles

### 1. Plateformes de Recrutement Tech
- **HackerRank, LeetCode, CodeSignal**: Utilisent des systèmes similaires pour évaluer les candidats
- **Karat**: Conduit des entretiens techniques externalisés pour des entreprises comme Indeed
- **Pramp**: Matching peer-to-peer pour la pratique

### 2. Formation Interne
- **Google's Interview Training**: Les nouveaux interviewers passent par un programme de certification
- **Meta's Bootcamp**: 6 semaines de formation incluant des mock interviews

### 3. Préparation Académique
- **Stanford CS courses**: Incluent des sessions de préparation aux entretiens
- **MIT 6.031**: Enseigne les techniques de code review utilisées en entretien

---

# Section 3: Exemple d'Utilisation

```bash
$ cargo run --release

=== INTERVIEW PREPARATION SYSTEM ===
[1] Profile Setup
[2] Practice Behavioral
[3] Practice Coding
[4] Practice System Design
[5] Full Mock Interview
[6] View Progress
[0] Exit

Selection: 1

=== PROFILE SETUP ===
Name: Alice Chen
Years of experience: 4
Current role: Software Engineer @ Startup

Adding experience...
Company: TechStartup Inc.
Role: Backend Engineer
Duration (months): 36
Achievement: "Reduced API latency by 60% through Redis caching layer"
Impact type [percentage/users/revenue]: percentage
Impact value: 60

Add STAR story for this achievement? [y/n]: y

Situation: Our API response times were 800ms average, causing user complaints
Task: I was tasked with improving backend performance without major refactoring
Action: I analyzed slow queries, implemented Redis caching for hot data,
        added connection pooling, and created a cache invalidation strategy
Result: API latency dropped from 800ms to 320ms (60% reduction),
        user complaints decreased by 75%, and we saw 15% improvement in conversion

Profile saved!

Selection: 2

=== BEHAVIORAL PRACTICE ===
Category: Leadership
Question: "Tell me about a time when you had to lead a project without formal authority."

Your response: [Recording... 2:34]

=== EVALUATION ===
STAR Completeness: 85/100
- Situation: FOUND (clear context provided)
- Task: FOUND (responsibility defined)
- Action: FOUND (specific steps taken)
- Result: PARTIAL (impact mentioned but not quantified)

Specificity: 70/100
- Good: Mentioned specific technologies
- Improve: Add exact metrics (team size, timeline, outcomes)

Red Flags: None detected

Suggested follow-up questions:
1. "How did you handle disagreements within the team?"
2. "What would you do differently if you could do it again?"

Overall Score: 78/100 (Good, but needs more quantification)

Selection: 3

=== CODING PRACTICE ===
Difficulty: Medium
Category: Arrays and Strings
Time Limit: 25 minutes

[PROBLEM] Two Sum Variations
Given an array of integers and a target sum, find all unique pairs
that sum to the target. Handle duplicates appropriately.

Examples:
Input: nums = [1, 2, 3, 2, 4, 1], target = 4
Output: [[1, 3], [2, 2]]

Constraints:
- 1 <= nums.length <= 10^5
- -10^9 <= nums[i] <= 10^9

Commands: [submit] [hint] [clarify] [time]

> clarify: Should the pairs be in sorted order?
Interviewer: Good question! Yes, each pair should have the smaller number first,
             and the output should be sorted by first element.

> clarify: What about empty array or no valid pairs?
Interviewer: Return an empty list in both cases.

[TIME: 22:45 remaining]

> submit
```rust
pub fn find_pairs(nums: Vec<i32>, target: i32) -> Vec<Vec<i32>> {
    use std::collections::HashMap;
    let mut count: HashMap<i32, i32> = HashMap::new();
    for &n in &nums {
        *count.entry(n).or_insert(0) += 1;
    }

    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for &n in &nums {
        let complement = target - n;
        let pair = (n.min(complement), n.max(complement));

        if seen.contains(&pair) {
            continue;
        }

        if n == complement {
            if *count.get(&n).unwrap_or(&0) >= 2 {
                result.push(vec![n, n]);
                seen.insert(pair);
            }
        } else if count.contains_key(&complement) {
            result.push(vec![pair.0, pair.1]);
            seen.insert(pair);
        }
    }

    result.sort();
    result
}
```

=== SUBMISSION EVALUATION ===
Test Results: 15/15 passed

Correctness: 100/100
- All test cases passed including edge cases

Complexity Analysis:
- Time: O(n) - Single pass with HashMap
- Space: O(n) - HashMap storage
- Expected: O(n) time, O(n) space
- Rating: OPTIMAL

Code Quality: 85/100
- Good: Clear variable names, proper use of standard library
- Improve: Could add brief comments for the two-pointer alternative

Communication: 90/100
- Good: Asked clarifying questions before coding
- Good: Handled edge cases explicitly

Time Used: 8:23 / 25:00
- Excellent time management

Overall: 94/100 (Strong Hire signal for this problem)

Selection: 4

=== SYSTEM DESIGN ===
Problem: Design a URL Shortener (like TinyURL)
Time Limit: 45 minutes

Scale Requirements:
- 100M daily active users
- 500M URLs shortened per month
- 100:1 read/write ratio
- URLs expire after 5 years

[Phase 1: Requirements Gathering - 5 min]

> question: What is the maximum URL length we need to support?
Good question. Assume 2KB max for the original URL.

> question: Do we need custom short URLs?
Yes, users should be able to request custom aliases.

> question: Analytics requirements?
Track click count, geographic distribution, referrer data.

[TIME: 40:00 remaining]

[Phase 2: Capacity Estimation - 5 min]

Your estimates:
- Write QPS: 500M / 30 days / 86400 sec ≈ 200 QPS
- Read QPS: 200 * 100 = 20,000 QPS
- Storage (5 years): 500M * 12 * 5 * 2KB ≈ 60TB
- Cache: 20% hot URLs, ~12TB

System: Your estimates are reasonable. Read QPS is actually the bottleneck.

[Phase 3: High-Level Design - 15 min]
...

=== FINAL EVALUATION ===
Requirements Gathering: 90/100
High-Level Design: 85/100
Scalability: 80/100
Trade-offs Discussion: 75/100
Overall: 83/100 (Hire)

Selection: 5

=== FULL MOCK INTERVIEW (45 min) ===
Position: Senior Software Engineer @ Google
Format: Phone Screen

[0:00-2:00] Introduction
Your 2-minute pitch was evaluated...
Score: 88/100

[2:00-12:00] Behavioral
Question about conflict resolution...
STAR Score: 82/100

[12:00-40:00] Coding
Problem: LRU Cache Implementation
Score: 91/100

[40:00-45:00] Candidate Questions
You asked 3 thoughtful questions about team culture.

=== MOCK INTERVIEW COMPLETE ===

Overall Score: 87/100
Decision: HIRE

Strengths:
- Strong algorithmic problem solving
- Good communication during coding
- Well-structured STAR responses

Areas for Improvement:
- Quantify behavioral responses more
- Consider more edge cases upfront
- Practice system design scalability

Recommended Practice:
1. Complete 5 more medium DP problems
2. Practice 3 system design problems
3. Record and review STAR responses

Next mock interview scheduled for: [Set reminder]
```

---

# Section 3.1: Bonus Avancé

## Bonus 1: AI-Powered Interview Feedback (250 XP)

```rust
/// Utilise un modèle de langage local pour générer du feedback
///
/// Intègre llama.cpp ou similar pour l'analyse
pub fn ai_feedback(
    response: &str,
    question: &BehavioralQuestion,
) -> AiFeedback;

/// Génère des variations de questions de suivi contextuelles
pub fn ai_follow_up_generator(
    conversation_history: &[ConversationTurn],
) -> Vec<FollowUpQuestion>;
```

## Bonus 2: Video Recording & Analysis (200 XP)

```rust
/// Enregistre une session vidéo de l'entretien
///
/// Analyse: temps de réponse, hésitations, langage corporel (si webcam)
pub fn record_interview_session(
    interview: &mut MockInterview,
    video_config: VideoConfig,
) -> RecordingSession;

/// Transcrit et analyse la session
pub fn analyze_recording(
    recording: &RecordingSession,
) -> RecordingAnalysis;
```

## Bonus 3: Competitive Leaderboard (150 XP)

```rust
/// Compare les performances avec d'autres utilisateurs (anonymisé)
pub fn submit_to_leaderboard(
    interview_result: &InterviewReport,
    anonymous_id: &str,
) -> LeaderboardPosition;

/// Récupère les statistiques globales
pub fn get_benchmark_stats(
    target_company: Company,
    target_level: Level,
) -> BenchmarkStats;
```

---

# Section 4: Zone Correction

## 4.1 Tests Unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ==================== STAR Parser Tests ====================

    #[test]
    fn test_star_complete_response() {
        let response = "
            In my previous role at TechCorp (situation), I was tasked with
            reducing our API latency which was affecting user experience (task).
            I analyzed the slow endpoints, implemented Redis caching, and
            optimized database queries (action). As a result, we achieved a
            60% reduction in latency and improved user satisfaction scores
            by 25% (result).
        ";

        let evaluation = evaluate_star_response(response, &leadership_question());

        assert!(evaluation.has_situation);
        assert!(evaluation.has_task);
        assert!(evaluation.has_action);
        assert!(evaluation.has_result);
        assert!(evaluation.completeness_score >= 0.9);
    }

    #[test]
    fn test_star_missing_result() {
        let response = "
            At my last company (situation), I needed to improve performance (task).
            I implemented caching and optimized queries (action).
        ";

        let evaluation = evaluate_star_response(response, &leadership_question());

        assert!(evaluation.has_situation);
        assert!(evaluation.has_task);
        assert!(evaluation.has_action);
        assert!(!evaluation.has_result);
        assert!(evaluation.completeness_score < 0.8);
    }

    #[test]
    fn test_star_detects_quantified_results() {
        let response = "The result was a 45% improvement in throughput.";
        let evaluation = evaluate_star_response(response, &generic_question());

        assert!(evaluation.has_quantified_result);
    }

    #[test]
    fn test_red_flag_detection_blame() {
        let response = "The project failed because my manager didn't support me
                        and the team was incompetent.";

        let flags = detect_response_red_flags(response);

        assert!(flags.iter().any(|f| f.flag_type == RedFlagType::BlamesOthers));
    }

    #[test]
    fn test_red_flag_detection_vague() {
        let response = "I did some things and it worked out.";

        let flags = detect_response_red_flags(response);

        assert!(flags.iter().any(|f| f.flag_type == RedFlagType::TooVague));
    }

    // ==================== Profile Matching Tests ====================

    #[test]
    fn test_profile_skill_matching() {
        let profile = CandidateProfile {
            skills: vec![
                Skill { name: "Rust".into(), level: SkillLevel::Advanced, .. },
                Skill { name: "Python".into(), level: SkillLevel::Expert, .. },
            ],
            ..Default::default()
        };

        let job = JobDescription {
            required_skills: vec!["Rust".into(), "Python".into()],
            ..Default::default()
        };

        let analysis = analyze_profile_fit(&profile, &job);

        assert!(analysis.skill_match_percentage >= 90.0);
    }

    #[test]
    fn test_elevator_pitch_generation() {
        let profile = create_test_profile();
        let job = create_test_job_description();

        let pitch = generate_elevator_pitch(&profile, &job, 120);

        assert!(pitch.duration_seconds <= 120);
        assert!(pitch.highlights.len() >= 2);
        assert!(pitch.text.contains(&profile.name));
    }

    // ==================== Coding Session Tests ====================

    #[test]
    fn test_coding_session_timer() {
        let problem = create_test_problem();
        let session = start_coding_session(problem, Duration::from_secs(1500));

        assert!(session.time_remaining() <= Duration::from_secs(1500));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_submission_evaluation_correctness() {
        let problem = two_sum_problem();
        let session = start_coding_session(problem, Duration::from_secs(1500));

        let submission = Submission {
            code: CORRECT_TWO_SUM_SOLUTION.to_string(),
            language: Language::Rust,
            ..Default::default()
        };

        let eval = evaluate_submission(&session, &submission);

        assert_eq!(eval.test_results.passed, eval.test_results.total);
        assert!(eval.correctness_score >= 95.0);
    }

    #[test]
    fn test_submission_complexity_analysis() {
        let submission = Submission {
            code: r#"
                fn two_sum(nums: Vec<i32>, target: i32) -> Vec<i32> {
                    for i in 0..nums.len() {
                        for j in i+1..nums.len() {
                            if nums[i] + nums[j] == target {
                                return vec![i as i32, j as i32];
                            }
                        }
                    }
                    vec![]
                }
            "#.to_string(),
            ..Default::default()
        };

        let analysis = analyze_complexity(&submission);

        assert_eq!(analysis.time_complexity, Complexity::O_N_SQUARED);
        assert_eq!(analysis.space_complexity, Complexity::O_1);
    }

    // ==================== System Design Tests ====================

    #[test]
    fn test_capacity_estimation() {
        let scale = ScaleRequirements {
            daily_active_users: 100_000_000,
            requests_per_second: 20_000,
            data_size_tb: 60.0,
            latency_p99_ms: 100,
            availability_nines: 4.0,
        };

        let estimate = capacity_estimation(&scale);

        assert!(estimate.num_servers > 0);
        assert!(estimate.storage_bytes > 0);
        assert!(estimate.num_db_shards > 1); // Should recommend sharding
    }

    #[test]
    fn test_url_shortener_design_evaluation() {
        let problem = generate_system_design_problem(
            ClassicSystemDesign::UrlShortener,
            moderate_scale(),
        );

        let design = CandidateDesign {
            components: vec![
                Component::LoadBalancer,
                Component::ApplicationServer,
                Component::Database,
                Component::Cache,
            ],
            ..Default::default()
        };

        let eval = evaluate_system_design(&problem, &design);

        assert!(eval.high_level_design_score >= 60.0);
    }

    // ==================== Mock Interview Tests ====================

    #[test]
    fn test_mock_interview_flow() {
        let candidate = create_test_profile();
        let position = google_swe_l4();

        let interview = start_mock_interview(
            candidate,
            position,
            InterviewFormat::PhoneScreen,
        );

        assert_eq!(interview.sections.len(), 4); // Intro, Behavioral, Coding, Questions
        assert!(interview.total_duration <= Duration::from_secs(45 * 60));
    }

    #[test]
    fn test_interview_report_generation() {
        let interview = completed_mock_interview();
        let report = generate_interview_report(&interview);

        assert!(report.overall_score >= 0.0 && report.overall_score <= 100.0);
        assert!(!report.strengths.is_empty() || !report.areas_for_improvement.is_empty());
    }

    #[test]
    fn test_hiring_decision_thresholds() {
        let scores = vec![95.0, 85.0, 70.0, 55.0, 40.0];
        let expected = vec![
            HiringDecision::StrongHire,
            HiringDecision::Hire,
            HiringDecision::Lean,
            HiringDecision::NoHire,
            HiringDecision::StrongNoHire,
        ];

        for (score, expected_decision) in scores.iter().zip(expected.iter()) {
            let decision = score_to_decision(*score);
            assert_eq!(decision, *expected_decision);
        }
    }
}
```

## 4.2 Tests de Validation

```rust
#[cfg(test)]
mod validation_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_star_parser_no_panic(response in "\\PC*") {
            let _ = evaluate_star_response(&response, &generic_question());
        }

        #[test]
        fn fuzz_profile_matching(
            skills in prop::collection::vec("[a-zA-Z]+", 0..20),
            required in prop::collection::vec("[a-zA-Z]+", 0..10),
        ) {
            let profile = CandidateProfile {
                skills: skills.iter().map(|s| Skill {
                    name: s.clone(),
                    ..Default::default()
                }).collect(),
                ..Default::default()
            };

            let job = JobDescription {
                required_skills: required,
                ..Default::default()
            };

            let analysis = analyze_profile_fit(&profile, &job);
            assert!(analysis.skill_match_percentage >= 0.0);
            assert!(analysis.skill_match_percentage <= 100.0);
        }
    }

    #[test]
    fn validate_behavioral_categories_coverage() {
        let categories = vec![
            BehavioralCategory::Leadership,
            BehavioralCategory::Teamwork,
            BehavioralCategory::ConflictResolution,
            BehavioralCategory::FailureAndLearning,
            BehavioralCategory::Innovation,
        ];

        for category in categories {
            let questions = get_questions_for_category(category);
            assert!(questions.len() >= 5, "Each category needs at least 5 questions");
        }
    }

    #[test]
    fn validate_coding_problems_have_solutions() {
        let problems = get_all_coding_problems();

        for problem in problems {
            assert!(!problem.solutions.is_empty(),
                    "Problem {} has no reference solution", problem.id);
            assert!(problem.time_limit_minutes >= 15);
            assert!(problem.time_limit_minutes <= 60);
        }
    }

    #[test]
    fn validate_system_design_rubrics_complete() {
        let designs = vec![
            ClassicSystemDesign::UrlShortener,
            ClassicSystemDesign::RateLimiter,
            ClassicSystemDesign::KeyValueStore,
        ];

        for design_type in designs {
            let problem = generate_system_design_problem(design_type, default_scale());
            let rubric = &problem.evaluation_rubric;

            assert!(rubric.requirements_gathering.max_score > 0);
            assert!(rubric.high_level_design.max_score > 0);
            assert!(rubric.scalability.max_score > 0);
        }
    }
}
```

## 4.3 Solution de Référence

```rust
// Solution de référence pour l'évaluateur STAR
pub fn evaluate_star_response_reference(
    response: &str,
    question: &BehavioralQuestion,
) -> StarEvaluation {
    let response_lower = response.to_lowercase();

    // Keywords indicating each STAR component
    let situation_indicators = [
        "at my", "in my", "when i was", "while working", "during",
        "previous", "last year", "back when", "situation"
    ];

    let task_indicators = [
        "i was tasked", "my responsibility", "i needed to", "the goal",
        "objective was", "challenge was", "problem was", "i had to"
    ];

    let action_indicators = [
        "i implemented", "i created", "i developed", "i led", "i built",
        "i analyzed", "i designed", "i coordinated", "i worked with",
        "steps i took", "my approach"
    ];

    let result_indicators = [
        "as a result", "the outcome", "we achieved", "this led to",
        "improved by", "reduced by", "increased by", "resulted in",
        "success", "impact"
    ];

    let has_situation = situation_indicators.iter()
        .any(|&ind| response_lower.contains(ind));
    let has_task = task_indicators.iter()
        .any(|&ind| response_lower.contains(ind));
    let has_action = action_indicators.iter()
        .any(|&ind| response_lower.contains(ind));
    let has_result = result_indicators.iter()
        .any(|&ind| response_lower.contains(ind));

    // Check for quantified results
    let quantified_pattern = regex::Regex::new(r"\d+%|\$\d+|\d+\s*(users|customers|percent|times)")
        .unwrap();
    let has_quantified_result = quantified_pattern.is_match(&response);

    // Calculate completeness
    let components_present = [has_situation, has_task, has_action, has_result]
        .iter()
        .filter(|&&x| x)
        .count();

    let completeness_score = (components_present as f32 / 4.0) * 100.0;

    // Bonus for quantification
    let quantification_bonus = if has_quantified_result { 10.0 } else { 0.0 };

    // Check specificity (presence of specific details)
    let specificity_score = calculate_specificity(&response);

    // Check relevance to question
    let relevance_score = calculate_relevance(&response, &question.question);

    StarEvaluation {
        has_situation,
        has_task,
        has_action,
        has_result,
        has_quantified_result,
        completeness_score: (completeness_score + quantification_bonus).min(100.0),
        specificity_score,
        relevance_score,
        overall_score: (completeness_score + specificity_score + relevance_score) / 3.0,
        feedback: generate_star_feedback(
            has_situation, has_task, has_action, has_result, has_quantified_result
        ),
    }
}

fn calculate_specificity(response: &str) -> f32 {
    let mut score = 0.0;

    // Check for specific technologies
    let tech_patterns = regex::Regex::new(
        r"(?i)(rust|python|java|kubernetes|aws|docker|redis|postgres|mongodb)"
    ).unwrap();
    if tech_patterns.is_match(response) {
        score += 20.0;
    }

    // Check for specific numbers
    let number_pattern = regex::Regex::new(r"\d+").unwrap();
    let number_count = number_pattern.find_iter(response).count();
    score += (number_count as f32 * 5.0).min(30.0);

    // Check for specific time references
    let time_patterns = regex::Regex::new(
        r"(?i)(week|month|year|day|hour|sprint|quarter)"
    ).unwrap();
    if time_patterns.is_match(response) {
        score += 15.0;
    }

    // Check for specific role mentions
    let role_patterns = regex::Regex::new(
        r"(?i)(manager|engineer|developer|team lead|cto|ceo|director)"
    ).unwrap();
    if role_patterns.is_match(response) {
        score += 10.0;
    }

    // Length bonus (more detailed responses)
    let word_count = response.split_whitespace().count();
    if word_count >= 100 {
        score += 15.0;
    } else if word_count >= 50 {
        score += 10.0;
    }

    score.min(100.0)
}
```

## 4.4 Mutants (Tests de Mutation)

```rust
// MUTANT 1: Inverted STAR detection
pub fn evaluate_star_response_mutant1(response: &str, question: &BehavioralQuestion) -> StarEvaluation {
    let mut eval = evaluate_star_response_reference(response, question);
    // BUG: Inverted detection
    eval.has_situation = !eval.has_situation;
    eval
}

// MUTANT 2: Always returns perfect score
pub fn evaluate_star_response_mutant2(response: &str, question: &BehavioralQuestion) -> StarEvaluation {
    StarEvaluation {
        has_situation: true,
        has_task: true,
        has_action: true,
        has_result: true,
        has_quantified_result: true,
        completeness_score: 100.0,
        specificity_score: 100.0,
        relevance_score: 100.0,
        overall_score: 100.0,
        feedback: vec![],
    }
}

// MUTANT 3: Off-by-one in component counting
pub fn evaluate_star_response_mutant3(response: &str, question: &BehavioralQuestion) -> StarEvaluation {
    let mut eval = evaluate_star_response_reference(response, question);
    // BUG: Wrong calculation
    eval.completeness_score = (eval.completeness_score / 100.0 * 3.0 / 4.0) * 100.0;
    eval
}

// MUTANT 4: Case-sensitive matching (misses uppercase)
pub fn evaluate_star_response_mutant4(response: &str, question: &BehavioralQuestion) -> StarEvaluation {
    // BUG: No lowercase conversion
    let has_situation = response.contains("situation");
    // ... rest of implementation
    StarEvaluation::default()
}

// MUTANT 5: Wrong capacity calculation
pub fn capacity_estimation_mutant(scale: &ScaleRequirements) -> CapacityEstimate {
    let mut estimate = capacity_estimation_reference(scale);
    // BUG: Using wrong factor
    estimate.num_servers = estimate.num_servers / 10; // Underestimates by 10x
    estimate
}
```

---

# Section 5: Comprendre

## 5.1 L'Art de l'Entretien Technique

### Anatomie d'un Entretien FAANG

Un entretien technique moderne est divisé en plusieurs phases distinctes, chacune évaluant des compétences différentes:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHONE SCREEN (45-60 min)                    │
├─────────────────────────────────────────────────────────────────┤
│  [0-5 min]    Introduction & Pitch                             │
│  [5-15 min]   Behavioral (1-2 questions)                       │
│  [15-40 min]  Coding Problem                                   │
│  [40-45 min]  Candidate Questions                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    ONSITE (4-6 rounds)                         │
├─────────────────────────────────────────────────────────────────┤
│  Round 1: Coding (Data Structures)                             │
│  Round 2: Coding (Algorithms)                                  │
│  Round 3: System Design                                        │
│  Round 4: Behavioral / Leadership                              │
│  Round 5: Team Fit / Hiring Manager                            │
│  [Optional] Round 6: Bar Raiser / Shadow                       │
└─────────────────────────────────────────────────────────────────┘
```

### La Méthode STAR Décomposée

```
SITUATION (10-15% du temps de réponse)
├── Contexte de l'entreprise/équipe
├── Votre rôle à l'époque
└── Contraintes ou défis initiaux

TASK (10-15% du temps)
├── Objectif spécifique assigné
├── Pourquoi c'était important
└── Critères de succès

ACTION (60-70% du temps)
├── Étapes spécifiques que VOUS avez prises
├── Décisions et leur raisonnement
├── Obstacles rencontrés et solutions
└── Collaboration avec l'équipe (votre contribution spécifique)

RESULT (10-15% du temps)
├── Résultats quantifiés (%, $, temps, users)
├── Impact sur l'équipe/entreprise
└── Apprentissages tirés
```

### Framework de Résolution de Problèmes de Coding

```
1. COMPRENDRE (2-3 min)
   ├── Répéter le problème dans vos propres mots
   ├── Identifier les inputs/outputs
   ├── Poser des questions de clarification
   │   ├── Taille des inputs?
   │   ├── Contraintes (negatifs, duplicates, empty)?
   │   ├── Format de sortie attendu?
   │   └── Edge cases?
   └── Écrire 2-3 exemples manuellement

2. EXPLORER (3-5 min)
   ├── Solution brute force d'abord
   ├── Analyser sa complexité
   ├── Identifier les inefficiences
   └── Proposer optimisations

3. PLANIFIER (2-3 min)
   ├── Expliquer l'approche choisie
   ├── Pseudo-code si complexe
   ├── Confirmer avec l'interviewer
   └── Identifier les structures de données

4. CODER (15-20 min)
   ├── Code propre et lisible
   ├── Noms de variables explicites
   ├── Commentaires minimaux mais utiles
   └── Penser à voix haute

5. TESTER (3-5 min)
   ├── Trace manuelle avec exemple simple
   ├── Tester edge cases
   ├── Vérifier la complexité finale
   └── Proposer améliorations possibles
```

### System Design Framework

```
Phase 1: REQUIREMENTS (5-7 min)
├── Functional Requirements
│   ├── Core features (must-have)
│   ├── Extended features (nice-to-have)
│   └── Out of scope (explicitly exclude)
├── Non-Functional Requirements
│   ├── Availability (99.9%? 99.99%?)
│   ├── Latency (P50, P99)
│   ├── Consistency model (strong vs eventual)
│   └── Scale (users, requests, data)
└── Clarifying Questions
    ├── Qui sont les utilisateurs?
    ├── Quelles régions géographiques?
    └── Contraintes techniques existantes?

Phase 2: CAPACITY ESTIMATION (5 min)
├── Traffic Estimates
│   ├── DAU → QPS calculation
│   ├── Read/Write ratio
│   └── Peak traffic multiplier
├── Storage Estimates
│   ├── Size per record
│   ├── Retention period
│   └── Growth projection
└── Bandwidth Estimates
    ├── Ingress (uploads)
    └── Egress (downloads)

Phase 3: HIGH-LEVEL DESIGN (10-15 min)
├── Core Components
│   ├── Load Balancer
│   ├── Application Servers
│   ├── Database(s)
│   ├── Cache Layer
│   └── CDN (if needed)
├── Data Flow
│   ├── Write path
│   └── Read path
└── API Design
    ├── Key endpoints
    └── Request/Response format

Phase 4: DEEP DIVE (10-15 min)
├── Database Design
│   ├── Schema
│   ├── Indexes
│   └── Partitioning strategy
├── Scalability
│   ├── Horizontal scaling
│   ├── Database sharding
│   └── Caching strategy
└── Reliability
    ├── Failure scenarios
    ├── Data replication
    └── Disaster recovery

Phase 5: TRADE-OFFS & WRAP-UP (5 min)
├── Alternatives considered
├── Current design limitations
├── Future improvements
└── Monitoring & Alerting
```

## 5.2 Psychologie de l'Entretien

### Gestion du Stress

```
AVANT L'ENTRETIEN
├── Préparation technique (évidemment)
├── Mock interviews (au moins 5)
├── Sommeil adéquat (pas de "cramming")
├── Exercice physique (cortisol management)
└── Préparation matérielle (setup testé)

PENDANT L'ENTRETIEN
├── Respiration contrôlée (4-7-8 technique)
├── "Thinking out loud" (réduit l'anxiété)
├── Demander du temps si besoin ("Let me think...")
├── Normaliser les erreurs ("Let me reconsider...")
└── Garder le contact visuel (écran pour remote)

SI BLOCAGE
├── Revenir aux bases (brute force)
├── Demander un hint (pas pénalisant si bien fait)
├── Simplifier le problème
├── Dessiner/visualiser
└── Prendre 30 sec de pause mentale
```

### Communication Efficace

| À Faire | À Éviter |
|---------|----------|
| "I think the time complexity is O(n log n) because..." | "I'm not sure, maybe O(n)?" |
| "Before I start coding, let me clarify..." | Commencer à coder immédiatement |
| "I'm going to use a HashMap here for O(1) lookups" | Utiliser sans expliquer |
| "Let me trace through this with the example" | Dire "ça devrait marcher" |
| "This could be improved by..." | Défendre un code suboptimal |

---

# Section 6: Pièges

## 6.1 Pièges STAR

### Piège 1: Le "We" Excessif
```
MAUVAIS: "We implemented a new caching system..."
         "Our team achieved 50% improvement..."

BON:     "I proposed and implemented a caching layer..."
         "As the technical lead, I coordinated the team and
          personally wrote the invalidation logic..."
```

### Piège 2: Résultats Non Quantifiés
```
MAUVAIS: "The project was successful and everyone was happy."

BON:     "The project reduced page load time from 3.2s to 800ms,
          leading to a 15% increase in user engagement and
          $200K annual cost savings on infrastructure."
```

### Piège 3: Blâmer les Autres
```
MAUVAIS: "The project failed because my manager didn't
          allocate enough resources and the requirements
          kept changing."

BON:     "The project faced challenges with scope creep. I learned
          to establish clearer requirements upfront and implemented
          a change request process for my next project, which
          reduced scope changes by 60%."
```

## 6.2 Pièges Coding

### Piège 1: Coder Avant de Comprendre
```rust
// ANTI-PATTERN: Commencer immédiatement
fn solve(nums: Vec<i32>) -> i32 {
    // ???
}

// PATTERN: Clarifier d'abord
// Q: "Can the array be empty?"
// Q: "Are there negative numbers?"
// Q: "What should I return if no solution exists?"
```

### Piège 2: Optimisation Prématurée
```rust
// D'ABORD: Solution brute force qui marche
fn two_sum_brute(nums: &[i32], target: i32) -> Option<(usize, usize)> {
    for i in 0..nums.len() {
        for j in i+1..nums.len() {
            if nums[i] + nums[j] == target {
                return Some((i, j));
            }
        }
    }
    None
}
// "This works but is O(n²). Let me optimize with a HashMap..."

// ENSUITE: Version optimisée
fn two_sum_optimal(nums: &[i32], target: i32) -> Option<(usize, usize)> {
    let mut seen = std::collections::HashMap::new();
    for (i, &n) in nums.iter().enumerate() {
        if let Some(&j) = seen.get(&(target - n)) {
            return Some((j, i));
        }
        seen.insert(n, i);
    }
    None
}
```

### Piège 3: Oublier les Edge Cases
```rust
fn binary_search(arr: &[i32], target: i32) -> Option<usize> {
    // PIÈGES COURANTS:
    // 1. Array vide → retourne None immédiatement
    // 2. Un seul élément → ne pas entrer dans une boucle infinie
    // 3. Overflow de mid → utiliser left + (right - left) / 2
    // 4. Target plus petit/grand que tous les éléments

    if arr.is_empty() {
        return None;
    }

    let mut left = 0;
    let mut right = arr.len() - 1;

    while left <= right {
        let mid = left + (right - left) / 2;  // Évite overflow
        match arr[mid].cmp(&target) {
            Ordering::Equal => return Some(mid),
            Ordering::Less => left = mid + 1,
            Ordering::Greater => {
                if mid == 0 { break; }  // Évite underflow de usize
                right = mid - 1;
            }
        }
    }
    None
}
```

## 6.3 Pièges System Design

### Piège 1: Sauter la Phase Requirements
```
MAUVAIS: "So for a URL shortener, I'll use a NoSQL database
          with consistent hashing..."

BON:     "Before diving into the design, let me clarify some
          requirements. What's our expected scale? Do we need
          custom aliases? What's the read/write ratio? Any
          geographic distribution requirements?"
```

### Piège 2: Over-Engineering
```
MAUVAIS: "We'll need Kubernetes with service mesh, event sourcing,
          CQRS, and a multi-region active-active setup..."
          (pour 1000 utilisateurs)

BON:     "Given the scale of 100K DAU, a simple architecture with
          a single primary database and read replicas should suffice.
          We can evolve to sharding if we grow 10x."
```

### Piège 3: Ignorer les Trade-offs
```
MAUVAIS: "SQL is the best choice for the database."

BON:     "For the database, we have several options:
          - SQL (PostgreSQL): Strong consistency, complex queries,
            but harder to scale horizontally
          - NoSQL (Cassandra): Easy horizontal scaling, high write
            throughput, but eventual consistency
          Given our requirement for strong consistency on financial
          transactions, I'd recommend PostgreSQL with read replicas."
```

---

# Section 7: QCM

## Question 1
Dans la méthode STAR, quelle proportion du temps de réponse devrait être consacrée à la section "Action"?

- A) 10-15%
- B) 30-40%
- C) 60-70%
- D) 90%

## Question 2
Lors d'un entretien de coding, que devriez-vous faire EN PREMIER?

- A) Commencer à coder la solution brute force
- B) Demander des clarifications et comprendre le problème
- C) Écrire les tests
- D) Optimiser pour la meilleure complexité possible

## Question 3
Quelle est la formule pour estimer le QPS à partir du nombre d'utilisateurs quotidiens?

- A) DAU * requests_per_user / 86400
- B) DAU * 86400 / requests_per_user
- C) DAU / requests_per_user
- D) DAU + requests_per_user

## Question 4
Dans un entretien de system design de 45 minutes, combien de temps devrait être consacré aux requirements?

- A) 1-2 minutes
- B) 5-7 minutes
- C) 15-20 minutes
- D) 30 minutes

## Question 5
Quel est un "red flag" dans une réponse comportementale?

- A) Utiliser des chiffres spécifiques
- B) Décrire un échec et ce que vous en avez appris
- C) Dire "nous" au lieu de "je" pour tout le récit
- D) Mentionner des technologies spécifiques

## Question 6
Pour éviter l'integer overflow lors du calcul du milieu dans une binary search, quelle formule utiliser?

- A) (left + right) / 2
- B) left + (right - left) / 2
- C) (left + right) >> 1
- D) left / 2 + right / 2

## Question 7
Quelle disponibilité représente "4 nines"?

- A) 99.9% (8.76h downtime/an)
- B) 99.99% (52.6 min downtime/an)
- C) 99.999% (5.26 min downtime/an)
- D) 99.9999% (31.5s downtime/an)

## Question 8
Lors d'un blocage en entretien de coding, que devriez-vous faire?

- A) Abandonner et passer au problème suivant
- B) Revenir à la solution brute force et demander un hint si nécessaire
- C) Prétendre que vous connaissez la solution
- D) Changer de langage de programmation

---

## Réponses

1. **C) 60-70%** - La section Action est le cœur de la réponse STAR où vous démontrez vos compétences.

2. **B) Demander des clarifications** - Toujours comprendre le problème avant de coder. Cela démontre aussi vos compétences de communication.

3. **A) DAU * requests_per_user / 86400** - Le nombre de requêtes par jour divisé par le nombre de secondes dans une journée.

4. **B) 5-7 minutes** - Suffisamment pour clarifier sans perdre trop de temps sur le design.

5. **C) Dire "nous" au lieu de "je"** - L'interviewer veut comprendre VOTRE contribution spécifique.

6. **B) left + (right - left) / 2** - Évite l'overflow quand left + right dépasse la capacité.

7. **B) 99.99%** - 4 nines = 99.99% = environ 52 minutes de downtime par an maximum.

8. **B) Revenir au brute force** - Montrez que vous pouvez produire une solution fonctionnelle, puis optimisez.

---

# Section 8: Récapitulatif

## Compétences Acquises

| Compétence | Description | Niveau |
|------------|-------------|--------|
| STAR Method | Structurer des réponses comportementales efficaces | Expert |
| Live Coding | Résoudre des problèmes sous pression temporelle | Avancé |
| System Design | Concevoir des systèmes scalables | Avancé |
| Communication | Expliquer sa pensée clairement | Expert |
| Stress Management | Performer sous pression | Intermédiaire |

## Checklist de Préparation

```
PRÉ-ENTRETIEN
□ 5+ STAR stories préparées et pratiquées
□ 50+ problèmes LeetCode (Easy: 20, Medium: 25, Hard: 5)
□ 5+ system design problems étudiés
□ Mock interviews complétés (3+)
□ Company-specific research done
□ Questions pour l'interviewer préparées

JOUR J
□ Setup technique testé
□ Eau et papier à portée
□ Arrivée/connexion 5 min en avance
□ Notes de révision rapide relues
```

## Prochaines Étapes

1. **Court terme**: Compléter l'exercice et pratiquer avec le simulateur
2. **Moyen terme**: Faire 5 mock interviews avec des pairs
3. **Long terme**: Maintenir une routine de 2-3 problèmes par semaine

---

# Section 9: Deployment Pack

```json
{
  "exercise_id": "1.9.04",
  "code_name": "the_social_network",
  "version": "1.0.0",
  "tier": 3,
  "estimated_hours": 45,
  "languages": ["rust", "c"],

  "concepts_covered": [
    "STAR_method",
    "behavioral_interviews",
    "live_coding",
    "system_design",
    "capacity_estimation",
    "mock_interviews",
    "feedback_systems",
    "performance_analysis"
  ],

  "learning_objectives": [
    "Master STAR method for behavioral questions",
    "Practice live coding under time pressure",
    "Design scalable systems with trade-off analysis",
    "Develop self-assessment capabilities"
  ],

  "prerequisites": [
    "module_1.1_arrays_sorting",
    "module_1.2_hash_strings",
    "module_1.3_trees",
    "module_1.4_graphs",
    "module_1.5_dynamic_programming",
    "module_1.8_testing"
  ],

  "grading": {
    "tests_weight": 0.30,
    "code_quality_weight": 0.20,
    "completeness_weight": 0.25,
    "documentation_weight": 0.10,
    "bonus_weight": 0.15
  },

  "files": {
    "rust": {
      "lib.rs": "src/lib.rs",
      "profile.rs": "src/profile.rs",
      "behavioral.rs": "src/behavioral.rs",
      "coding.rs": "src/coding.rs",
      "system_design.rs": "src/system_design.rs",
      "mock_interview.rs": "src/mock_interview.rs"
    },
    "c": {
      "interview.h": "include/interview.h",
      "timer.c": "src/timer.c",
      "star_parser.c": "src/star_parser.c",
      "capacity.c": "src/capacity.c"
    }
  },

  "test_commands": {
    "rust": "cargo test --all-features",
    "c": "make test"
  },

  "docker": {
    "image": "hackbrain/interview-prep:1.0",
    "resources": {
      "memory": "2G",
      "cpu": "2"
    }
  },

  "metadata": {
    "author": "HACKBRAIN",
    "created": "2025-01-17",
    "difficulty": "expert",
    "tags": ["capstone", "interview", "career", "synthesis"]
  }
}
```

---

*"The people who are crazy enough to think they can change the world are the ones who do."* — Steve Jobs (The Social Network inspired)

**Bon courage pour vos entretiens.** Ce n'est pas juste un test technique, c'est une conversation. Montrez qui vous êtes, pas seulement ce que vous savez coder.
