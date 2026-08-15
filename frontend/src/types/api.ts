/**
 * TypeScript definitions mirroring IGRIS backend analysis schemas (Phases 1–11).
 * Strictly preserves epistemological categories, confidence dimensions, and evidence structures.
 */

// ============================================================================
// Phase 1 & 2: File Intelligence & Static Analysis
// ============================================================================

export type FileFormat = "pe" | "elf" | "macho" | "unknown";

export interface HashSet {
  sha256: string;
  sha1: string;
  md5: string;
}

export interface PESection {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_size: number;
  entropy?: number;
  characteristics?: string;
  permissions?: string;
}

export interface PEHeaderInfo {
  machine: string;
  timestamp: number;
  subsystem: string;
  entry_point: number;
  image_base: number;
  number_of_sections: number;
  sections: PESection[];
  imported_dlls: string[];
}

export interface ELFHeaderInfo {
  architecture: string;
  byte_order: string;
  entry_point: number;
  elf_type: string;
  number_of_sections: number;
}

export interface FileMetadata {
  file_format: FileFormat;
  architecture: string;
  is_executable: boolean;
  mime_type: string;
  detected_extension: string;
  pe?: PEHeaderInfo;
  elf?: ELFHeaderInfo;
  string_count: number;
  import_count: number;
}

export interface Sample {
  sample_id: string;
  original_filename: string;
  safe_filename: string;
  hashes: HashSet;
  storage_ref?: string;
  size_bytes: number;
  status: "pending" | "running" | "analyzing" | "completed" | "failed";
  detected_format?: FileFormat | string | null;
  file_metadata?: FileMetadata;
  static_analysis?: StaticAnalysisResult;
  reverse_analysis?: ReverseAnalysisResult;
  behavior_analysis?: BehaviorAnalysisResult;
  detection?: DetectionResult;
  threat_assessment?: ThreatAssessmentResult;
  ml_prediction?: MLPrediction;
  similarity_analysis?: SimilarityReport;
  malware_assessment?: ExplainableAssessment;
  bookmarks?: Bookmark[];
  notes?: AnalystNote[];
  created_at: string;
  updated_at?: string;
}

export interface StaticEvidence {
  evidence_id: string;
  category: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  data: Record<string, unknown>;
}

export interface StaticAnalysisResult {
  sample_id: string;
  file_format: FileFormat;
  entropy: number;
  is_packed: boolean;
  strings_found: string[];
  imports: Record<string, string[]>;
  evidence: StaticEvidence[];
  analyzed_at: string;
  limitations: string[];
}

// ============================================================================
// Phase 3 & 4: Detection & Reverse Analysis
// ============================================================================

export type DetectionStatus = "BENIGN" | "SUSPICIOUS" | "HIGHLY_SUSPICIOUS" | "UNKNOWN";

export interface TriggeredRule {
  rule_id: string;
  name: string;
  version: string;
  severity: "info" | "low" | "medium" | "high";
  confidence: number;
  contribution: number;
  explanation: string;
  matched_conditions: Array<{ field: string; operator: string; value: unknown }>;
}

export interface HeuristicFinding {
  heuristic_id: string;
  name: string;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  contribution: number;
  explanation: string;
  supporting_evidence_ids: string[];
}

export interface ScoreContribution {
  source: string;
  label: string;
  contribution: number;
  confidence: number;
  rationale: string;
}

export interface ScoreBreakdown {
  rule_contributions: ScoreContribution[];
  heuristic_contributions: ScoreContribution[];
  evidence_contributions: ScoreContribution[];
  total: number;
  maximum: number;
}

export interface DetectionResult {
  sample_id: string;
  status: DetectionStatus;
  run_status: "completed" | "failed";
  heuristic_score: number;
  triggered_rules: TriggeredRule[];
  heuristics: HeuristicFinding[];
  evidence: StaticEvidence[];
  behavior_evidence: BehaviorEvidence[];
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  explanation: string;
  score_breakdown: ScoreBreakdown;
  engine_version: string;
  analyzed_at: string;
  limitations: string[];
}

export interface CFGInstruction {
  address: number;
  mnemonic: string;
  operands: string;
  bytes: string;
}

export interface CFGBlock {
  block_id: string;
  start_address: number;
  end_address: number;
  instructions: CFGInstruction[];
  outgoing_edges: string[];
  is_entry?: boolean;
  is_exit?: boolean;
}

export interface CFGEdge {
  source_block_id: string;
  target_block_id: string;
  edge_type: "unconditional" | "conditional_true" | "conditional_false" | "indirect";
}

export interface ControlFlowGraph {
  function_id: string;
  blocks: CFGBlock[];
  edges: CFGEdge[];
}

export interface FunctionSummary {
  function_id: string;
  name: string;
  address: number;
  size_bytes: number;
  block_count: number;
  cyclomatic_complexity: number;
  call_count: number;
  api_calls: string[];
  has_suspicious_patterns: boolean;
}

export interface ReverseEvidence {
  evidence_id: string;
  function_id: string;
  type: string;
  description: string;
  confidence: number;
  related_apis: string[];
  related_strings: string[];
}

export interface ReverseAnalysisResult {
  sample_id: string;
  status: "completed" | "failed";
  functions: FunctionSummary[];
  evidence: ReverseEvidence[];
  analyzed_at: string;
  limitations: string[];
}

// ============================================================================
// Phase 7 & 8: Behavioral Analysis
// ============================================================================

export interface ProcessEvent {
  pid: number;
  ppid: number;
  process_name: string;
  command_line: string;
  timestamp_ms: number;
  image_path?: string;
}

export interface RegistryEvent {
  operation: string;
  key_path: string;
  value_name?: string;
  data?: string;
  timestamp_ms: number;
}

export interface NetworkEvent {
  protocol: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  domain?: string;
  direction: "outbound" | "inbound";
  timestamp_ms: number;
}

export interface DroppedFileEvent {
  path: string;
  size_bytes: number;
  sha256: string;
  timestamp_ms: number;
}

export interface BehaviorEvidence {
  evidence_id: string;
  category: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  supporting_event_ids: string[];
}

export interface BehaviorAnalysisResult {
  sample_id: string;
  status: "completed" | "failed";
  provenance: "synthetic" | "sandbox_execution";
  processes: ProcessEvent[];
  registry_events: RegistryEvent[];
  network_events: NetworkEvent[];
  dropped_files: DroppedFileEvent[];
  evidence: BehaviorEvidence[];
  analyzed_at: string;
  limitations: string[];
}

// ============================================================================
// Phase 5: Threat Intelligence & ATT&CK Mappings
// ============================================================================

export interface CapabilityHypothesis {
  capability_id: string;
  name: string;
  description: string;
  confidence: number;
  supporting_evidence_ids: string[];
}

export interface AttackTechniqueMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  supporting_evidence_ids: string[];
}

export interface EvidenceRelationship {
  source_id: string;
  target_id: string;
  relationship_type: string;
  description: string;
}

export interface ThreatAssessmentResult {
  sample_id: string;
  capabilities: CapabilityHypothesis[];
  attack_techniques: AttackTechniqueMapping[];
  relationships: EvidenceRelationship[];
  narrative: string;
  analyzed_at: string;
}

// ============================================================================
// Phase 6: Machine Learning Prediction
// ============================================================================

export type MLLabel = "benign" | "malware";

export interface MLPrediction {
  sample_id: string;
  model_version: string;
  feature_schema_version: string;
  feature_set: string;
  prediction: MLLabel;
  calibrated_probability: number | null;
  score: number;
  uncertainty: "low" | "medium" | "high";
  important_contributing_features: Array<[string, number]>;
  explanation: string;
  limitations: string[];
}

// ============================================================================
// Phase 10: Sample Similarity Analysis
// ============================================================================

export type SimilarityHypothesis =
  | "identical"
  | "renamed_identical"
  | "modified_variant"
  | "possible_related_cluster"
  | "unrelated";

export interface SimilarityCategoryScore {
  category: "file_metadata" | "sections" | "imports" | "strings" | "functions" | "behavior";
  score: number;
  weight: number;
  contributing_elements: string[];
}

export interface SimilarityMatch {
  target_sample_id: string;
  target_sha256: string;
  target_filename: string;
  overall_similarity: number;
  hypothesis: SimilarityHypothesis;
  confidence: "low" | "medium" | "high";
  category_scores: SimilarityCategoryScore[];
  matching_feature_categories: string[];
  shared_indicators: string[];
  discriminating_differences: string[];
  verdict_hint?: string;
}

export interface SimilarityReport {
  sample_id: string;
  sha256: string;
  created_at: string;
  schema_version: string;
  feature_version: string;
  scoring_version: string;
  total_candidates_evaluated: number;
  matches: SimilarityMatch[];
  summary: string;
  limitations: string[];
  provenance: string;
}

// ============================================================================
// Phase 11: Explainable Malware Assessment
// ============================================================================

export type AssessmentVerdict =
  | "BENIGN"
  | "LIKELY_BENIGN"
  | "SUSPICIOUS"
  | "HIGHLY_SUSPICIOUS"
  | "UNKNOWN";

export type RiskLevel = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type ObservationLevel = "OBSERVED" | "INFERRED" | "POSSIBLE";

export type EvidenceRole = "SUPPORTING" | "CONTRADICTING" | "NEUTRAL";

export type EvidenceCategory =
  | "STATIC"
  | "REVERSE"
  | "BEHAVIOR"
  | "RULES"
  | "ML"
  | "SIMILARITY";

export type EvidenceStrength = "LOW" | "MEDIUM" | "HIGH";

export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH" | "UNAVAILABLE";

export interface AssessmentEvidenceItem {
  evidence_id: string;
  category: EvidenceCategory;
  source: string;
  source_id: string;
  statement: string;
  evidence_type: string;
  observation_level: ObservationLevel;
  role: EvidenceRole;
  strength: EvidenceStrength;
  weight: number;
  provenance: string;
  technical_details: Record<string, unknown>;
  limitations: string[];
}

export interface ConfidenceBreakdown {
  detection_confidence: ConfidenceLevel;
  evidence_quality: ConfidenceLevel;
  behavioral_confidence: ConfidenceLevel;
  similarity_confidence: ConfidenceLevel;
  attribution_confidence: ConfidenceLevel;
  attribution_scope: string; // "cluster_only"
  explanation: string;
}

export interface UncertaintyItem {
  category: string;
  reason: string;
  impact: string;
}

export interface RiskFactor {
  factor_name: string;
  category: EvidenceCategory;
  points: number;
  description: string;
  observation_level: ObservationLevel;
}

export interface RiskScoreDetails {
  score: number;
  formula: string;
  contributing_factors: RiskFactor[];
  mitigating_factors: RiskFactor[];
  unknown_factors: string[];
}

export interface HumanExplanation {
  summary: string;
  observed_findings: string[];
  inferred_findings: string[];
  possible_hypotheses: string[];
  supporting_arguments: string[];
  contradicting_arguments: string[];
  uncertainty_and_unknowns: string[];
  limitations: string[];
}

export interface VerdictSummary {
  sample_id: string;
  sha256: string;
  verdict: AssessmentVerdict;
  risk_level: RiskLevel;
  risk_score: RiskScoreDetails;
  confidence: ConfidenceBreakdown;
  summary: string;
  limitations: string[];
  created_at: string;
}

export interface EvidenceSummary {
  sample_id: string;
  sha256: string;
  total_evidence_count: number;
  supporting_count: number;
  contradicting_count: number;
  neutral_count: number;
  observed_count: number;
  inferred_count: number;
  possible_count: number;
  evidence_items: AssessmentEvidenceItem[];
  disagreements: string[];
  uncertainties: UncertaintyItem[];
  created_at: string;
}

export interface ExplainableAssessment {
  sample_id: string;
  sha256: string;
  schema_version: string;
  created_at: string;
  verdict: AssessmentVerdict;
  risk_level: RiskLevel;
  risk_score: RiskScoreDetails;
  confidence: ConfidenceBreakdown;
  explanation: HumanExplanation;
  evidence_summary: EvidenceSummary;
  limitations: string[];
}

// ============================================================================
// API Response Wrappers
// ============================================================================

export interface SampleCreateResponse {
  sample_id: string;
  original_filename: string;
  safe_filename: string;
  hashes: HashSet;
  size_bytes: number;
  status: string;
  created_at: string;
}

export type SampleResponse = Sample;

export interface SampleListResponse {
  samples: Sample[];
}

export interface FileInfoResponse {
  sample_id: string;
  file_metadata: FileMetadata;
}

export interface StaticAnalysisResponse {
  analysis: StaticAnalysisResult;
}

export interface IndicatorsResponse {
  sample_id: string;
  indicators: StaticEvidence[];
}

export interface DetectionResponse {
  detection: DetectionResult;
}

export interface ReverseAnalysisResponse {
  reverse_analysis: ReverseAnalysisResult;
}

export interface FunctionsResponse {
  sample_id: string;
  functions: FunctionSummary[];
}

export interface FunctionResponse {
  function: FunctionSummary;
}

export interface CFGResponse {
  cfg: ControlFlowGraph;
}

export interface ThreatAssessmentResponse {
  threat_assessment: ThreatAssessmentResult;
}

export interface CapabilitiesResponse {
  sample_id: string;
  capabilities: CapabilityHypothesis[];
}

export interface TechniquesResponse {
  sample_id: string;
  techniques: AttackTechniqueMapping[];
}

export interface EvidenceRelationshipsResponse {
  sample_id: string;
  relationships: EvidenceRelationship[];
}

export interface NarrativeResponse {
  sample_id: string;
  narrative: string;
}

export interface MLPredictionResponse {
  prediction: MLPrediction;
}

export interface BehaviorAnalysisResponse {
  behavior_analysis: BehaviorAnalysisResult;
}

export interface BehaviorEventsResponse {
  sample_id: string;
  events: Array<ProcessEvent | RegistryEvent | NetworkEvent | DroppedFileEvent>;
}

export interface BehaviorEvidenceResponse {
  sample_id: string;
  evidence: BehaviorEvidence[];
}

export interface SimilarityResponse {
  similarity: SimilarityReport;
}

export interface SimilarityResultsResponse {
  sample_id: string;
  similarity: SimilarityReport;
}

export interface VerdictResponse {
  verdict: VerdictSummary;
}

export interface ExplanationResponse {
  sample_id: string;
  sha256: string;
  verdict: AssessmentVerdict;
  explanation: HumanExplanation;
  created_at: string;
}

export interface EvidenceSummaryResponse {
  evidence_summary: EvidenceSummary;
}

export interface AssessmentResponse {
  assessment: ExplainableAssessment;
}

export interface HealthResponse {
  status: "ok" | "degraded" | "error";
  service: string;
  version: string;
  environment: string;
  components: Record<string, "ok" | "degraded" | "unavailable">;
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    status_code: number;
    details?: Record<string, unknown>;
  };
}

// Navigation & UI State Types
export type InvestigationTab =
  | "overview"
  | "pipeline"
  | "verdict"
  | "evidence"
  | "static"
  | "reverse"
  | "behavior"
  | "similarity"
  | "attack"
  | "ml"
  | "report"
  | "evaluation"
  | "robustness"
  | "demo";

export interface AnalysisCoverage {
  static: boolean;
  reverse: boolean;
  behavior: boolean;
  detection: boolean;
  ml: boolean;
  similarity: boolean;
  assessment: boolean;
  totalCompleted: number;
  totalAvailable: number;
}

// ============================================================================
// Phase 13: Investigation Workspace, Bookmarks, Analyst Notes, Reports
// ============================================================================

export type BookmarkTargetType =
  | "evidence"
  | "function"
  | "timeline_event"
  | "cfg_block"
  | "network_event"
  | "registry_event"
  | "process"
  | "dropped_file"
  | "attack_technique"
  | "similarity_match"
  | "custom";

export interface Bookmark {
  bookmark_id: string;
  sample_id: string;
  target_type: BookmarkTargetType;
  target_id: string;
  title: string;
  description?: string | null;
  category?: string | null;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface BookmarkCreateRequest {
  target_type: BookmarkTargetType;
  target_id: string;
  title: string;
  description?: string | null;
  category?: string | null;
  metadata?: Record<string, unknown>;
}

export interface BookmarkResponse {
  bookmark: Bookmark;
}

export interface BookmarksListResponse {
  sample_id: string;
  bookmarks: Bookmark[];
}

export interface AnalystNote {
  note_id: string;
  sample_id: string;
  author: string;
  title: string;
  content: string;
  attached_evidence_ids: string[];
  attached_bookmark_ids: string[];
  tags: string[];
  created_at: string;
  updated_at?: string | null;
}

export interface NoteCreateRequest {
  author?: string;
  title: string;
  content: string;
  attached_evidence_ids?: string[];
  attached_bookmark_ids?: string[];
  tags?: string[];
}

export interface NoteUpdateRequest {
  title?: string;
  content?: string;
  attached_evidence_ids?: string[];
  attached_bookmark_ids?: string[];
  tags?: string[];
}

export interface NoteResponse {
  note: AnalystNote;
}

export interface NotesListResponse {
  sample_id: string;
  notes: AnalystNote[];
}

export interface EvidenceFilterQuery {
  source?: string;
  severity?: string;
  role?: string;
  observation_level?: string;
  process?: string;
  function?: string;
  technique?: string;
  query?: string;
}

export interface EvidenceListResponse {
  sample_id: string;
  total_count: number;
  filtered_count: number;
  items: AssessmentEvidenceItem[];
}

export interface ReportVersionMetadata {
  igris_version: string;
  report_schema_version: string;
  engine_versions: Record<string, string>;
  rule_version: string;
  attack_dataset_version: string;
  generated_at: string;
}

export interface InvestigationReport {
  report_id: string;
  sample_id: string;
  sha256: string;
  version_metadata: ReportVersionMetadata;
  executive_summary: string;
  sample_identification: Record<string, unknown>;
  verdict_assessment: {
    verdict: AssessmentVerdict;
    risk_level: RiskLevel;
    risk_score: RiskScoreDetails;
    confidence_breakdown: ConfidenceBreakdown;
  };
  epistemology_summary: {
    observed_facts: string[];
    inferred_conclusions: string[];
    possible_hypotheses: string[];
    supporting_arguments?: string[];
    contradicting_arguments?: string[];
  };
  subsystem_summaries: Record<string, unknown>;
  evidence_items: AssessmentEvidenceItem[];
  analyst_notes: AnalystNote[];
  analyst_bookmarks: Bookmark[];
  uncertainties: Array<{ category: string; reason: string; impact: string }>;
  limitations: string[];
}

export interface ReportCreateResponse {
  report: InvestigationReport;
}

export interface InvestigationWorkspace {
  sample_id: string;
  sha256: string;
  original_filename: string;
  safe_filename: string;
  status: string;
  size_bytes: number;
  verdict_summary?: VerdictSummary | null;
  explainable_assessment?: ExplainableAssessment | null;
  coverage: Record<string, boolean>;
  bookmarks: Bookmark[];
  notes: AnalystNote[];
  created_at: string;
  updated_at: string;
}

export interface InvestigationWorkspaceResponse {
  workspace: InvestigationWorkspace;
}

// ============================================================================
// Phase 14: Analysis Job Orchestration & Pipeline Types
// ============================================================================

export type PipelineStageName =
  | "FILE_INTELLIGENCE"
  | "STATIC_ANALYSIS"
  | "DETECTION"
  | "REVERSE_ANALYSIS"
  | "ML"
  | "BEHAVIOR"
  | "SIMILARITY"
  | "THREAT_INTELLIGENCE"
  | "EVIDENCE_CORRELATION"
  | "ASSESSMENT"
  | "REPORT";

export type JobStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "TIMEOUT";

export type StageStatus =
  | "NOT_STARTED"
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "SKIPPED"
  | "CANCELLED"
  | "TIMEOUT";

export type FailureCategory =
  | "RETRYABLE"
  | "NON_RETRYABLE"
  | "TIMEOUT"
  | "CANCELLED"
  | "VALIDATION";

export interface StageError {
  error_category: FailureCategory;
  safe_message: string;
  timestamp: string;
  attempt_number: number;
}

export interface PipelineStageRecord {
  name: PipelineStageName;
  status: StageStatus;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms?: number | null;
  dependencies: PipelineStageName[];
  retry_count: number;
  error?: StageError | null;
  result_available: boolean;
}

export interface AnalysisJob {
  analysis_id: string;
  sample_id: string;
  status: JobStatus;
  current_stage?: PipelineStageName | null;
  progress: number;
  stages: PipelineStageRecord[];
  idempotency_key: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  cancelled_at?: string | null;
  cancellation_reason?: string | null;
  error?: string | null;
  engine_versions: Record<string, string>;
  partial_results_preserved: boolean;
  verdict_summary?: VerdictSummary | null;
  report_id?: string | null;
}

export interface AnalysisCreateRequest {
  sample_id: string;
  enabled_stages?: PipelineStageName[];
  force_reanalyze?: boolean;
  max_retries?: number;
  timeout_seconds?: number;
}

export interface AnalysisJobResponse {
  analysis: AnalysisJob;
}

export interface AnalysisStatusResponse {
  analysis_id: string;
  sample_id: string;
  status: JobStatus;
  progress: number;
  current_stage?: PipelineStageName | null;
  stages: PipelineStageRecord[];
  verdict_summary?: VerdictSummary | null;
  report_id?: string | null;
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface AnalysisCancelResponse {
  analysis_id: string;
  status: JobStatus;
  cancelled_at: string;
  message: string;
}

export interface AnalysisListResponse {
  analyses: AnalysisJob[];
  total_count: number;
}

// ============================================================================
// Phase 15: Experimental Evaluation & Research Infrastructure Types
// ============================================================================

export type GroundTruthLabel = "BENIGN" | "MALICIOUS" | "UNKNOWN";
export type EvaluationSplit = "TRAIN" | "VALIDATION" | "TEST" | "HELD_OUT_FAMILY";
export type SplitStrategy = "RANDOM" | "STRATIFIED" | "FAMILY_AWARE" | "TEMPORAL";

export type AblationConfigName =
  | "STATIC_ONLY"
  | "STATIC_HEURISTICS"
  | "STATIC_REVERSE"
  | "STATIC_REVERSE_ML"
  | "STATIC_REVERSE_BEHAVIOR"
  | "FULL_IGRIS";

export interface DatasetSampleRecord {
  sample_id: string;
  sha256: string;
  label: GroundTruthLabel;
  family?: string | null;
  split: EvaluationSplit;
  source: string;
  format: string;
  file_size_bytes: number;
  tags: string[];
}

export interface EvaluationDataset {
  dataset_id: string;
  dataset_version: string;
  name: string;
  description: string;
  source: string;
  license: string;
  collection_methodology: string;
  class_distribution: Record<string, number>;
  family_distribution: Record<string, number>;
  samples: DatasetSampleRecord[];
  inclusion_criteria: string[];
  exclusion_criteria: string[];
  limitations: string[];
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  unknown_count: number;
}

export interface ConfidenceInterval {
  low: number;
  high: number;
  confidence_level: number;
}

export interface EvaluationMetrics {
  precision?: number | null;
  recall?: number | null;
  f1_score?: number | null;
  fpr?: number | null;
  fnr?: number | null;
  accuracy?: number | null;
  total_samples: number;
  evaluated_samples: number;
  unknown_verdicts: number;
  confusion_matrix: ConfusionMatrix;
  confidence_intervals: Record<string, ConfidenceInterval>;
}

export interface PerformanceMetrics {
  total_duration_ms: number;
  mean_sample_latency_ms: number;
  median_sample_latency_ms: number;
  p95_sample_latency_ms: number;
  per_stage_latency_ms: Record<string, number>;
  throughput_samples_per_sec: number;
  successful_analyses: number;
  failed_analyses: number;
  timed_out_analyses: number;
  cancelled_analyses: number;
}

export interface ErrorRecord {
  sample_id: string;
  sha256: string;
  ground_truth: GroundTruthLabel;
  igris_verdict: AssessmentVerdict;
  risk_score: number;
  error_type: "FALSE_POSITIVE" | "FALSE_NEGATIVE" | "UNKNOWN_VERDICT";
  likely_cause_category: string;
  explanation: string;
  contributing_evidence: string[];
  available_stages: PipelineStageName[];
  observation_level: ObservationLevel;
}

export interface AblationResult {
  configuration_name: AblationConfigName;
  enabled_stages: PipelineStageName[];
  metrics: EvaluationMetrics;
  performance: PerformanceMetrics;
  error_count: number;
}

export interface ExperimentConfig {
  experiment_id: string;
  research_question: string;
  dataset_id: string;
  dataset_version: string;
  split_strategy: SplitStrategy;
  ablation_configurations: AblationConfigName[];
  random_seed: number;
  max_samples?: number | null;
  description: string;
}

export interface ExperimentReproducibilityMetadata {
  experiment_id: string;
  dataset_id: string;
  dataset_version: string;
  dataset_hash: string;
  code_version: string;
  pipeline_version: string;
  engine_versions: Record<string, string>;
  random_seed: number;
  split_strategy: SplitStrategy;
  timestamp: string;
}

export interface ExperimentRecord {
  experiment_id: string;
  config: ExperimentConfig;
  reproducibility: ExperimentReproducibilityMetadata;
  status: JobStatus;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  ablation_results: AblationResult[];
  overall_metrics?: EvaluationMetrics | null;
  overall_performance?: PerformanceMetrics | null;
  error_analysis: ErrorRecord[];
  threats_to_validity: string[];
  conclusions: string[];
}

export interface ExperimentCreateRequest {
  research_question: string;
  dataset_id: string;
  dataset_version?: string;
  split_strategy?: SplitStrategy;
  ablation_configurations?: AblationConfigName[];
  random_seed?: number;
  max_samples?: number;
  description?: string;
}

export interface ExperimentResponse {
  experiment: ExperimentRecord;
}

export interface ExperimentListResponse {
  experiments: ExperimentRecord[];
  total_count: number;
}

export interface ExperimentResultsResponse {
  experiment_id: string;
  ablation_results: AblationResult[];
  error_analysis: ErrorRecord[];
  overall_metrics?: EvaluationMetrics | null;
  overall_performance?: PerformanceMetrics | null;
}

export interface ExperimentArtifactsResponse {
  experiment_id: string;
  reproducibility_metadata: ExperimentReproducibilityMetadata;
  json_report: string;
  summary_markdown: string;
}

// ============================================================================
// Phase 16: Robustness & Adversarial Resilience
// ============================================================================

export type TransformationType =
  | "FILENAME_RENAME"
  | "METADATA_MUTATION"
  | "STRING_PADDING"
  | "SECTION_OVERLAY_PADDING"
  | "INSTRUCTION_NOP_INSERTION"
  | "SYNTHETIC_PACKING_SIMULATION"
  | "COMPILER_FLAG_VARIATION";

export type DegradationSeverity = "NONE" | "LOW" | "MODERATE" | "SEVERE";

export interface EngineSensitivity {
  engine_name: string;
  baseline_score: number;
  transformed_score: number;
  absolute_delta: number;
  degradation_severity: DegradationSeverity;
  notes: string;
}

export interface RobustnessMatrixRow {
  transformation_type: TransformationType;
  transformation_description: string;
  static_sensitivity: EngineSensitivity;
  reverse_sensitivity: EngineSensitivity;
  ml_sensitivity: EngineSensitivity;
  similarity_sensitivity: EngineSensitivity;
  behavior_sensitivity: EngineSensitivity;
  final_verdict_sensitivity: EngineSensitivity;
  overall_stability: DegradationSeverity;
}

export type BenignStressCategory =
  | "ADMIN_TOOL"
  | "INSTALLER_COMPRESSOR"
  | "DEVELOPER_DEBUGGER"
  | "NETWORK_UTILITY";

export interface FalsePositiveStressTestResult {
  sample_name: string;
  category: BenignStressCategory;
  suspicious_characteristics: string[];
  baseline_verdict: AssessmentVerdict;
  risk_score: number;
  overreaction_flag: boolean;
  mitigating_evidence: string[];
  epistemological_reasoning: string;
}

export interface FailureAnalysisRecord {
  failure_id: string;
  vulnerable_engine: string;
  transformation_or_scenario: string;
  observed_failure: string;
  root_cause: string;
  mitigation_strategy: string;
  fp_risk_of_mitigation: string;
  status: "OBSERVED_LIMITATION" | "RESOLVED_LIMITATION";
}

export interface RobustnessEvaluationReport {
  report_id: string;
  timestamp: string;
  matrix_rows: RobustnessMatrixRow[];
  false_positive_tests: FalsePositiveStressTestResult[];
  failure_records: FailureAnalysisRecord[];
  mean_stability_score: number;
  fp_resilience_rate: number;
  summary: string;
  threats_to_validity: string[];
}

export interface RobustnessEvaluateRequest {
  sample_id?: string | null;
  include_stress_tests?: boolean;
  random_seed?: number;
}

export interface RobustnessReportResponse {
  report: RobustnessEvaluationReport;
}

export interface RobustnessMatrixResponse {
  report_id: string;
  matrix_rows: RobustnessMatrixRow[];
  mean_stability_score: number;
}

export interface FalsePositiveTestsResponse {
  report_id: string;
  false_positive_tests: FalsePositiveStressTestResult[];
  fp_resilience_rate: number;
}

export interface RobustnessReportListResponse {
  reports: RobustnessEvaluationReport[];
  total_count: number;
}



