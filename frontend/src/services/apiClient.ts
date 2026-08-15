/**
 * Strongly typed HTTP API Client for Igris Analyst Interface.
 * Handles abort signals, robust error formatting, and normalized endpoint requests.
 */

import type {
  AnalysisCancelResponse,
  AnalysisCreateRequest,
  AnalysisJobResponse,
  AnalysisListResponse,
  AnalysisStatusResponse,
  BehaviorAnalysisResponse,
  BehaviorEventsResponse,
  BehaviorEvidenceResponse,
  CFGResponse,
  CapabilitiesResponse,
  DetectionResponse,
  EvidenceRelationshipsResponse,
  EvidenceSummaryResponse,
  ExplanationResponse,
  FileInfoResponse,
  FunctionsResponse,
  HealthResponse,
  BookmarkCreateRequest,
  BookmarkResponse,
  BookmarksListResponse,
  EvidenceFilterQuery,
  EvidenceListResponse,
  InvestigationWorkspaceResponse,
  MLPredictionResponse,
  NarrativeResponse,
  NoteCreateRequest,
  NoteResponse,
  NotesListResponse,
  NoteUpdateRequest,
  ReportCreateResponse,
  ReverseAnalysisResponse,
  SampleCreateResponse,
  SampleResponse,
  SimilarityResponse,
  SimilarityResultsResponse,
  StaticAnalysisResponse,
  TechniquesResponse,
  ThreatAssessmentResponse,
  VerdictResponse,
  ExperimentArtifactsResponse,
  ExperimentCreateRequest,
  ExperimentListResponse,
  ExperimentResponse,
  ExperimentResultsResponse,
  FalsePositiveTestsResponse,
  RobustnessEvaluateRequest,
  RobustnessMatrixResponse,
  RobustnessReportListResponse,
  RobustnessReportResponse,
} from "../types/api";

export class ApiError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(message: string, statusCode: number, code: string = "api_error", details?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = "api_error";
    let message = `Request failed with HTTP ${response.status} (${response.statusText})`;
    let details: Record<string, unknown> | undefined;

    try {
      const errJson = (await response.json()) as { error?: { code?: string; message?: string; details?: Record<string, unknown> } };
      if (errJson && errJson.error) {
        code = errJson.error.code || code;
        message = errJson.error.message || message;
        details = errJson.error.details;
      }
    } catch {
      // Ignore JSON parse failure on non-JSON error bodies
    }

    throw new ApiError(message, response.status, code, details);
  }

  return response.json() as Promise<T>;
}

export const apiClient = {
  // --------------------------------------------------------------------------
  // System Health
  // --------------------------------------------------------------------------
  async getHealth(signal?: AbortSignal): Promise<HealthResponse> {
    const res = await fetch("/api/v1/health", {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<HealthResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Sample Lifecycle & Metadata
  // --------------------------------------------------------------------------
  async uploadSample(file: File, signal?: AbortSignal): Promise<SampleCreateResponse> {
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch("/api/v1/samples", {
      method: "POST",
      body: formData,
      signal,
    });
    return handleResponse<SampleCreateResponse>(res);
  },

  async getSample(sampleId: string, signal?: AbortSignal): Promise<SampleResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<SampleResponse>(res);
  },

  async getFileInfo(sampleId: string, signal?: AbortSignal): Promise<FileInfoResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/file-info`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<FileInfoResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Phase 11: Explainable Verdict & Assessment
  // --------------------------------------------------------------------------
  async getVerdict(sampleId: string, signal?: AbortSignal): Promise<VerdictResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/verdict`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<VerdictResponse>(res);
  },

  async getExplanation(sampleId: string, signal?: AbortSignal): Promise<ExplanationResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/explanation`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ExplanationResponse>(res);
  },

  async getEvidenceSummary(sampleId: string, signal?: AbortSignal): Promise<EvidenceSummaryResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/evidence-summary`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<EvidenceSummaryResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Static Analysis & Detection Rules
  // --------------------------------------------------------------------------
  async runStaticAnalysis(sampleId: string, signal?: AbortSignal): Promise<StaticAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/static-analysis`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<StaticAnalysisResponse>(res);
  },

  async getStaticAnalysis(sampleId: string, signal?: AbortSignal): Promise<StaticAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/static-analysis`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<StaticAnalysisResponse>(res);
  },

  async runDetection(sampleId: string, signal?: AbortSignal): Promise<DetectionResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/detect`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<DetectionResponse>(res);
  },

  async getDetection(sampleId: string, signal?: AbortSignal): Promise<DetectionResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/detection`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<DetectionResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Reverse Analysis & Control Flow Graphs
  // --------------------------------------------------------------------------
  async runReverseAnalysis(sampleId: string, signal?: AbortSignal): Promise<ReverseAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/reverse-analysis`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ReverseAnalysisResponse>(res);
  },

  async getReverseAnalysis(sampleId: string, signal?: AbortSignal): Promise<ReverseAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/reverse-analysis`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ReverseAnalysisResponse>(res);
  },

  async getFunctions(sampleId: string, signal?: AbortSignal): Promise<FunctionsResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/functions`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<FunctionsResponse>(res);
  },

  async getCFG(sampleId: string, functionId: string, signal?: AbortSignal): Promise<CFGResponse> {
    const res = await fetch(
      `/api/v1/samples/${encodeURIComponent(sampleId)}/functions/${encodeURIComponent(functionId)}/cfg`,
      {
        headers: { Accept: "application/json" },
        signal,
      }
    );
    return handleResponse<CFGResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Behavioral Telemetry & Dynamic Sandbox
  // --------------------------------------------------------------------------
  async runBehaviorAnalysis(sampleId: string, signal?: AbortSignal): Promise<BehaviorAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/behavior-analysis`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<BehaviorAnalysisResponse>(res);
  },

  async getBehaviorAnalysis(sampleId: string, signal?: AbortSignal): Promise<BehaviorAnalysisResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/behavior-analysis`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<BehaviorAnalysisResponse>(res);
  },

  async getBehaviorEvents(sampleId: string, signal?: AbortSignal): Promise<BehaviorEventsResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/behavior-events`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<BehaviorEventsResponse>(res);
  },

  async getBehaviorEvidence(sampleId: string, signal?: AbortSignal): Promise<BehaviorEvidenceResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/behavior-evidence`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<BehaviorEvidenceResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Threat Intelligence & ATT&CK Mappings
  // --------------------------------------------------------------------------
  async runThreatAssessment(sampleId: string, signal?: AbortSignal): Promise<ThreatAssessmentResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/threat-assessment`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ThreatAssessmentResponse>(res);
  },

  async getThreatAssessment(sampleId: string, signal?: AbortSignal): Promise<ThreatAssessmentResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/threat-assessment`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ThreatAssessmentResponse>(res);
  },

  async getCapabilities(sampleId: string, signal?: AbortSignal): Promise<CapabilitiesResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/capabilities`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<CapabilitiesResponse>(res);
  },

  async getAttackMappings(sampleId: string, signal?: AbortSignal): Promise<TechniquesResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/attack-mappings`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<TechniquesResponse>(res);
  },

  async getEvidenceRelationships(sampleId: string, signal?: AbortSignal): Promise<EvidenceRelationshipsResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/evidence-relationships`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<EvidenceRelationshipsResponse>(res);
  },

  async getNarrative(sampleId: string, signal?: AbortSignal): Promise<NarrativeResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/narrative`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<NarrativeResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Machine Learning Classifier
  // --------------------------------------------------------------------------
  async runMLPrediction(sampleId: string, modelVersion?: string, signal?: AbortSignal): Promise<MLPredictionResponse> {
    const url = modelVersion
      ? `/api/v1/samples/${encodeURIComponent(sampleId)}/ml-prediction?model_version=${encodeURIComponent(modelVersion)}`
      : `/api/v1/samples/${encodeURIComponent(sampleId)}/ml-prediction`;
    const res = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<MLPredictionResponse>(res);
  },

  async getMLPrediction(sampleId: string, signal?: AbortSignal): Promise<MLPredictionResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/ml-prediction`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<MLPredictionResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Phase 10: Similarity Analysis
  // --------------------------------------------------------------------------
  async runSimilarity(sampleId: string, maxMatches: number = 20, signal?: AbortSignal): Promise<SimilarityResponse> {
    const res = await fetch(
      `/api/v1/samples/${encodeURIComponent(sampleId)}/similarity?max_matches=${encodeURIComponent(maxMatches)}`,
      {
        method: "POST",
        headers: { Accept: "application/json" },
        signal,
      }
    );
    return handleResponse<SimilarityResponse>(res);
  },

  async getSimilarity(sampleId: string, signal?: AbortSignal): Promise<SimilarityResultsResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/similarity/results`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<SimilarityResultsResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Phase 13: Investigation Workspace, Bookmarks, Notes & Reports
  // --------------------------------------------------------------------------
  async getInvestigationWorkspace(
    sampleId: string,
    signal?: AbortSignal
  ): Promise<InvestigationWorkspaceResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/investigation`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<InvestigationWorkspaceResponse>(res);
  },

  async getFilteredEvidence(
    sampleId: string,
    query?: EvidenceFilterQuery,
    signal?: AbortSignal
  ): Promise<EvidenceListResponse> {
    const params = new URLSearchParams();
    if (query?.source) params.append("source", query.source);
    if (query?.severity) params.append("severity", query.severity);
    if (query?.role) params.append("role", query.role);
    if (query?.observation_level) params.append("observation_level", query.observation_level);
    if (query?.process) params.append("process", query.process);
    if (query?.function) params.append("function", query.function);
    if (query?.technique) params.append("technique", query.technique);
    if (query?.query) params.append("query", query.query);

    const qs = params.toString() ? `?${params.toString()}` : "";
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/evidence${qs}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<EvidenceListResponse>(res);
  },

  async createBookmark(
    sampleId: string,
    data: BookmarkCreateRequest,
    signal?: AbortSignal
  ): Promise<BookmarkResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/bookmarks`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(data),
      signal,
    });
    return handleResponse<BookmarkResponse>(res);
  },

  async listBookmarks(sampleId: string, signal?: AbortSignal): Promise<BookmarksListResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/bookmarks`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<BookmarksListResponse>(res);
  },

  async deleteBookmark(sampleId: string, bookmarkId: string, signal?: AbortSignal): Promise<void> {
    const res = await fetch(
      `/api/v1/samples/${encodeURIComponent(sampleId)}/bookmarks/${encodeURIComponent(bookmarkId)}`,
      {
        method: "DELETE",
        signal,
      }
    );
    if (!res.ok && res.status !== 204) {
      throw new ApiError(`Failed to delete bookmark: ${res.statusText}`, res.status);
    }
  },

  async createNote(
    sampleId: string,
    data: NoteCreateRequest,
    signal?: AbortSignal
  ): Promise<NoteResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(data),
      signal,
    });
    return handleResponse<NoteResponse>(res);
  },

  async listNotes(sampleId: string, signal?: AbortSignal): Promise<NotesListResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/notes`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<NotesListResponse>(res);
  },

  async updateNote(
    sampleId: string,
    noteId: string,
    data: NoteUpdateRequest,
    signal?: AbortSignal
  ): Promise<NoteResponse> {
    const res = await fetch(
      `/api/v1/samples/${encodeURIComponent(sampleId)}/notes/${encodeURIComponent(noteId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(data),
        signal,
      }
    );
    return handleResponse<NoteResponse>(res);
  },

  async deleteNote(sampleId: string, noteId: string, signal?: AbortSignal): Promise<void> {
    const res = await fetch(
      `/api/v1/samples/${encodeURIComponent(sampleId)}/notes/${encodeURIComponent(noteId)}`,
      {
        method: "DELETE",
        signal,
      }
    );
    if (!res.ok && res.status !== 204) {
      throw new ApiError(`Failed to delete note: ${res.statusText}`, res.status);
    }
  },

  async generateReport(sampleId: string, signal?: AbortSignal): Promise<ReportCreateResponse> {
    const res = await fetch(`/api/v1/samples/${encodeURIComponent(sampleId)}/report`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ReportCreateResponse>(res);
  },

  getReportJsonUrl(sampleId: string): string {
    return `/api/v1/samples/${encodeURIComponent(sampleId)}/report/json`;
  },

  getReportPdfUrl(sampleId: string): string {
    return `/api/v1/samples/${encodeURIComponent(sampleId)}/report/pdf`;
  },

  // --------------------------------------------------------------------------
  // Phase 14: Analysis Job Orchestration & Pipeline Management
  // --------------------------------------------------------------------------
  async startAnalysis(data: AnalysisCreateRequest, signal?: AbortSignal): Promise<AnalysisJobResponse> {
    const res = await fetch("/api/v1/analyses", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(data),
      signal,
    });
    return handleResponse<AnalysisJobResponse>(res);
  },

  async getAnalysis(analysisId: string, signal?: AbortSignal): Promise<AnalysisJobResponse> {
    const res = await fetch(`/api/v1/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<AnalysisJobResponse>(res);
  },

  async getAnalysisStatus(analysisId: string, signal?: AbortSignal): Promise<AnalysisStatusResponse> {
    const res = await fetch(`/api/v1/analyses/${encodeURIComponent(analysisId)}/status`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<AnalysisStatusResponse>(res);
  },

  async cancelAnalysis(analysisId: string, signal?: AbortSignal): Promise<AnalysisCancelResponse> {
    const res = await fetch(`/api/v1/analyses/${encodeURIComponent(analysisId)}/cancel`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<AnalysisCancelResponse>(res);
  },

  async listAnalyses(sampleId?: string, signal?: AbortSignal): Promise<AnalysisListResponse> {
    const url = sampleId
      ? `/api/v1/analyses?sample_id=${encodeURIComponent(sampleId)}`
      : "/api/v1/analyses";
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<AnalysisListResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Phase 15: Evaluation & Research Infrastructure
  // --------------------------------------------------------------------------
  async createExperiment(
    payload: ExperimentCreateRequest,
    signal?: AbortSignal
  ): Promise<ExperimentResponse> {
    const res = await fetch("/api/v1/experiments", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
      signal,
    });
    return handleResponse<ExperimentResponse>(res);
  },

  async listExperiments(limit: number = 100, signal?: AbortSignal): Promise<ExperimentListResponse> {
    const res = await fetch(`/api/v1/experiments?limit=${limit}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ExperimentListResponse>(res);
  },

  async getExperiment(experimentId: string, signal?: AbortSignal): Promise<ExperimentResponse> {
    const res = await fetch(`/api/v1/experiments/${encodeURIComponent(experimentId)}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ExperimentResponse>(res);
  },

  async getExperimentResults(
    experimentId: string,
    signal?: AbortSignal
  ): Promise<ExperimentResultsResponse> {
    const res = await fetch(`/api/v1/experiments/${encodeURIComponent(experimentId)}/results`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ExperimentResultsResponse>(res);
  },

  async getExperimentArtifacts(
    experimentId: string,
    signal?: AbortSignal
  ): Promise<ExperimentArtifactsResponse> {
    const res = await fetch(`/api/v1/experiments/${encodeURIComponent(experimentId)}/artifacts`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<ExperimentArtifactsResponse>(res);
  },

  // --------------------------------------------------------------------------
  // Phase 16: Robustness & Adversarial Resilience
  // --------------------------------------------------------------------------
  async evaluateRobustness(
    body: RobustnessEvaluateRequest,
    signal?: AbortSignal
  ): Promise<RobustnessReportResponse> {
    const res = await fetch("/api/v1/robustness/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    return handleResponse<RobustnessReportResponse>(res);
  },

  async getRobustnessMatrix(signal?: AbortSignal): Promise<RobustnessMatrixResponse> {
    const res = await fetch("/api/v1/robustness/matrix", {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<RobustnessMatrixResponse>(res);
  },

  async getFalsePositiveTests(signal?: AbortSignal): Promise<FalsePositiveTestsResponse> {
    const res = await fetch("/api/v1/robustness/false-positives", {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<FalsePositiveTestsResponse>(res);
  },

  async getRobustnessReport(
    reportId: string,
    signal?: AbortSignal
  ): Promise<RobustnessReportResponse> {
    const res = await fetch(`/api/v1/robustness/reports/${encodeURIComponent(reportId)}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<RobustnessReportResponse>(res);
  },

  async listRobustnessReports(
    limit: number = 50,
    signal?: AbortSignal
  ): Promise<RobustnessReportListResponse> {
    const res = await fetch(`/api/v1/robustness/reports?limit=${limit}`, {
      headers: { Accept: "application/json" },
      signal,
    });
    return handleResponse<RobustnessReportListResponse>(res);
  },
};

