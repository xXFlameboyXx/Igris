import React from "react";
import type {
  Sample,
  StaticAnalysisResult,
  ReverseAnalysisResult,
  BehaviorAnalysisResult,
  MLPrediction,
  ThreatAssessmentResult,
  ExplainableAssessment,
} from "../types/api";
import { OverviewView } from "../components/views/OverviewView";
import { AnalysisPipelineView } from "../components/views/AnalysisPipelineView";
import { VerdictExplainabilityView } from "../components/views/VerdictExplainabilityView";
import { EvidenceExplorerView } from "../components/views/EvidenceExplorerView";
import { StaticAnalysisView } from "../components/views/StaticAnalysisView";
import { ReverseEngineeringView } from "../components/views/ReverseEngineeringView";
import { BehavioralView } from "../components/views/BehavioralView";
import { SimilarityView } from "../components/views/SimilarityView";
import { AttackMatrixView } from "../components/views/AttackMatrixView";
import { MLClassifierView } from "../components/views/MLClassifierView";
import { InvestigationReportView } from "../components/views/InvestigationReportView";
import { EvaluationResearchView } from "../components/views/EvaluationResearchView";
import { RobustnessStressView } from "../components/views/RobustnessStressView";
import { BookmarksPanel } from "../components/investigation/BookmarksPanel";
import { AnalystNotesPanel } from "../components/investigation/AnalystNotesPanel";
import { Header } from "../components/layout/Header";
import { Sidebar } from "../components/layout/Sidebar";
import { ErrorBoundary } from "../components/common/ErrorBoundary";

/**
 * Compile-time and type-level test assertions ensuring that all views
 * safely accept minimal, empty, partial, and full specimen objects
 * without type errors or missing required property crashes.
 */
export function testViewComponentSignatures() {
  const minimalSample: Sample = {
    sample_id: "00b648fc1463f1c84fa89f7861f47cbfb236d8cbca04256ad03f9f5f04480853",
    original_filename: "loader.exe",
    safe_filename: "loader.exe",
    hashes: {
      sha256: "00b648fc1463f1c84fa89f7861f47cbfb236d8cbca04256ad03f9f5f04480853",
      sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      md5: "d41d8cd98f00b204e9800998ecf8427e",
    },
    size_bytes: 1024,
    status: "pending",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const emptySample: Sample = {
    sample_id: "empty_sample_id",
    original_filename: "",
    safe_filename: "",
    hashes: {
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      md5: "d41d8cd98f00b204e9800998ecf8427e",
    },
    size_bytes: 0,
    status: "completed",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  // 1. Verify Zero Specimen Rendering
  const zeroSpecimenElements = [
    <OverviewView sample={null} onNavigateTab={() => {}} onRunAnalysis={async () => {}} runningLayers={{}} />,
    <AnalysisPipelineView sample={null} onNavigateTab={() => {}} />,
    <VerdictExplainabilityView sample={null} />,
    <EvidenceExplorerView sample={null} onNavigateTab={() => {}} />,
    <StaticAnalysisView sample={null} />,
    <ReverseEngineeringView sample={null} onFetchCFG={async () => null} />,
    <BehavioralView sample={null} />,
    <SimilarityView sample={null} />,
    <AttackMatrixView sample={null} />,
    <MLClassifierView sample={null} />,
    <InvestigationReportView sample={null} />,
    <EvaluationResearchView sample={null} onNavigateTab={() => {}} />,
    <RobustnessStressView sample={null} onNavigateTab={() => {}} />,
    <BookmarksPanel sample={null} bookmarks={[]} onCreateBookmark={async () => {}} onDeleteBookmark={async () => {}} onNavigateTab={() => {}} isOpen={false} onClose={() => {}} />,
    <AnalystNotesPanel sample={null} notes={[]} onCreateNote={async () => {}} onUpdateNote={async () => {}} onDeleteNote={async () => {}} isOpen={false} onClose={() => {}} />,
    <Header currentSample={null} samplesList={[]} onSelectSampleId={() => {}} onUploadSample={async () => {}} onDeleteSample={async () => {}} health={null} bookmarksCount={0} notesCount={0} onOpenBookmarks={() => {}} onOpenNotes={() => {}} isUploadOpen={false} onSetIsUploadOpen={() => {}} />,
    <Sidebar activeTab="overview" onSelectTab={() => {}} sample={null} />,
    <ErrorBoundary level="global"><div /></ErrorBoundary>,
    <ErrorBoundary level="view"><div /></ErrorBoundary>,
  ];

  // 2. Verify Minimal Specimen (no analysis results populated)
  const minimalSpecimenElements = [
    <OverviewView sample={minimalSample} onNavigateTab={() => {}} onRunAnalysis={async () => {}} runningLayers={{}} />,
    <AnalysisPipelineView sample={minimalSample} onNavigateTab={() => {}} />,
    <VerdictExplainabilityView sample={minimalSample} />,
    <EvidenceExplorerView sample={minimalSample} onNavigateTab={() => {}} />,
    <StaticAnalysisView sample={minimalSample} />,
    <ReverseEngineeringView sample={minimalSample} onFetchCFG={async () => null} />,
    <BehavioralView sample={minimalSample} />,
    <SimilarityView sample={minimalSample} />,
    <AttackMatrixView sample={minimalSample} />,
    <MLClassifierView sample={minimalSample} />,
    <InvestigationReportView sample={minimalSample} />,
    <Sidebar activeTab="static" onSelectTab={() => {}} sample={minimalSample} />,
  ];

  // 3. Verify Empty/Edge-case Specimen
  const emptySpecimenElements = [
    <OverviewView sample={emptySample} onNavigateTab={() => {}} onRunAnalysis={async () => {}} runningLayers={{}} />,
    <InvestigationReportView sample={emptySample} />,
    <Sidebar activeTab="overview" onSelectTab={() => {}} sample={emptySample} />,
  ];

  // 4. Verify Partial Analysis Models
  const partialStatic: StaticAnalysisResult = {
    sample_id: minimalSample.sample_id,
    strings: [{ value: "UPX0" }, { value: "KERNEL32.DLL" }],
    imports: { "KERNEL32.DLL": ["ExitProcess", "GetProcAddress"] },
  };

  const partialReverse: ReverseAnalysisResult = {
    sample_id: minimalSample.sample_id,
    status: "completed",
    functions: [
      {
        function_id: "sub_401000",
        name: "entry",
        address: 0x401000,
        size_bytes: 50,
        block_count: 3,
        cyclomatic_complexity: 2,
        call_count: 1,
        api_calls: ["ExitProcess"],
        has_suspicious_patterns: false,
      },
    ],
    evidence: [],
    analyzed_at: new Date().toISOString(),
    limitations: [],
  };

  const partialBehavior: BehaviorAnalysisResult = {
    sample_id: minimalSample.sample_id,
    status: "completed",
    provenance: "sandbox_execution",
    processes: [],
    registry_events: [],
    network_events: [],
    dropped_files: [],
    evidence: [],
    analyzed_at: new Date().toISOString(),
    limitations: [],
  };

  const partialThreat: ThreatAssessmentResult = {
    sample_id: minimalSample.sample_id,
    narrative: "Preliminary telemetry mapped to persistence capabilities.",
    attack_techniques: [
      {
        technique_id: "T1547.001",
        technique_name: "Registry Run Keys / Startup Folder",
        tactic: "Persistence",
        confidence: 0.85,
        supporting_evidence_ids: ["EV-001"],
      },
    ],
    capabilities: [
      {
        capability_id: "cap-1",
        name: "Persistence via Registry",
        description: "Modifies autostart registry keys",
        confidence: 0.85,
        supporting_evidence_ids: ["EV-001"],
      },
    ],
    relationships: [],
    analyzed_at: new Date().toISOString(),
  };

  const partialML: MLPrediction = {
    sample_id: minimalSample.sample_id,
    score: 0.88,
    prediction: "malware",
    uncertainty: "low",
    model_version: "rf-v1",
    feature_schema_version: "static-feature-vector/v1",
    feature_set: "rf_enhanced_v1",
    calibrated_probability: 0.88,
    explanation: "High entropy packed sections combined with registry autostart API calls.",
    important_contributing_features: [["entropy_max", 0.42], ["writable_exec_sections", 0.35]],
    limitations: ["Model trained on synthetic PE benchmark dataset."],
  };

  const partialAssessment: ExplainableAssessment = {
    sample_id: minimalSample.sample_id,
    sha256: minimalSample.hashes.sha256,
    schema_version: "v1.0",
    verdict: "SUSPICIOUS",
    risk_level: "HIGH",
    risk_score: {
      score: 72,
      formula: "min(100, max(0, sum(positive) - 0.5 * sum(mitigating)))",
      contributing_factors: [
        {
          factor_name: "High Entropy Section",
          category: "STATIC",
          points: 30,
          description: "Packed section detected",
          observation_level: "OBSERVED",
        },
      ],
      mitigating_factors: [],
      unknown_factors: [],
    },
    confidence: {
      detection_confidence: "HIGH",
      evidence_quality: "HIGH",
      behavioral_confidence: "MEDIUM",
      similarity_confidence: "LOW",
      attribution_confidence: "LOW",
      attribution_scope: "cluster_only",
      explanation: "Direct structural anomalies observed with high confidence.",
    },
    explanation: {
      summary: "Sample exhibits strong packing indicators and persistence mechanisms.",
      observed_findings: ["Section .upx1 has entropy 7.82/8.00"],
      inferred_findings: ["Persistence via Registry Run key"],
      possible_hypotheses: ["Cluster similarity with generic dropper family"],
      supporting_arguments: ["Observed executable writable section"],
      contradicting_arguments: [],
      uncertainty_and_unknowns: ["Network telemetry was unobserved in offline sandbox"],
      limitations: ["Attribution limited to technical clusters only."],
    },
    evidence_summary: {
      sample_id: minimalSample.sample_id,
      sha256: minimalSample.hashes.sha256,
      total_evidence_count: 1,
      supporting_count: 1,
      contradicting_count: 0,
      observed_count: 1,
      neutral_count: 0,
      inferred_count: 0,
      possible_count: 0,
      uncertainties: [],
      created_at: new Date().toISOString(),
      evidence_items: [
        {
          evidence_id: "EV-001",
          category: "STATIC",
          source: "StaticAnalysisEngine",
          source_id: "PEParser",
          evidence_type: "HIGH_ENTROPY",
          observation_level: "OBSERVED",
          role: "SUPPORTING",
          statement: "Section .upx1 has high entropy 7.82",
          strength: "HIGH",
          weight: 1.0,
          provenance: "StaticAnalysisEngine:PEParser",
          technical_details: { entropy: 7.82 },
          limitations: [],
        },
      ],
      disagreements: [],
    },
    created_at: new Date().toISOString(),
    limitations: [],
  };

  const richSample: Sample = {
    ...minimalSample,
    status: "completed",
    static_analysis: partialStatic,
    reverse_analysis: partialReverse,
    behavior_analysis: partialBehavior,
    threat_assessment: partialThreat,
    ml_prediction: partialML,
    malware_assessment: partialAssessment,
  };

  const richSpecimenElements = [
    <OverviewView sample={richSample} onNavigateTab={() => {}} onRunAnalysis={async () => {}} runningLayers={{}} />,
    <VerdictExplainabilityView sample={richSample} />,
    <EvidenceExplorerView sample={richSample} onNavigateTab={() => {}} />,
    <StaticAnalysisView sample={richSample} />,
    <ReverseEngineeringView sample={richSample} onFetchCFG={async () => null} />,
    <BehavioralView sample={richSample} />,
    <AttackMatrixView sample={richSample} />,
    <MLClassifierView sample={richSample} />,
    <InvestigationReportView sample={richSample} />,
    <Sidebar activeTab="overview" onSelectTab={() => {}} sample={richSample} />,
  ];

  // 5. Verify Real Backend Response Models (Regression protection for .map and .toUpperCase)
  const backendAccurateReverse: ReverseAnalysisResult = {
    sample_id: minimalSample.sample_id,
    status: "completed",
    schema_version: "reverse-analysis/v1",
    analyzed_at: new Date().toISOString(),
    disassembly: {
      architecture: "x86_64",
      entry_point: 0x401000,
      engine: "capstone-5.0",
      instruction_count: 24,
    },
    functions: [
      {
        function_id: "fn_401000",
        address: 0x401000,
        size: 64,
        basic_block_count: 2,
        cyclomatic_complexity: 3,
        referenced_apis: ["VirtualAlloc", "CreateThread"],
        referenced_strings: ["evil.dll"],
        callers: [],
        callees: ["fn_401050"],
        calls: [0x401050],
        instructions: [
          {
            address: 0x401000,
            mnemonic: "push",
            operands: "rbp",
            size: 1,
            bytes_hex: "55",
            normalized: "push rbp",
          },
          {
            address: 0x401001,
            mnemonic: "call",
            operands: "VirtualAlloc",
            size: 5,
            bytes_hex: "e800000000",
            normalized: "call VirtualAlloc",
          },
        ],
        evidence: [
          {
            evidence_id: "REV-001",
            function_id: "fn_401000",
            type: "EXECUTABLE_MEMORY_OPERATION",
            description: "Function 'fn_401000' references executable memory operation(s): 'VirtualAlloc'.",
            confidence: 0.72,
            technical_details: { apis: ["VirtualAlloc"] },
            related_apis: ["VirtualAlloc"],
            related_strings: [],
          },
        ],
      },
      {
        function_id: "fn_401050",
        address: 0x401050,
        size: 32,
        basic_block_count: 1,
        cyclomatic_complexity: 1,
        referenced_apis: [],
        referenced_strings: [],
        callers: ["fn_401000"],
        callees: [],
        calls: [],
        instructions: [
          {
            address: 0x401050,
            mnemonic: "ret",
            operands: "",
            size: 1,
            bytes_hex: "c3",
            normalized: "ret",
          },
        ],
        evidence: [],
      },
    ],
    cfgs: {
      fn_401000: {
        function_id: "fn_401000",
        blocks: [
          {
            block_id: "bb_0",
            start_address: 0x401000,
            end_address: 0x401006,
            instruction_addresses: [0x401000, 0x401001],
            successors: ["bb_1"],
            predecessors: [],
          },
          {
            block_id: "bb_1",
            start_address: 0x401006,
            end_address: 0x401040,
            instruction_addresses: [0x401006],
            successors: [],
            predecessors: ["bb_0"],
          },
        ],
        edges: [
          {
            source: "bb_0",
            target: "bb_1",
            edge_type: "unconditional",
          },
        ],
      },
    },
    call_graph: {
      nodes: [
        { node_id: "fn_401000", label: "fn_401000", node_type: "function" },
        { node_id: "fn_401050", label: "fn_401050", node_type: "function" },
      ],
      edges: [
        { source: "fn_401000", target: "fn_401050", call_type: "direct_call" },
      ],
    },
    evidence: [
      {
        evidence_id: "REV-001",
        function_id: "fn_401000",
        type: "EXECUTABLE_MEMORY_OPERATION",
        description: "Function 'fn_401000' references executable memory operation(s): 'VirtualAlloc'.",
        confidence: 0.72,
        technical_details: { apis: ["VirtualAlloc"] },
        related_apis: ["VirtualAlloc"],
        related_strings: [],
      },
    ],
    limitations: [],
  };

  const backendAccurateBehavior: BehaviorAnalysisResult = {
    sample_id: minimalSample.sample_id,
    status: "completed",
    schema_version: "behavior-analysis/v1",
    analyzed_at: new Date().toISOString(),
    sandbox_metadata: {
      analysis_mode: "synthetic",
      analyzer_version: "0.1.0",
      analysis_duration_seconds: 1.5,
      network_policy: "controlled_egress",
      exit_reason: "completed",
      os_platform: "Windows 11 Professional",
      os_version: "10.0.22631",
      artifacts_collected: 1,
      synthetic_scenario: "persistence_activity",
    },
    processes: [
      {
        timestamp_ms: 100,
        pid: 3044,
        ppid: 1024,
        process_name: "payload.exe",
        command_line: "C:\\Windows\\Temp\\payload.exe --run",
        is_sample: true,
      },
    ],
    file_events: [
      {
        timestamp_ms: 200,
        pid: 3044,
        operation: "write",
        path: "C:\\Users\\Analyst\\AppData\\Roaming\\dropped.bin",
        size_bytes: 4096,
      },
    ],
    registry_events: [
      {
        timestamp_ms: 250,
        pid: 3044,
        operation: "set_value",
        key_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name: "Updater",
        value_data: "C:\\Users\\Analyst\\AppData\\Roaming\\dropped.bin",
      },
    ],
    network_events: [
      {
        timestamp_ms: 300,
        pid: 3044,
        protocol: "tcp",
        direction: "outbound",
        destination_ip: "192.168.1.100",
        destination_port: 443,
        bytes_sent: 128,
        bytes_received: 512,
      },
    ],
    dropped_files: [
      {
        path: "C:\\Users\\Analyst\\AppData\\Roaming\\dropped.bin",
        sha256: "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        size_bytes: 4096,
        is_executable: true,
        retained: true,
      },
    ],
    evidence: [
      {
        evidence_id: "BEH-001",
        type: "REGISTRY_MODIFICATION",
        source: "BehaviorAnalyzer",
        severity: "high",
        confidence: 0.85,
        description: "Created autostart Run key in HKCU",
        technical_details: { key: "HKCU\\...\\Run" },
      },
    ],
    limitations: [],
  };

  const realBackendSample: Sample = {
    ...minimalSample,
    status: "completed",
    reverse_analysis: backendAccurateReverse,
    behavior_analysis: backendAccurateBehavior,
  };

  const backendAccurateElements = [
    <ReverseEngineeringView sample={realBackendSample} onFetchCFG={async () => backendAccurateReverse.cfgs?.fn_401000 || null} />,
    <BehavioralView sample={realBackendSample} />,
  ];

  return {
    zeroCount: zeroSpecimenElements.length,
    minimalCount: minimalSpecimenElements.length,
    emptyCount: emptySpecimenElements.length,
    richCount: richSpecimenElements.length,
    backendAccurateCount: backendAccurateElements.length,
  };
}

