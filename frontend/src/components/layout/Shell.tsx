import React, { useEffect, useState } from "react";
import { apiClient } from "../../services/apiClient";
import type {
  AnalystNote,
  AssessmentEvidenceItem,
  Bookmark,
  BookmarkCreateRequest,
  ControlFlowGraph,
  HealthResponse,
  InvestigationTab,
  NoteCreateRequest,
  NoteUpdateRequest,
  Sample,
} from "../../types/api";
import { AnalystNotesPanel } from "../investigation/AnalystNotesPanel";
import { BookmarksPanel } from "../investigation/BookmarksPanel";
import { SyntheticBanner } from "../common/StateViews";
import { AttackMatrixView } from "../views/AttackMatrixView";
import { AnalysisPipelineView } from "../views/AnalysisPipelineView";
import { BehavioralView } from "../views/BehavioralView";
import { EvaluationResearchView } from "../views/EvaluationResearchView";
import { EvidenceExplorerView } from "../views/EvidenceExplorerView";
import { InvestigationReportView } from "../views/InvestigationReportView";
import { MLClassifierView } from "../views/MLClassifierView";
import { OverviewView } from "../views/OverviewView";
import { ReverseEngineeringView } from "../views/ReverseEngineeringView";
import { RobustnessStressView } from "../views/RobustnessStressView";
import { SimilarityView } from "../views/SimilarityView";
import { StaticAnalysisView } from "../views/StaticAnalysisView";
import { SyntheticDemoView } from "../views/SyntheticDemoView";
import { VerdictExplainabilityView } from "../views/VerdictExplainabilityView";
import { AnalysisCoverageBar } from "./AnalysisCoverageBar";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";

export function Shell() {
  const [activeTab, setActiveTab] = useState<InvestigationTab>("overview");
  const [isSyntheticMode, setIsSyntheticMode] = useState<boolean>(false);
  const [currentSample, setCurrentSample] = useState<Sample | null>(null);
  const [samplesList, setSamplesList] = useState<Sample[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [runningLayers, setRunningLayers] = useState<Record<string, boolean>>({});
  const [statusNotification, setStatusNotification] = useState<string | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  // Investigation Workspace State: Bookmarks & Analyst Notes
  const [isBookmarksOpen, setIsBookmarksOpen] = useState(false);
  const [isNotesOpen, setIsNotesOpen] = useState(false);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [notes, setNotes] = useState<AnalystNote[]>([]);

  // Synchronize bookmarks and notes whenever active sample changes
  useEffect(() => {
    if (!currentSample) {
      setBookmarks([]);
      setNotes([]);
      return;
    }

    if (isSyntheticMode) {
      setBookmarks(currentSample.bookmarks || []);
      setNotes(currentSample.notes || []);
      return;
    }

    const controller = new AbortController();
    Promise.all([
      apiClient.listBookmarks(currentSample.sample_id, controller.signal).catch(() => ({ sample_id: currentSample.sample_id, bookmarks: [] })),
      apiClient.listNotes(currentSample.sample_id, controller.signal).catch(() => ({ sample_id: currentSample.sample_id, notes: [] })),
    ]).then(([bmkRes, noteRes]) => {
      setBookmarks(bmkRes.bookmarks || []);
      setNotes(noteRes.notes || []);
    });

    return () => controller.abort();
  }, [currentSample, isSyntheticMode]);

  // Load initial samples list and system health on mount
  useEffect(() => {
    const controller = new AbortController();

    // 1. Check system health
    apiClient
      .getHealth(controller.signal)
      .then((res) => setHealth(res))
      .catch(() => {
        setHealth({
          status: "degraded",
          service: "igris-backend",
          version: "0.1.0",
          environment: "local",
          components: {},
        });
      });

    // 2. Fetch ingested samples from live API
    apiClient
      .listSamples(controller.signal)
      .then((res) => {
        const list = res.samples || [];
        setSamplesList(list);
        if (list.length > 0) {
          apiClient
            .getSample(list[0].sample_id, controller.signal)
            .then((fullSample) => setCurrentSample(fullSample))
            .catch(() => setCurrentSample(list[0]));
        } else {
          setCurrentSample(null);
        }
      })
      .catch(() => {
        setSamplesList([]);
        setCurrentSample(null);
      });

    return () => controller.abort();
  }, []);

  const notify = (msg: string) => {
    setStatusNotification(msg);
    setTimeout(() => setStatusNotification(null), 4000);
  };

  const handleSelectSampleId = async (sampleId: string) => {
    if (!sampleId) return;
    try {
      notify(`Loading specimen ${sampleId.slice(0, 8)}...`);
      const sample = await apiClient.getSample(sampleId);
      setCurrentSample(sample);
      setIsSyntheticMode(false);
      notify(`Loaded specimen: ${sample.original_filename || sample.safe_filename || sample.sample_id.slice(0, 8)}`);
    } catch (err) {
      notify(`Failed to load specimen: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleUploadSample = async (file: File) => {
    try {
      notify(`Uploading ${file.name}...`);
      const created = await apiClient.uploadSample(file);
      notify(`Specimen uploaded successfully (${created.sample_id.slice(0, 8)}). Initializing pipeline...`);

      // Optionally start automated orchestration pipeline
      try {
        await apiClient.startAnalysis({ sample_id: created.sample_id });
      } catch {
        // Continue if pipeline was queued
      }

      // Fetch updated samples list and the newly uploaded sample
      const [listRes, fullSample] = await Promise.all([
        apiClient.listSamples().catch(() => ({ samples: [] })),
        apiClient.getSample(created.sample_id),
      ]);

      setSamplesList(listRes.samples || []);
      setCurrentSample(fullSample);
      setIsSyntheticMode(false);
      setActiveTab("overview");
      notify(`Loaded specimen: ${fullSample.original_filename || fullSample.safe_filename || file.name}`);
    } catch (err) {
      notify(`Upload error: ${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  };

  const handleRunAnalysis = async (layer: string) => {
    if (!currentSample) return;
    setRunningLayers((prev) => ({ ...prev, [layer]: true }));
    notify(`Triggering ${layer} analysis...`);

    try {
      if (isSyntheticMode) {
        await new Promise((resolve) => setTimeout(resolve, 800));
        notify(`Completed ${layer} analysis on demonstration sample.`);
      } else {
        const sId = currentSample.sample_id;
        switch (layer) {
          case "static":
            await apiClient.runStaticAnalysis(sId);
            break;
          case "reverse":
            await apiClient.runReverseAnalysis(sId);
            break;
          case "behavior":
            await apiClient.runBehaviorAnalysis(sId);
            break;
          case "detection":
            await apiClient.runDetection(sId);
            break;
          case "ml":
            await apiClient.runMLPrediction(sId);
            break;
          case "similarity":
            await apiClient.runSimilarity(sId);
            break;
        }

        const refreshed = await apiClient.getSample(sId);
        setCurrentSample(refreshed);
        notify(`Completed ${layer} analysis successfully.`);
      }
    } catch (err) {
      notify(`Analysis error (${layer}): ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRunningLayers((prev) => ({ ...prev, [layer]: false }));
    }
  };

  const handleCreateBookmark = async (req: BookmarkCreateRequest) => {
    if (!currentSample) return;
    try {
      if (isSyntheticMode) {
        const syntheticBookmark: Bookmark = {
          bookmark_id: `bmk-local-${Date.now()}`,
          sample_id: currentSample.sample_id,
          target_type: req.target_type,
          target_id: req.target_id,
          title: req.title,
          description: req.description,
          category: req.category,
          metadata: req.metadata,
          created_at: new Date().toISOString(),
        };
        setBookmarks((prev) => [syntheticBookmark, ...prev]);
        notify(`Bookmarked ${req.title}`);
        return;
      }

      const res = await apiClient.createBookmark(currentSample.sample_id, req);
      setBookmarks((prev) => [res.bookmark, ...prev]);
      notify(`Bookmarked ${req.title}`);
    } catch (err) {
      notify(`Failed to create bookmark: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteBookmark = async (bookmarkId: string) => {
    if (!currentSample) return;
    try {
      if (isSyntheticMode) {
        setBookmarks((prev) => prev.filter((b) => b.bookmark_id !== bookmarkId));
        notify("Bookmark deleted.");
        return;
      }

      await apiClient.deleteBookmark(currentSample.sample_id, bookmarkId);
      setBookmarks((prev) => prev.filter((b) => b.bookmark_id !== bookmarkId));
      notify("Bookmark deleted.");
    } catch (err) {
      notify(`Failed to delete bookmark: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleCreateNote = async (req: NoteCreateRequest) => {
    if (!currentSample) return;
    try {
      if (isSyntheticMode) {
        const syntheticNote: AnalystNote = {
          note_id: `note-local-${Date.now()}`,
          sample_id: currentSample.sample_id,
          author: req.author || "Analyst",
          title: req.title,
          content: req.content,
          tags: req.tags || [],
          attached_evidence_ids: req.attached_evidence_ids || [],
          attached_bookmark_ids: req.attached_bookmark_ids || [],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        setNotes((prev) => [syntheticNote, ...prev]);
        notify(`Created note: ${req.title}`);
        return;
      }

      const res = await apiClient.createNote(currentSample.sample_id, req);
      setNotes((prev) => [res.note, ...prev]);
      notify(`Created note: ${req.title}`);
    } catch (err) {
      notify(`Failed to create note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleUpdateNote = async (noteId: string, req: NoteUpdateRequest) => {
    if (!currentSample) return;
    try {
      if (isSyntheticMode) {
        setNotes((prev) =>
          prev.map((n) =>
            n.note_id === noteId
              ? {
                  ...n,
                  title: req.title || n.title,
                  content: req.content || n.content,
                  tags: req.tags || n.tags,
                  attached_evidence_ids: req.attached_evidence_ids || n.attached_evidence_ids,
                  attached_bookmark_ids: req.attached_bookmark_ids || n.attached_bookmark_ids,
                  updated_at: new Date().toISOString(),
                }
              : n
          )
        );
        notify("Note updated.");
        return;
      }

      const res = await apiClient.updateNote(currentSample.sample_id, noteId, req);
      setNotes((prev) => prev.map((n) => (n.note_id === noteId ? res.note : n)));
      notify("Note updated.");
    } catch (err) {
      notify(`Failed to update note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!currentSample) return;
    try {
      if (isSyntheticMode) {
        setNotes((prev) => prev.filter((n) => n.note_id !== noteId));
        notify("Note deleted.");
        return;
      }

      await apiClient.deleteNote(currentSample.sample_id, noteId);
      setNotes((prev) => prev.filter((n) => n.note_id !== noteId));
      notify("Note deleted.");
    } catch (err) {
      notify(`Failed to delete note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleBookmarkEvidenceItem = (item: AssessmentEvidenceItem) => {
    handleCreateBookmark({
      target_type: "evidence",
      target_id: item.evidence_id,
      title: item.statement.slice(0, 48),
      description: `Observed at level ${item.observation_level} with role ${item.role}`,
      category: item.category,
    });
  };

  const handleAddNoteForEvidenceItem = (item: AssessmentEvidenceItem) => {
    setIsNotesOpen(true);
    handleCreateNote({
      author: "Analyst",
      title: `Finding: ${item.statement.slice(0, 40)}`,
      content: `Evidence Item ID: ${item.evidence_id}\nCategory: ${item.category}\nRole: ${item.role}\nObservation Level: ${item.observation_level}\n\nAnalyst Assessment:`,
      tags: [item.category, item.role.toLowerCase()],
      attached_evidence_ids: [item.evidence_id],
      attached_bookmark_ids: [],
    });
  };

  const handleFetchCFG = async (functionId: string): Promise<ControlFlowGraph | null> => {
    if (!currentSample) return null;
    try {
      const res = await apiClient.getCFG(currentSample.sample_id, functionId);
      return res.cfg;
    } catch {
      return null;
    }
  };

  return (
    <div className="analyst-console-shell">
      <Header
        currentSample={currentSample}
        samplesList={samplesList}
        onSelectSampleId={handleSelectSampleId}
        onUploadSample={handleUploadSample}
        health={health}
        bookmarksCount={bookmarks.length}
        notesCount={notes.length}
        onOpenBookmarks={() => setIsBookmarksOpen(true)}
        onOpenNotes={() => setIsNotesOpen(true)}
        isUploadOpen={isUploadOpen}
        onSetIsUploadOpen={setIsUploadOpen}
      />

      {isSyntheticMode && <SyntheticBanner />}

      <AnalysisCoverageBar
        sample={currentSample}
        onNavigateTab={(tab) => setActiveTab(tab as InvestigationTab)}
      />

      {statusNotification && (
        <div className="status-toast-notification" role="status">
          <span>{statusNotification}</span>
          <button
            type="button"
            className="toast-close-btn"
            onClick={() => setStatusNotification(null)}
            aria-label="Dismiss notification"
          >
            ✕
          </button>
        </div>
      )}

      <div className="main-content-layout">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          sample={currentSample}
        />

        <main className="view-pane" id="main-content">
          {activeTab === "overview" && (
            <OverviewView
              sample={currentSample}
              onNavigateTab={setActiveTab}
              onRunAnalysis={handleRunAnalysis}
              runningLayers={runningLayers}
              onOpenUpload={() => setIsUploadOpen(true)}
            />
          )}

          {activeTab === "pipeline" && (
            <AnalysisPipelineView
              sample={currentSample}
              onNavigateTab={setActiveTab}
              isDemoMode={isSyntheticMode}
            />
          )}

          {activeTab === "verdict" && (
            <VerdictExplainabilityView
              sample={currentSample}
              onRunAssessment={() => handleRunAnalysis("assessment")}
              isRunning={runningLayers.assessment}
            />
          )}

          {activeTab === "evidence" && (
            <EvidenceExplorerView
              sample={currentSample}
              onNavigateTab={setActiveTab}
              onRunAssessment={() => handleRunAnalysis("assessment")}
              isRunning={runningLayers.assessment}
              onBookmarkItem={handleBookmarkEvidenceItem}
              onAddNoteForItem={handleAddNoteForEvidenceItem}
            />
          )}

          {activeTab === "static" && (
            <StaticAnalysisView
              sample={currentSample}
              onRunStatic={() => handleRunAnalysis("static")}
              isRunning={runningLayers.static}
            />
          )}

          {activeTab === "reverse" && (
            <ReverseEngineeringView
              sample={currentSample}
              onRunReverse={() => handleRunAnalysis("reverse")}
              isRunning={runningLayers.reverse}
              onFetchCFG={handleFetchCFG}
            />
          )}

          {activeTab === "behavior" && (
            <BehavioralView
              sample={currentSample}
              onRunBehavior={() => handleRunAnalysis("behavior")}
              isRunning={runningLayers.behavior}
            />
          )}

          {activeTab === "similarity" && (
            <SimilarityView
              sample={currentSample}
              onRunSimilarity={() => handleRunAnalysis("similarity")}
              isRunning={runningLayers.similarity}
            />
          )}

          {activeTab === "attack" && (
            <AttackMatrixView
              sample={currentSample}
              onRunThreat={() => handleRunAnalysis("threat")}
              isRunning={runningLayers.threat}
            />
          )}

          {activeTab === "ml" && (
            <MLClassifierView
              sample={currentSample}
              onRunML={() => handleRunAnalysis("ml")}
              isRunning={runningLayers.ml}
            />
          )}

          {activeTab === "report" && (
            <InvestigationReportView sample={currentSample} />
          )}

          {activeTab === "evaluation" && (
            <EvaluationResearchView
              sample={currentSample}
              onNavigateTab={setActiveTab}
              isDemoMode={isSyntheticMode}
            />
          )}

          {activeTab === "robustness" && (
            <RobustnessStressView
              sample={currentSample}
              onNavigateTab={setActiveTab}
              isDemoMode={isSyntheticMode}
            />
          )}

          {activeTab === "demo" && (
            <SyntheticDemoView
              currentSample={currentSample}
              onSelectSample={(s) => {
                setCurrentSample(s);
                setIsSyntheticMode(true);
                notify(`Activated scenario: ${s.original_filename}`);
              }}
              onNavigateTab={setActiveTab}
            />
          )}
        </main>
      </div>

      {/* Investigation Bookmarks Drawer */}
      <BookmarksPanel
        sample={currentSample}
        bookmarks={bookmarks}
        onCreateBookmark={handleCreateBookmark}
        onDeleteBookmark={handleDeleteBookmark}
        onNavigateTab={setActiveTab}
        isOpen={isBookmarksOpen}
        onClose={() => setIsBookmarksOpen(false)}
      />

      {/* Analyst Notes Drawer */}
      <AnalystNotesPanel
        sample={currentSample}
        notes={notes}
        onCreateNote={handleCreateNote}
        onUpdateNote={handleUpdateNote}
        onDeleteNote={handleDeleteNote}
        isOpen={isNotesOpen}
        onClose={() => setIsNotesOpen(false)}
      />
    </div>
  );
}
