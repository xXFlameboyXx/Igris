import React, { useEffect, useState } from "react";
import { apiClient } from "../../services/apiClient";
import {
  DEMO_CFG_INJECT,
  DEMO_MALICIOUS_SAMPLE,
  DEMO_SAMPLES_LIST,
} from "../../services/syntheticDemoData";
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
  const [isSyntheticMode, setIsSyntheticMode] = useState<boolean>(true);
  const [currentSample, setCurrentSample] = useState<Sample | null>(DEMO_MALICIOUS_SAMPLE);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [runningLayers, setRunningLayers] = useState<Record<string, boolean>>({});
  const [statusNotification, setStatusNotification] = useState<string | null>(null);

  // Investigation Workspace State: Bookmarks & Analyst Notes
  const [isBookmarksOpen, setIsBookmarksOpen] = useState(false);
  const [isNotesOpen, setIsNotesOpen] = useState(false);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>(DEMO_MALICIOUS_SAMPLE.bookmarks || []);
  const [notes, setNotes] = useState<AnalystNote[]>(DEMO_MALICIOUS_SAMPLE.notes || []);

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

    // In live mode, fetch from backend endpoints
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

  // Poll system health once on mount
  useEffect(() => {
    const controller = new AbortController();
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

    return () => controller.abort();
  }, []);

  const notify = (msg: string) => {
    setStatusNotification(msg);
    setTimeout(() => setStatusNotification(null), 4000);
  };

  const handleSelectSampleId = async (sampleId: string) => {
    // Check if in demo samples list
    const demo = DEMO_SAMPLES_LIST.find((s) => s.sample_id === sampleId);
    if (demo) {
      setCurrentSample(demo);
      setIsSyntheticMode(true);
      notify(`Loaded demonstration scenario: ${demo.original_filename}`);
      return;
    }

    // Otherwise fetch from live API
    try {
      notify(`Loading sample ${sampleId} from API...`);
      const res = await apiClient.getSample(sampleId);
      setCurrentSample(res.sample);
      setIsSyntheticMode(false);
      notify(`Loaded sample: ${res.sample.original_filename}`);
    } catch (err) {
      notify(`Failed to load sample: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleUploadSample = async (file: File) => {
    try {
      notify(`Uploading ${file.name}...`);
      const created = await apiClient.uploadSample(file);
      notify(`Sample uploaded successfully (ID: ${created.sample_id}). Ingesting metadata...`);

      // Fetch full sample record
      const full = await apiClient.getSample(created.sample_id);
      setCurrentSample(full.sample);
      setIsSyntheticMode(false);
      setActiveTab("overview");
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
        // Simulate completion in synthetic mode
        await new Promise((resolve) => setTimeout(resolve, 800));
        notify(`Completed ${layer} analysis on demonstration sample.`);
      } else {
        // Real API invocation
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

        // Refresh sample state
        const refreshed = await apiClient.getSample(sId);
        setCurrentSample(refreshed.sample);
        notify(`Completed ${layer} analysis successfully.`);
      }
    } catch (err) {
      notify(`Error running ${layer}: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRunningLayers((prev) => ({ ...prev, [layer]: false }));
    }
  };

  const handleCreateBookmark = async (data: BookmarkCreateRequest) => {
    if (!currentSample) return;
    if (isSyntheticMode) {
      const newBmk: Bookmark = {
        bookmark_id: `bmk-synth-${Date.now()}`,
        sample_id: currentSample.sample_id,
        target_type: data.target_type,
        target_id: data.target_id,
        title: data.title,
        description: data.description,
        category: data.category,
        created_at: new Date().toISOString(),
      };
      const updated = [newBmk, ...bookmarks];
      setBookmarks(updated);
      setCurrentSample({ ...currentSample, bookmarks: updated });
      notify(`Created bookmark: ${data.title}`);
      return;
    }

    try {
      const res = await apiClient.createBookmark(currentSample.sample_id, data);
      setBookmarks([res.bookmark, ...bookmarks]);
      notify(`Created bookmark: ${data.title}`);
    } catch (err) {
      notify(`Failed to create bookmark: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteBookmark = async (bookmarkId: string) => {
    if (!currentSample) return;
    if (isSyntheticMode) {
      const updated = bookmarks.filter((b) => b.bookmark_id !== bookmarkId);
      setBookmarks(updated);
      setCurrentSample({ ...currentSample, bookmarks: updated });
      notify("Deleted bookmark.");
      return;
    }

    try {
      await apiClient.deleteBookmark(currentSample.sample_id, bookmarkId);
      setBookmarks(bookmarks.filter((b) => b.bookmark_id !== bookmarkId));
      notify("Deleted bookmark.");
    } catch (err) {
      notify(`Failed to delete bookmark: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleCreateNote = async (data: NoteCreateRequest) => {
    if (!currentSample) return;
    if (isSyntheticMode) {
      const newNote: AnalystNote = {
        note_id: `note-synth-${Date.now()}`,
        sample_id: currentSample.sample_id,
        author: data.author || "Analyst",
        title: data.title,
        content: data.content,
        attached_evidence_ids: data.attached_evidence_ids || [],
        attached_bookmark_ids: data.attached_bookmark_ids || [],
        tags: data.tags || [],
        created_at: new Date().toISOString(),
      };
      const updated = [newNote, ...notes];
      setNotes(updated);
      setCurrentSample({ ...currentSample, notes: updated });
      notify(`Created analyst note: ${data.title}`);
      return;
    }

    try {
      const res = await apiClient.createNote(currentSample.sample_id, data);
      setNotes([res.note, ...notes]);
      notify(`Created analyst note: ${data.title}`);
    } catch (err) {
      notify(`Failed to create note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleUpdateNote = async (noteId: string, data: NoteUpdateRequest) => {
    if (!currentSample) return;
    if (isSyntheticMode) {
      const updated = notes.map((n) =>
        n.note_id === noteId
          ? {
              ...n,
              title: data.title !== undefined ? data.title : n.title,
              content: data.content !== undefined ? data.content : n.content,
              attached_evidence_ids:
                data.attached_evidence_ids !== undefined
                  ? data.attached_evidence_ids
                  : n.attached_evidence_ids,
              tags: data.tags !== undefined ? data.tags : n.tags,
              updated_at: new Date().toISOString(),
            }
          : n
      );
      setNotes(updated);
      setCurrentSample({ ...currentSample, notes: updated });
      notify("Updated analyst note.");
      return;
    }

    try {
      const res = await apiClient.updateNote(currentSample.sample_id, noteId, data);
      setNotes(notes.map((n) => (n.note_id === noteId ? res.note : n)));
      notify("Updated analyst note.");
    } catch (err) {
      notify(`Failed to update note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!currentSample) return;
    if (isSyntheticMode) {
      const updated = notes.filter((n) => n.note_id !== noteId);
      setNotes(updated);
      setCurrentSample({ ...currentSample, notes: updated });
      notify("Deleted analyst note.");
      return;
    }

    try {
      await apiClient.deleteNote(currentSample.sample_id, noteId);
      setNotes(notes.filter((n) => n.note_id !== noteId));
      notify("Deleted analyst note.");
    } catch (err) {
      notify(`Failed to delete note: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleBookmarkEvidenceItem = async (item: AssessmentEvidenceItem) => {
    await handleCreateBookmark({
      target_type: "evidence",
      target_id: item.evidence_id,
      title: `Finding: ${item.statement.slice(0, 50)}…`,
      description: item.statement,
      category: item.category,
    });
  };

  const handleAddNoteForEvidenceItem = () => {
    setIsNotesOpen(true);
  };

  const handleFetchCFG = async (functionId: string): Promise<ControlFlowGraph | null> => {
    if (!currentSample) return null;
    if (isSyntheticMode) {
      return DEMO_CFG_INJECT;
    }
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
        onSelectSampleId={handleSelectSampleId}
        onUploadSample={handleUploadSample}
        isSyntheticMode={isSyntheticMode}
        onToggleSyntheticMode={() => {
          setIsSyntheticMode(!isSyntheticMode);
          if (!isSyntheticMode) {
            setCurrentSample(DEMO_MALICIOUS_SAMPLE);
            notify("Switched to Synthetic Demonstration Mode.");
          } else {
            notify("Switched to Live API Mode.");
          }
        }}
        demoSamples={DEMO_SAMPLES_LIST}
        health={health}
        bookmarksCount={bookmarks.length}
        notesCount={notes.length}
        onOpenBookmarks={() => setIsBookmarksOpen(true)}
        onOpenNotes={() => setIsNotesOpen(true)}
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
              demoCFG={DEMO_CFG_INJECT}
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
