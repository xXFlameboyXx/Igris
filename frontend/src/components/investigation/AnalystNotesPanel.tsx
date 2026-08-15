import React, { useState } from "react";
import type {
  AnalystNote,
  NoteCreateRequest,
  NoteUpdateRequest,
  Sample,
} from "../../types/api";
import { EmptyState } from "../common/StateViews";

interface AnalystNotesPanelProps {
  sample: Sample | null;
  notes: AnalystNote[];
  onCreateNote: (data: NoteCreateRequest) => Promise<void>;
  onUpdateNote: (noteId: string, data: NoteUpdateRequest) => Promise<void>;
  onDeleteNote: (noteId: string) => Promise<void>;
  isOpen: boolean;
  onClose: () => void;
}

export function AnalystNotesPanel({
  sample,
  notes,
  onCreateNote,
  onUpdateNote,
  onDeleteNote,
  isOpen,
  onClose,
}: AnalystNotesPanelProps) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingNote, setEditingNote] = useState<AnalystNote | null>(null);

  const [author, setAuthor] = useState("Lead Analyst");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [tagsInput, setTagsInput] = useState("");
  const [attachedEvidenceInput, setAttachedEvidenceInput] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !content.trim()) return;

    try {
      setIsSubmitting(true);
      const tags = tagsInput
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const attached_evidence_ids = attachedEvidenceInput
        .split(",")
        .map((eId) => eId.trim())
        .filter(Boolean);

      await onCreateNote({
        author: author.trim() || "Analyst",
        title: title.trim(),
        content: content.trim(),
        tags,
        attached_evidence_ids,
      });

      setTitle("");
      setContent("");
      setTagsInput("");
      setAttachedEvidenceInput("");
      setShowAddModal(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingNote || !title.trim() || !content.trim()) return;

    try {
      setIsSubmitting(true);
      const tags = tagsInput
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const attached_evidence_ids = attachedEvidenceInput
        .split(",")
        .map((eId) => eId.trim())
        .filter(Boolean);

      await onUpdateNote(editingNote.note_id, {
        title: title.trim(),
        content: content.trim(),
        tags,
        attached_evidence_ids,
      });

      setEditingNote(null);
      setTitle("");
      setContent("");
      setTagsInput("");
      setAttachedEvidenceInput("");
    } finally {
      setIsSubmitting(false);
    }
  };

  const startEdit = (note: AnalystNote) => {
    setEditingNote(note);
    setTitle(note.title);
    setContent(note.content);
    setAuthor(note.author);
    setTagsInput(note.tags.join(", "));
    setAttachedEvidenceInput(note.attached_evidence_ids.join(", "));
    setShowAddModal(false);
  };

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <div
        className="investigation-drawer"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="notes-drawer-title"
        aria-modal="true"
      >
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className="drawer-icon" aria-hidden="true">📝</span>
            <h3 id="notes-drawer-title" className="drawer-title">
              Analyst Notes ({notes.length})
            </h3>
          </div>
          <div className="drawer-actions">
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => {
                setEditingNote(null);
                setTitle("");
                setContent("");
                setTagsInput("");
                setAttachedEvidenceInput("");
                setShowAddModal(true);
              }}
            >
              + New Note
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={onClose}
              aria-label="Close Notes Drawer"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Strict Epistemological Separation Banner */}
        <div className="notes-separation-banner" role="note">
          <span className="banner-icon" aria-hidden="true">🔒</span>
          <div>
            <strong>HUMAN ANALYST INPUT</strong>
            <p>
              Analyst notes are strictly separated from automated observations, inferences, and verdicts.
              They never alter automated ML predictions or heuristic scoring.
            </p>
          </div>
        </div>

        <div className="drawer-body">
          {notes.length === 0 ? (
            <EmptyState
              title="No Analyst Notes"
              message="Record hypotheses, triage notes, external threat intel correlations, or investigation summaries."
            />
          ) : (
            <ul className="note-list" role="list">
              {notes.map((n) => (
                <li key={n.note_id} className="note-card">
                  <div className="note-card-header">
                    <div className="note-author-meta">
                      <span className="badge badge-accent badge-sm">👤 {n.author}</span>
                      <span className="timestamp-text">
                        {new Date(n.created_at).toLocaleString(undefined, {
                          dateStyle: "short",
                          timeStyle: "short",
                        })}
                      </span>
                    </div>
                    <div className="note-card-actions">
                      <button
                        type="button"
                        className="btn-icon"
                        onClick={() => startEdit(n)}
                        title="Edit Note"
                        aria-label={`Edit note ${n.title}`}
                      >
                        ✏️
                      </button>
                      <button
                        type="button"
                        className="btn-icon-danger"
                        onClick={() => onDeleteNote(n.note_id)}
                        title="Delete Note"
                        aria-label={`Delete note ${n.title}`}
                      >
                        🗑️
                      </button>
                    </div>
                  </div>

                  <h4 className="note-card-title">{n.title}</h4>
                  <div className="note-card-body">{n.content}</div>

                  {(n.tags.length > 0 || n.attached_evidence_ids.length > 0) && (
                    <div className="note-card-footer">
                      {n.tags.length > 0 && (
                        <div className="note-tags">
                          {n.tags.map((tag, idx) => (
                            <span key={idx} className="badge badge-neutral badge-xs">
                              #{tag}
                            </span>
                          ))}
                        </div>
                      )}
                      {n.attached_evidence_ids.length > 0 && (
                        <div className="note-attached-evidence">
                          <small>Attached Evidence:</small>
                          {n.attached_evidence_ids.map((eId, idx) => (
                            <code key={idx} className="evidence-ref-pill">
                              {eId}
                            </code>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Modal for Create / Edit Note */}
        {(showAddModal || editingNote) && (
          <div className="nested-modal-overlay" role="dialog" aria-labelledby="note-form-title">
            <div className="nested-modal-card">
              <h4 id="note-form-title">{editingNote ? "Edit Analyst Note" : "Create Analyst Note"}</h4>
              <form onSubmit={editingNote ? handleEditSubmit : handleCreateSubmit}>
                {!editingNote && (
                  <div className="form-group">
                    <label htmlFor="note-author">Author</label>
                    <input
                      id="note-author"
                      className="input-control"
                      type="text"
                      placeholder="e.g. Lead Analyst Alice"
                      value={author}
                      onChange={(e) => setAuthor(e.target.value)}
                      required
                    />
                  </div>
                )}

                <div className="form-group">
                  <label htmlFor="note-title">Note Title</label>
                  <input
                    id="note-title"
                    className="input-control"
                    type="text"
                    placeholder="e.g. Staging Infrastructure Attribution Triage"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="note-content">Note Content (Analyst Assessment / Observations)</label>
                  <textarea
                    id="note-content"
                    className="textarea-control"
                    rows={4}
                    placeholder="Detailed analyst findings, external OSINT lookups, or hypothesis notes..."
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="note-tags">Tags (Comma-separated)</label>
                  <input
                    id="note-tags"
                    className="input-control"
                    type="text"
                    placeholder="e.g. c2, dropper, high-priority, osint"
                    value={tagsInput}
                    onChange={(e) => setTagsInput(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="note-evidence">Attached Evidence IDs (Comma-separated)</label>
                  <input
                    id="note-evidence"
                    className="input-control"
                    type="text"
                    placeholder="e.g. ev-static-1, ev-behavior-proc-2048"
                    value={attachedEvidenceInput}
                    onChange={(e) => setAttachedEvidenceInput(e.target.value)}
                  />
                </div>

                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => {
                      setShowAddModal(false);
                      setEditingNote(null);
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn-sm btn-primary"
                    disabled={isSubmitting || !sample}
                  >
                    {isSubmitting ? "Saving…" : editingNote ? "Update Note" : "Save Note"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
