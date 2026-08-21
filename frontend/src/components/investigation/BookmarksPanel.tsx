import React, { useState } from "react";
import type {
  Bookmark,
  BookmarkCreateRequest,
  BookmarkTargetType,
  InvestigationTab,
  Sample,
} from "../../types/api";
import { EmptyState } from "../common/StateViews";

interface BookmarksPanelProps {
  sample: Sample | null;
  bookmarks: Bookmark[];
  onCreateBookmark: (data: BookmarkCreateRequest) => Promise<void>;
  onDeleteBookmark: (bookmarkId: string) => Promise<void>;
  onNavigateTab: (tab: InvestigationTab) => void;
  isOpen: boolean;
  onClose: () => void;
}

export function BookmarksPanel({
  sample,
  bookmarks,
  onCreateBookmark,
  onDeleteBookmark,
  onNavigateTab,
  isOpen,
  onClose,
}: BookmarksPanelProps) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [targetType, setTargetType] = useState<BookmarkTargetType>("evidence");
  const [targetId, setTargetId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("GENERAL");
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !targetId.trim()) return;

    try {
      setIsSubmitting(true);
      await onCreateBookmark({
        target_type: targetType,
        target_id: targetId.trim(),
        title: title.trim(),
        description: description.trim() || null,
        category: category.trim() || null,
      });
      setTitle("");
      setTargetId("");
      setDescription("");
      setShowAddModal(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleJump = (b: Bookmark) => {
    switch (b.target_type) {
      case "evidence":
        onNavigateTab("evidence");
        break;
      case "function":
      case "cfg_block":
        onNavigateTab("reverse");
        break;
      case "process":
      case "network_event":
      case "registry_event":
      case "dropped_file":
      case "timeline_event":
        onNavigateTab("behavior");
        break;
      case "attack_technique":
        onNavigateTab("attack");
        break;
      case "similarity_match":
        onNavigateTab("similarity");
        break;
      default:
        onNavigateTab("overview");
        break;
    }
    onClose();
  };

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <div
        className="investigation-drawer"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="bookmarks-drawer-title"
        aria-modal="true"
      >
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className="drawer-icon" aria-hidden="true">🔖</span>
            <h3 id="bookmarks-drawer-title" className="drawer-title">
              Investigation Bookmarks ({(bookmarks || []).length})
            </h3>
          </div>
          <div className="drawer-actions">
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setShowAddModal(true)}
            >
              + New Bookmark
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={onClose}
              aria-label="Close Bookmarks Drawer"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="drawer-body">
          {(bookmarks || []).length === 0 ? (
            <EmptyState
              title="No Bookmarks"
              message="Bookmark suspicious functions, evidence items, network connections, or ATT&CK techniques to curate your investigation."
            />
          ) : (
            <ul className="bookmark-list" role="list">
              {(bookmarks || []).map((b) => (
                <li key={b.bookmark_id} className="bookmark-card">
                  <div className="bookmark-card-header">
                    <div className="bookmark-meta-tags">
                      <span className="badge badge-category badge-sm">{(b.target_type || "general").toUpperCase()}</span>
                      {b.category && (
                        <span className="badge badge-neutral badge-sm">{b.category}</span>
                      )}
                    </div>
                    <button
                      type="button"
                      className="btn-icon-danger"
                      onClick={() => onDeleteBookmark(b.bookmark_id)}
                      title="Delete Bookmark"
                      aria-label={`Delete bookmark ${b.title}`}
                    >
                      🗑️
                    </button>
                  </div>

                  <h4 className="bookmark-card-title">{b.title}</h4>
                  {b.description && <p className="bookmark-card-desc">{b.description}</p>}

                  <div className="bookmark-card-footer">
                    <code className="bookmark-target-code">Target: {b.target_id}</code>
                    <button
                      type="button"
                      className="btn btn-xs btn-outline"
                      onClick={() => handleJump(b)}
                    >
                      Jump to Finding →
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {showAddModal && (
          <div className="nested-modal-overlay" role="dialog" aria-labelledby="add-bmk-title">
            <div className="nested-modal-card">
              <h4 id="add-bmk-title">Create Investigation Bookmark</h4>
              <form onSubmit={handleAddSubmit}>
                <div className="form-group">
                  <label htmlFor="bmk-type">Target Type</label>
                  <select
                    id="bmk-type"
                    className="select-control"
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value as BookmarkTargetType)}
                  >
                    <option value="evidence">Evidence Item</option>
                    <option value="function">Function</option>
                    <option value="cfg_block">CFG Basic Block</option>
                    <option value="process">Process Event</option>
                    <option value="network_event">Network Event</option>
                    <option value="registry_event">Registry Key</option>
                    <option value="dropped_file">Dropped File</option>
                    <option value="attack_technique">ATT&CK Technique</option>
                    <option value="similarity_match">Similarity Candidate</option>
                    <option value="custom">Custom Finding</option>
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="bmk-target">Target ID or Reference</label>
                  <input
                    id="bmk-target"
                    className="input-control"
                    type="text"
                    placeholder="e.g. ev-static-1, fn_401000, 192.168.1.5:8080"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="bmk-title">Bookmark Title</label>
                  <input
                    id="bmk-title"
                    className="input-control"
                    type="text"
                    placeholder="e.g. Obfuscated PowerShell Dropper Invocation"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="bmk-cat">Category / Tag</label>
                  <input
                    id="bmk-cat"
                    className="input-control"
                    type="text"
                    placeholder="e.g. GENERAL, TRIAGE, PERSISTENCE, C2"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="bmk-desc">Analyst Note / Context (Optional)</label>
                  <textarea
                    id="bmk-desc"
                    className="textarea-control"
                    rows={2}
                    placeholder="Why is this finding notable for this investigation?"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => setShowAddModal(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn-sm btn-primary"
                    disabled={isSubmitting || !sample}
                  >
                    {isSubmitting ? "Saving…" : "Save Bookmark"}
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
