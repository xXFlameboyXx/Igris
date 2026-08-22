import React, { useState } from "react";
import { BRANDING } from "../../config/branding";
import type { HealthResponse, Sample } from "../../types/api";
import { BrandLogo } from "../common/BrandLogo";
import { CopyButton } from "../common/DataTable";
import { Modal } from "../common/Modal";

interface HeaderProps {
  currentSample: Sample | null;
  samplesList?: Sample[];
  onSelectSampleId: (sampleId: string) => void;
  onUploadSample: (file: File) => Promise<void>;
  onDeleteSample?: (sampleId: string) => Promise<void>;
  health: HealthResponse | null;
  bookmarksCount?: number;
  notesCount?: number;
  onOpenBookmarks?: () => void;
  onOpenNotes?: () => void;
  isUploadOpen?: boolean;
  onSetIsUploadOpen?: (open: boolean) => void;
}

export function Header({
  currentSample,
  samplesList = [],
  onSelectSampleId,
  onUploadSample,
  onDeleteSample,
  health,
  bookmarksCount = 0,
  notesCount = 0,
  onOpenBookmarks,
  onOpenNotes,
  isUploadOpen: externalIsUploadOpen,
  onSetIsUploadOpen,
}: HeaderProps) {
  const [internalIsUploadOpen, setInternalIsUploadOpen] = useState(false);
  const isUploadOpen = externalIsUploadOpen !== undefined ? externalIsUploadOpen : internalIsUploadOpen;
  const setIsUploadOpen = onSetIsUploadOpen || setInternalIsUploadOpen;

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [customSampleId, setCustomSampleId] = useState("");
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    setUploading(true);
    setUploadError(null);
    try {
      await onUploadSample(selectedFile);
      setIsUploadOpen(false);
      setSelectedFile(null);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Failed to upload sample.");
    } finally {
      setUploading(false);
    }
  };

  const handleCustomSampleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (customSampleId.trim()) {
      onSelectSampleId(customSampleId.trim());
      setCustomSampleId("");
    }
  };

  return (
    <header className="app-header" role="banner">
      <div className="header-brand-row">
        <div className="brand-lockup">
          <BrandLogo size="md" />
          <div className="brand-titles-wrapper">
            <h1 className="brand-title">{BRANDING.appName}</h1>
            <p className="brand-tagline">{BRANDING.tagline}</p>
          </div>
        </div>

        <div className="header-controls">
          {/* Sample Selector */}
          <div className="sample-selector-group">
            <label htmlFor="sample-quick-select" className="sr-only">
              Select Sample
            </label>
            <select
              id="sample-quick-select"
              className="sample-select-dropdown"
              value={currentSample?.sample_id || ""}
              onChange={(e) => onSelectSampleId(e.target.value)}
              aria-label="Select active sample"
            >
              {samplesList.length === 0 ? (
                <option value="" disabled>
                  No specimens available
                </option>
              ) : (
                <optgroup label="Ingested Specimens">
                  {samplesList.map((s) => (
                    <option key={s.sample_id} value={s.sample_id}>
                      {s.original_filename || s.safe_filename || s.sample_id.slice(0, 8)} ({s.malware_assessment?.verdict || s.status})
                    </option>
                  ))}
                </optgroup>
              )}
              {currentSample && !samplesList.some((d) => d.sample_id === currentSample.sample_id) && (
                <optgroup label="Active Investigation">
                  <option value={currentSample.sample_id}>
                    {currentSample.original_filename || currentSample.safe_filename || currentSample.sample_id.slice(0, 8)} ({currentSample.sample_id.slice(0, 8)})
                  </option>
                </optgroup>
              )}
            </select>

            <button
              type="button"
              className="btn btn-sm btn-primary upload-trigger-btn"
              onClick={() => setIsUploadOpen(true)}
            >
              ⬆ Upload Specimen
            </button>

            {currentSample && onDeleteSample && (
              <button
                type="button"
                className="btn btn-sm btn-outline-danger remove-specimen-btn"
                onClick={() => {
                  setDeleteError(null);
                  setIsDeleteOpen(true);
                }}
                title="Remove current specimen and its investigation history"
              >
                ✕ Remove Specimen
              </button>
            )}

            {onOpenBookmarks && (
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={onOpenBookmarks}
                title="Open Investigation Bookmarks"
              >
                🔖 Bookmarks ({bookmarksCount})
              </button>
            )}

            {onOpenNotes && (
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={onOpenNotes}
                title="Open Analyst Notes"
              >
                📝 Notes ({notesCount})
              </button>
            )}
          </div>

          {/* System Health */}
          <div className="health-status-badge">
            <span
              className={`health-dot ${health?.status === "ok" ? "healthy" : "degraded"}`}
              aria-hidden="true"
            />
            <span className="health-label">
              API: {health?.status === "ok" ? "READY" : health?.status || "CONNECTING"}
            </span>
          </div>
        </div>
      </div>

      {/* Active Sample Context Bar */}
      {currentSample && (
        <div className="sample-context-bar" role="region" aria-label="Active sample context">
          <div className="context-item filename-context">
            <span className="context-label">SPECIMEN:</span>
            <strong className="context-val">{currentSample.original_filename || currentSample.safe_filename || currentSample.sample_id}</strong>
          </div>

          <div className="context-item sha-context">
            <span className="context-label">SHA-256:</span>
            <code className="context-hash" title={currentSample.hashes.sha256}>
              {currentSample.hashes.sha256.slice(0, 16)}…{currentSample.hashes.sha256.slice(-8)}
            </code>
            <CopyButton text={currentSample.hashes.sha256} label="SHA-256" />
          </div>

          <div className="context-item size-context">
            <span className="context-label">SIZE:</span>
            <span className="context-val">
              {(currentSample.size_bytes / 1024).toFixed(1)} KB ({currentSample.size_bytes.toLocaleString()} bytes)
            </span>
          </div>

          <div className="context-item format-context">
            <span className="context-label">FORMAT:</span>
            <span className="context-val uppercase">
              {currentSample.file_metadata?.file_format || "PE/BIN"} ({currentSample.file_metadata?.architecture || "x86_64"})
            </span>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      <Modal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        title="Upload Specimen for Investigation"
        footer={
          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsUploadOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              form="upload-form"
              className="btn btn-primary"
              disabled={!selectedFile || uploading}
            >
              {uploading ? "Ingesting Specimen..." : "Start Investigation"}
            </button>
          </div>
        }
      >
        <form id="upload-form" onSubmit={handleUploadSubmit} className="upload-form">
          <p className="form-help-text">
            Upload an executable, library, or raw binary for automated static, reverse,
            behavioral, and explainable malware assessment.
          </p>

          <div className="file-drop-area">
            <input
              type="file"
              id="file-upload-input"
              className="file-input-hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  setSelectedFile(e.target.files[0]);
                }
              }}
              required
            />
            <label htmlFor="file-upload-input" className="file-drop-label">
              <span className="drop-icon" aria-hidden="true">📁</span>
              <span className="drop-prompt">
                {selectedFile ? `Selected: ${selectedFile.name}` : "Click to select a binary file"}
              </span>
              <span className="drop-sub">PE (.exe, .dll), ELF, or Mach-O binaries</span>
            </label>
          </div>

          {uploadError && (
            <p className="form-error" role="alert">
              {uploadError}
            </p>
          )}

          <div className="custom-id-divider">
            <span>OR LOOK UP EXISTING SPECIMEN ID</span>
          </div>

          <div className="custom-id-row">
            <input
              type="text"
              className="search-input"
              placeholder="Paste Specimen ID..."
              value={customSampleId}
              onChange={(e) => setCustomSampleId(e.target.value)}
              aria-label="Paste existing specimen ID"
            />
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleCustomSampleSubmit}
              disabled={!customSampleId.trim()}
            >
              Load ID
            </button>
          </div>
        </form>
      </Modal>

      {/* Remove Specimen Confirmation Modal */}
      {currentSample && (
        <Modal
          isOpen={isDeleteOpen}
          onClose={() => {
            if (!deleting) setIsDeleteOpen(false);
          }}
          title="Remove specimen?"
          footer={
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setIsDeleteOpen(false)}
                disabled={deleting}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={async () => {
                  if (!onDeleteSample || !currentSample) return;
                  setDeleting(true);
                  setDeleteError(null);
                  try {
                    await onDeleteSample(currentSample.sample_id);
                    setIsDeleteOpen(false);
                  } catch (err) {
                    setDeleteError(err instanceof Error ? err.message : "Failed to remove specimen.");
                  } finally {
                    setDeleting(false);
                  }
                }}
                disabled={deleting}
              >
                {deleting ? "Removing specimen..." : "Remove specimen"}
              </button>
            </div>
          }
        >
          <div className="delete-specimen-confirmation">
            <p style={{ marginBottom: "14px", color: "var(--text-primary)", fontSize: "14px", lineHeight: "1.5" }}>
              This will remove the uploaded specimen and its associated analysis history from IGRIS. This action cannot be undone.
            </p>
            <div
              style={{
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "6px",
                padding: "12px 14px",
                fontSize: "12px",
                color: "var(--text-secondary)",
                marginBottom: "12px",
                display: "flex",
                flexDirection: "column",
                gap: "6px",
              }}
            >
              <div>
                <strong>Filename:</strong>{" "}
                <span style={{ color: "var(--text-primary)" }}>
                  {currentSample.original_filename || currentSample.safe_filename || currentSample.sample_id}
                </span>
              </div>
              <div>
                <strong>Specimen ID:</strong> <code>{currentSample.sample_id}</code>
              </div>
              {currentSample.hashes?.sha256 && (
                <div>
                  <strong>SHA-256:</strong> <code>{currentSample.hashes.sha256}</code>
                </div>
              )}
            </div>
            {deleteError && (
              <p className="form-error" role="alert">
                {deleteError}
              </p>
            )}
          </div>
        </Modal>
      )}
    </header>
  );
}
