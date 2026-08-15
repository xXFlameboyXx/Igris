import React, { useMemo, useState } from "react";

export interface Column<T> {
  id: string;
  header: string;
  accessor?: (row: T) => string | number | boolean | null | undefined;
  render?: (row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  align?: "left" | "center" | "right";
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      className="btn btn-xs btn-outline copy-btn"
      onClick={handleCopy}
      title={copied ? "Copied!" : `Copy ${label}`}
      aria-label={`Copy ${label}`}
    >
      {copied ? "✓ Copied" : "📋 Copy"}
    </button>
  );
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string;
  searchPlaceholder?: string;
  searchFilter?: (row: T, query: string) => boolean;
  defaultSortColumn?: string;
  defaultSortAsc?: boolean;
  pageSizeOptions?: number[];
  initialPageSize?: number;
  onRowClick?: (row: T) => void;
  selectedRowKey?: string;
  emptyMessage?: string;
  caption?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  searchPlaceholder = "Search records...",
  searchFilter,
  defaultSortColumn,
  defaultSortAsc = true,
  pageSizeOptions = [10, 25, 50, 100],
  initialPageSize = 10,
  onRowClick,
  selectedRowKey,
  emptyMessage = "No matching records found.",
  caption,
}: DataTableProps<T>) {
  const [searchQuery, setSearchQuery] = useState("");
  const [sortColumnId, setSortColumnId] = useState<string | undefined>(defaultSortColumn);
  const [sortAsc, setSortAsc] = useState<boolean>(defaultSortAsc);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);

  // Filter
  const filteredData = useMemo(() => {
    if (!searchQuery.trim()) return data;
    const q = searchQuery.toLowerCase().trim();
    if (searchFilter) {
      return data.filter((row) => searchFilter(row, q));
    }
    return data.filter((row) =>
      columns.some((col) => {
        if (col.accessor) {
          const val = col.accessor(row);
          return String(val ?? "").toLowerCase().includes(q);
        }
        return false;
      })
    );
  }, [data, searchQuery, searchFilter, columns]);

  // Sort
  const sortedData = useMemo(() => {
    if (!sortColumnId) return filteredData;
    const col = columns.find((c) => c.id === sortColumnId);
    if (!col || !col.accessor) return filteredData;

    return [...filteredData].sort((a, b) => {
      const valA = col.accessor!(a);
      const valB = col.accessor!(b);
      if (valA === valB) return 0;
      if (valA == null) return 1;
      if (valB == null) return -1;
      if (typeof valA === "number" && typeof valB === "number") {
        return sortAsc ? valA - valB : valB - valA;
      }
      return sortAsc
        ? String(valA).localeCompare(String(valB))
        : String(valB).localeCompare(String(valA));
    });
  }, [filteredData, sortColumnId, sortAsc, columns]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(sortedData.length / pageSize));
  const pageData = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedData.slice(start, start + pageSize);
  }, [sortedData, currentPage, pageSize]);

  const handleSort = (colId: string) => {
    if (sortColumnId === colId) {
      setSortAsc(!sortAsc);
    } else {
      setSortColumnId(colId);
      setSortAsc(true);
    }
    setCurrentPage(1);
  };

  return (
    <div className="data-table-container">
      <div className="table-controls">
        <div className="search-bar">
          <span className="search-icon" aria-hidden="true">🔍</span>
          <input
            type="text"
            className="search-input"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder={searchPlaceholder}
            aria-label={searchPlaceholder}
          />
          {searchQuery && (
            <button
              type="button"
              className="clear-search-btn"
              onClick={() => setSearchQuery("")}
              aria-label="Clear search"
            >
              ✕
            </button>
          )}
        </div>

        <div className="table-meta">
          <span className="record-count">
            Showing {sortedData.length > 0 ? (currentPage - 1) * pageSize + 1 : 0}–
            {Math.min(currentPage * pageSize, sortedData.length)} of {sortedData.length} entries
            {sortedData.length !== data.length && ` (filtered from ${data.length})`}
          </span>
          <div className="page-size-selector">
            <label htmlFor="page-size-select">Per page:</label>
            <select
              id="page-size-select"
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="table-responsive">
        <table className="analyst-table">
          {caption && <caption className="sr-only">{caption}</caption>}
          <thead>
            <tr>
              {columns.map((col) => {
                const isSorted = sortColumnId === col.id;
                return (
                  <th
                    key={col.id}
                    scope="col"
                    style={{ width: col.width, textAlign: col.align || "left" }}
                    aria-sort={isSorted ? (sortAsc ? "ascending" : "descending") : "none"}
                  >
                    {col.sortable !== false && col.accessor ? (
                      <button
                        type="button"
                        className={`th-sort-btn ${isSorted ? "active" : ""}`}
                        onClick={() => handleSort(col.id)}
                      >
                        <span>{col.header}</span>
                        <span className="sort-arrow" aria-hidden="true">
                          {isSorted ? (sortAsc ? " ▲" : " ▼") : " ⬍"}
                        </span>
                      </button>
                    ) : (
                      <span>{col.header}</span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {pageData.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="table-empty-cell">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              pageData.map((row, idx) => {
                const key = keyExtractor(row, idx);
                const isSelected = selectedRowKey === key;
                return (
                  <tr
                    key={key}
                    className={`table-row ${onRowClick ? "clickable" : ""} ${isSelected ? "selected" : ""}`}
                    onClick={() => onRowClick && onRowClick(row)}
                  >
                    {columns.map((col) => {
                      const content = col.render
                        ? col.render(row)
                        : col.accessor
                        ? String(col.accessor(row) ?? "—")
                        : "—";
                      return (
                        <td key={col.id} style={{ textAlign: col.align || "left" }}>
                          {content}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="pagination-bar" role="navigation" aria-label="Table pagination">
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            disabled={currentPage <= 1}
            onClick={() => setCurrentPage(1)}
            aria-label="First page"
          >
            « First
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            disabled={currentPage <= 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            aria-label="Previous page"
          >
            ‹ Prev
          </button>

          <span className="page-indicator">
            Page {currentPage} of {totalPages}
          </span>

          <button
            type="button"
            className="btn btn-sm btn-secondary"
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            aria-label="Next page"
          >
            Next ›
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage(totalPages)}
            aria-label="Last page"
          >
            Last »
          </button>
        </div>
      )}
    </div>
  );
}
