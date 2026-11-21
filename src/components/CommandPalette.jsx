import React, { useEffect, useMemo, useState } from "react";
import { ArrowRight, Command, Search, X } from "lucide-react";

export default function CommandPalette({ open, items, onClose, onNavigate }) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
    }
  }, [open]);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items.slice(0, 12);
    return items.filter(item =>
      `${item.label} ${item.group || ""}`.toLowerCase().includes(needle)
    ).slice(0, 12);
  }, [items, query]);

  if (!open) return null;

  const choose = item => {
    onNavigate(item.id);
    onClose();
  };

  return (
    <div
      className="wa-command-backdrop"
      role="presentation"
      onMouseDown={event => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section className="wa-command-dialog" role="dialog" aria-modal="true" aria-labelledby="wa-command-title">
        <div className="wa-command-search">
          <Search size={18} aria-hidden="true"/>
          <label id="wa-command-title" className="wa-sr-only">Navigate to a workspace page</label>
          <input
            autoFocus
            type="search"
            value={query}
            onChange={event => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={event => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActiveIndex(index => Math.min(index + 1, Math.max(0, matches.length - 1)));
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setActiveIndex(index => Math.max(0, index - 1));
              } else if (event.key === "Enter" && matches[activeIndex]) {
                event.preventDefault();
                choose(matches[activeIndex]);
              } else if (event.key === "Escape") {
                event.preventDefault();
                onClose();
              }
            }}
            placeholder="Search pages, tools and settings…"
            aria-label="Search all workspace pages"
            aria-controls="wa-command-results"
            aria-activedescendant={matches[activeIndex] ? `wa-command-${matches[activeIndex].id}` : undefined}
          />
          <button type="button" className="wa-command-close" onClick={onClose} aria-label="Close command menu"><X size={16}/></button>
        </div>
        <div className="wa-command-meta">
          <span>{query.trim() ? `${matches.length} matching pages` : "Quick navigation"}</span>
          <span><kbd>↑</kbd><kbd>↓</kbd> to move <kbd>↵</kbd> to open</span>
        </div>
        <div id="wa-command-results" className="wa-command-results" role="listbox" aria-label="Workspace pages">
          {matches.map((item, index) => {
            const Icon = item.Icon;
            return (
              <button
                type="button"
                id={`wa-command-${item.id}`}
                key={item.id}
                role="option"
                aria-selected={index === activeIndex}
                className={index === activeIndex ? "wa-command-item active" : "wa-command-item"}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(item)}
              >
                <span className="wa-command-item-icon"><Icon size={15}/></span>
                <span className="wa-command-item-copy">
                  <strong>{item.label}</strong>
                  <small>{item.group}</small>
                </span>
                <ArrowRight size={14} className="wa-command-item-arrow"/>
              </button>
            );
          })}
          {matches.length === 0 && (
            <div className="wa-command-empty" role="status">
              <Search size={18}/>
              <span>No workspace pages match “{query.trim()}”.</span>
            </div>
          )}
        </div>
        <div className="wa-command-footer">
          <span><Command size={12}/> Workspace navigation</span>
          <button type="button" onClick={onClose}>Dismiss <kbd>Esc</kbd></button>
        </div>
      </section>
    </div>
  );
}
