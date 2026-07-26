import React, { useState, useEffect, useRef } from 'react';
import ErrorBoundary from '@docusaurus/ErrorBoundary';
import { ErrorBoundaryErrorMessageFallback } from '@docusaurus/theme-common';
import {
  MermaidContainerClassName,
  useMermaidRenderResult,
} from '@docusaurus/theme-mermaid/client';
import styles from './styles.module.css';

interface MermaidProps {
  value: string;
}

function MermaidRenderResult({ renderResult, value }: { renderResult: any; value: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(1);

  useEffect(() => {
    const div = ref.current;
    if (div && renderResult?.bindFunctions) {
      renderResult.bindFunctions(div);
    }
  }, [renderResult]);

  // Handle ESC key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isExpanded) {
        setIsExpanded(false);
        setZoomLevel(1);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isExpanded]);

  const handleZoomIn = (e: React.MouseEvent) => {
    e.stopPropagation();
    setZoomLevel((prev) => Math.min(prev + 0.25, 3.0));
  };

  const handleZoomOut = (e: React.MouseEvent) => {
    e.stopPropagation();
    setZoomLevel((prev) => Math.max(prev - 0.25, 0.5));
  };

  const handleResetZoom = (e: React.MouseEvent) => {
    e.stopPropagation();
    setZoomLevel(1);
  };

  const openModal = () => {
    setIsExpanded(true);
    setZoomLevel(1);
  };

  const closeModal = () => {
    setIsExpanded(false);
    setZoomLevel(1);
  };

  return (
    <>
      {/* Normal Diagram View with Click-to-Expand Badge */}
      <div className={styles.mermaidWrapper}>
        <button
          type="button"
          className={styles.expandBadge}
          onClick={openModal}
          title="Click to expand diagram fullscreen"
          aria-label="Expand diagram to fullscreen modal">
          <span aria-hidden="true">🔍</span>
          <span>Expand Diagram</span>
        </button>

        <div
          ref={ref}
          className={`${MermaidContainerClassName} ${styles.container}`}
          onClick={openModal}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              openModal();
            }
          }}
          title="Click diagram to view fullscreen"
          dangerouslySetInnerHTML={{ __html: renderResult.svg }}
        />
      </div>

      {/* Fullscreen Interactive Zoom Modal */}
      {isExpanded && (
        <div
          className={styles.modalOverlay}
          onClick={closeModal}
          role="dialog"
          aria-modal="true"
          aria-label="Fullscreen Diagram Viewer">
          <div
            className={styles.modalContent}
            onClick={(e) => e.stopPropagation()}>
            {/* Modal Top Control Bar */}
            <div className={styles.modalHeader}>
              <div className={styles.modalTitle}>
                <span aria-hidden="true">📊</span>
                <span>Diagram Viewer</span>
                <span className={styles.zoomBadge}>{Math.round(zoomLevel * 100)}%</span>
              </div>

              <div className={styles.modalControls}>
                <button
                  type="button"
                  className={styles.controlBtn}
                  onClick={handleZoomIn}
                  title="Zoom In (+25%)">
                  ➕ Zoom In
                </button>
                <button
                  type="button"
                  className={styles.controlBtn}
                  onClick={handleZoomOut}
                  title="Zoom Out (-25%)">
                  ➖ Zoom Out
                </button>
                <button
                  type="button"
                  className={styles.controlBtn}
                  onClick={handleResetZoom}
                  title="Reset Zoom (100%)">
                  🔄 Reset
                </button>
                <button
                  type="button"
                  className={`${styles.controlBtn} ${styles.closeBtn}`}
                  onClick={closeModal}
                  title="Close Fullscreen (ESC)">
                  ❌ Close (ESC)
                </button>
              </div>
            </div>

            {/* Scalable Diagram Viewport */}
            <div className={styles.modalBody}>
              <div
                className={styles.zoomViewport}
                style={{ transform: `scale(${zoomLevel})` }}
                dangerouslySetInnerHTML={{ __html: renderResult.svg }}
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function MermaidRenderer({ value }: MermaidProps) {
  const renderResult = useMermaidRenderResult({ text: value });
  if (renderResult === null) {
    return null;
  }
  return <MermaidRenderResult renderResult={renderResult} value={value} />;
}

export default function Mermaid(props: MermaidProps) {
  return (
    <ErrorBoundary
      fallback={(params) => <ErrorBoundaryErrorMessageFallback {...params} />}>
      <MermaidRenderer {...props} />
    </ErrorBoundary>
  );
}
