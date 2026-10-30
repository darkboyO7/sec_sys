import React, { useEffect, useRef } from 'react';
import { X, AlertTriangle, Loader2 } from 'lucide-react';

export interface AccessibleModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  onConfirm?: () => void | Promise<void>;
  isDestructive?: boolean;
  isSubmitting?: boolean;
  role?: 'dialog' | 'alertdialog';
  maxWidthClass?: string;
}

export const AccessibleModal: React.FC<AccessibleModalProps> = ({
  isOpen,
  onClose,
  title,
  description,
  children,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  onConfirm,
  isDestructive = false,
  isSubmitting = false,
  role = isDestructive ? 'alertdialog' : 'dialog',
  maxWidthClass = 'max-w-lg',
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  const titleId = `modal-title-${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
  const descId = description ? `modal-desc-${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}` : undefined;

  // Manage focus trap and escape key
  useEffect(() => {
    if (!isOpen) return;

    previouslyFocusedElementRef.current = document.activeElement as HTMLElement;

    // Focus cancel button for destructive actions to prevent accidental confirm
    if (isDestructive && cancelButtonRef.current) {
      cancelButtonRef.current.focus();
    } else if (confirmButtonRef.current) {
      confirmButtonRef.current.focus();
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isSubmitting) {
        e.preventDefault();
        onClose();
        return;
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusableElements = modalRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        const focusable = Array.from(focusableElements);
        if (focusable.length === 0) return;

        const firstElement = focusable[0];
        const lastElement = focusable[focusable.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (previouslyFocusedElementRef.current) {
        previouslyFocusedElementRef.current.focus();
      }
    };
  }, [isOpen, isDestructive, isSubmitting, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget && !isSubmitting) {
          onClose();
        }
      }}
    >
      <div
        ref={modalRef}
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className={`w-full ${maxWidthClass} bg-cyber-900 border border-cyber-700 rounded-xl shadow-2xl p-6 text-slate-100 animate-in fade-in zoom-in-95 duration-150`}
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-cyber-800">
          <div className="flex items-center gap-3">
            {isDestructive && (
              <span className="p-2 bg-red-500/10 text-red-400 rounded-lg border border-red-500/20" aria-hidden="true">
                <AlertTriangle className="w-5 h-5" />
              </span>
            )}
            <div>
              <h2 id={titleId} className="text-lg font-bold text-white tracking-wide">
                {title}
              </h2>
              {description && (
                <p id={descId} className="text-xs text-slate-400 mt-1">
                  {description}
                </p>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            aria-label="Close dialog"
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-cyber-800 transition disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-accent-cyan"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="py-4 text-sm text-slate-300">
          {children}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-cyber-800">
          <button
            ref={cancelButtonRef}
            type="button"
            onClick={onClose}
            disabled={isSubmitting}
            className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white bg-cyber-800 hover:bg-cyber-750 transition disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyber-600"
          >
            {cancelText}
          </button>
          {onConfirm && (
            <button
              ref={confirmButtonRef}
              type="button"
              onClick={onConfirm}
              disabled={isSubmitting}
              aria-busy={isSubmitting}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition disabled:opacity-50 focus:outline-none focus:ring-2 ${
                isDestructive
                  ? 'bg-red-600 hover:bg-red-500 text-white focus:ring-red-400'
                  : 'bg-accent-cyan hover:bg-cyan-400 text-cyber-950 focus:ring-cyan-300'
              }`}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                  <span>Processing...</span>
                </>
              ) : (
                confirmText
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
