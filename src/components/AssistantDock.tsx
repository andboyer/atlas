/**
 * AssistantDock — the persistent, always-visible AI assistant.
 *
 * Lives in a right-hand column on every tab so AI is the forefront of the
 * tool, not a buried panel. It is Atlas-themed (design tokens, not the old
 * gray/white chat), grounds answers in the latest scan, can trigger a scan
 * when none exists yet, and surfaces one-click troubleshooting prompts.
 *
 * The agentic backend (`chat_agent`) can run probes and SSH into inventory
 * hosts, so this dock is the front door to both *explaining* and *acting*.
 */
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Sparkles,
  Send,
  Eye,
  X,
  Loader2,
  Trash2,
  Terminal,
  PanelRightClose,
  PanelRightOpen,
  ScanLine,
} from "lucide-react";
import { useApp } from "../store";

/** Troubleshooting starters shown when the conversation is empty. */
const SUGGESTIONS: string[] = [
  "Summarize my network health",
  "Why is my Wi-Fi slow right now?",
  "Any security risks I should fix?",
  "What's the single fastest fix I can do?",
];

export default function AssistantDock() {
  const settings = useApp((s) => s.settings);
  const collapsed = useApp((s) => s.assistantDockCollapsed);
  const setCollapsed = useApp((s) => s.setAssistantDockCollapsed);
  const messages = useApp((s) => s.chatMessages);
  const input = useApp((s) => s.chatInput);
  const setInput = useApp((s) => s.setChatInput);
  const loading = useApp((s) => s.chatLoading);
  const sendChat = useApp((s) => s.sendChat);
  const clearChat = useApp((s) => s.clearChat);
  const lastScan = useApp((s) => s.lastScan);
  const scanning = useApp((s) => s.scanning);
  const runQuickScan = useApp((s) => s.runQuickScan);

  const [previewText, setPreviewText] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const provider = settings?.llm_provider ?? null;
  const isLocalProvider = provider === "ollama";
  const llmConfigured = isLocalProvider || !!settings?.llm_api_key;

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send(question: string) {
    const q = question.trim();
    if (!q || loading) return;
    // The assistant needs a scan to ground its answer. If none exists yet,
    // run one first so the user never hits a dead end.
    let scan = useApp.getState().lastScan;
    if (!scan) {
      await runQuickScan();
      scan = useApp.getState().lastScan;
    }
    if (!scan) return;
    await sendChat(scan, q);
    inputRef.current?.focus();
  }

  function handleSend() {
    void send(input);
  }

  function handleSuggestion(text: string) {
    setInput("");
    void send(text);
  }

  async function handlePreview() {
    const scan = useApp.getState().lastScan;
    if (!scan) return;
    setLoadingPreview(true);
    try {
      const text = await invoke<string>("get_payload_preview", {
        scanResult: scan,
      });
      setPreviewText(text);
    } catch (e) {
      setPreviewText(`Error: ${String(e)}`);
    } finally {
      setLoadingPreview(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  // ── Collapsed rail ──────────────────────────────────────────────────────
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={() => setCollapsed(false)}
        title="Open AI assistant"
        className="group flex h-full w-12 flex-col items-center gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]/80 py-4 text-[var(--color-muted)] transition-colors hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text)]"
      >
        <PanelRightOpen className="h-4 w-4" />
        <Sparkles className="h-5 w-5 text-[var(--color-accent)]" />
        <span
          className="text-[11px] font-semibold uppercase tracking-[0.2em]"
          style={{ writingMode: "vertical-rl" }}
        >
          Atlas AI
        </span>
      </button>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]/80">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3">
        <span className="flex items-center gap-2 text-sm font-semibold text-[var(--color-text)]">
          <Sparkles className="h-4 w-4 text-[var(--color-accent)]" />
          Atlas AI
        </span>
        <div className="flex items-center gap-1">
          {messages.length > 0 && (
            <button
              onClick={() => clearChat()}
              disabled={loading}
              title="New conversation"
              className="rounded-lg p-1.5 text-[var(--color-muted)] transition-colors hover:bg-[var(--color-panel-2)]/70 hover:text-[var(--color-text)] disabled:opacity-40"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            onClick={() => setCollapsed(true)}
            title="Collapse assistant"
            className="rounded-lg p-1.5 text-[var(--color-muted)] transition-colors hover:bg-[var(--color-panel-2)]/70 hover:text-[var(--color-text)]"
          >
            <PanelRightClose className="h-4 w-4" />
          </button>
        </div>
      </div>

      {!llmConfigured ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6 text-center">
          <Sparkles className="h-6 w-6 text-[var(--color-muted)]" />
          <p className="text-sm text-[var(--color-text)]">
            No AI provider configured
          </p>
          <p className="text-xs text-[var(--color-muted)]">
            Open <span className="font-mono">Settings</span> and add an OpenAI /
            Anthropic key, or pick Ollama (local) to chat.
          </p>
        </div>
      ) : (
        <>
          {/* Message list */}
          <div className="flex flex-1 flex-col gap-3 overflow-y-auto px-4 py-4">
            {messages.length === 0 && (
              <div className="flex flex-col gap-3">
                <p className="text-sm text-[var(--color-text)]">
                  Ask anything about your network — I can read the latest scan,
                  run probes, and SSH into your fleet to troubleshoot.
                </p>
                <div className="flex flex-col gap-1.5">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      onClick={() => handleSuggestion(s)}
                      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)]/50 px-3 py-2 text-left text-xs text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)]/40 hover:bg-[var(--color-panel-2)]/80"
                    >
                      {s}
                    </button>
                  ))}
                </div>
                {!lastScan && (
                  <p className="text-[11px] text-[var(--color-muted)]">
                    No scan yet — asking will run one first to ground the
                    answer.
                  </p>
                )}
              </div>
            )}

            {messages.map((m, i) =>
              m.step ? (
                <div key={i} className="flex justify-center">
                  <div className="flex items-center gap-1.5 px-2 py-0.5 text-[11px] italic text-[var(--color-muted)]">
                    <Terminal className="h-3 w-3" />
                    <span>{m.content}</span>
                  </div>
                </div>
              ) : (
                <div
                  key={i}
                  className={`flex ${
                    m.role === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  <div
                    className={[
                      "max-w-[88%] whitespace-pre-wrap rounded-2xl px-3 py-2 text-sm leading-relaxed",
                      m.role === "user"
                        ? "rounded-br-sm bg-[var(--color-accent)]/90 text-[var(--color-bg)]"
                        : m.isError
                        ? "rounded-bl-sm border border-rose-500/30 bg-rose-500/10 text-rose-200"
                        : "rounded-bl-sm border border-[var(--color-border)] bg-[var(--color-panel-2)]/70 text-[var(--color-text)]",
                    ].join(" ")}
                  >
                    {m.content}
                  </div>
                </div>
              ),
            )}

            {(loading || scanning) && (
              <div className="flex justify-start">
                <div className="flex items-center gap-1.5 rounded-2xl rounded-bl-sm border border-[var(--color-border)] bg-[var(--color-panel-2)]/70 px-3 py-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--color-accent)]" />
                  <span className="text-xs text-[var(--color-muted)]">
                    {scanning && !loading ? "Scanning…" : "Thinking…"}
                  </span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="border-t border-[var(--color-border)] px-3 py-3">
            <div className="flex items-end gap-2">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your network…"
                rows={2}
                className="flex-1 resize-none rounded-xl border border-[var(--color-border)] bg-[var(--color-panel-2)]/50 px-3 py-2 text-sm text-[var(--color-text)] outline-none placeholder:text-[var(--color-muted)] focus:border-[var(--color-accent)]/50"
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || loading}
                title="Send (Enter)"
                className="rounded-xl bg-[var(--color-accent)] p-2.5 text-[var(--color-bg)] transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between">
              <button
                onClick={handlePreview}
                disabled={loadingPreview || !lastScan}
                className="inline-flex items-center gap-1 text-[11px] text-[var(--color-muted)] transition-colors hover:text-[var(--color-text)] disabled:opacity-40"
                title="Preview exactly what is sent to the LLM"
              >
                {loadingPreview ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Eye className="h-3 w-3" />
                )}
                Preview context
              </button>
              {lastScan ? (
                <span className="inline-flex items-center gap-1 text-[11px] text-[var(--color-muted)]">
                  <ScanLine className="h-3 w-3" />
                  Grounded in latest scan
                </span>
              ) : (
                <button
                  onClick={() => void runQuickScan()}
                  disabled={scanning}
                  className="inline-flex items-center gap-1 text-[11px] text-[var(--color-muted)] transition-colors hover:text-[var(--color-text)] disabled:opacity-40"
                >
                  <ScanLine className="h-3 w-3" />
                  Run a scan
                </button>
              )}
            </div>
          </div>
        </>
      )}

      {/* Payload preview modal */}
      {previewText !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6">
          <div className="flex max-h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3">
              <span className="text-sm font-semibold text-[var(--color-text)]">
                LLM context preview
              </span>
              <button
                onClick={() => setPreviewText(null)}
                className="rounded-lg p-1.5 text-[var(--color-muted)] hover:bg-[var(--color-panel-2)]/70 hover:text-[var(--color-text)]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <pre className="overflow-auto whitespace-pre-wrap px-4 py-3 text-xs text-[var(--color-muted)]">
              {previewText}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
