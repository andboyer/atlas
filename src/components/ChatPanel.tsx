/**
 * ChatPanel — interactive LLM Q&A grounded in the current scan result.
 *
 * - Shown in Pro/Admin mode when a scan result is available.
 * - Collapsible to save vertical space.
 * - Maintains message history locally; sends history + question to chat_query.
 * - "Preview payload" opens a modal showing exactly what is sent to the LLM.
 * - If no API key is configured, shows a friendly prompt to set one in Settings.
 */
import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { MessageCircle, ChevronDown, ChevronUp, Send, Eye, X, Loader2, Trash2, Terminal } from "lucide-react";
import { useApp } from "../store";
import type { ScanResult } from "../types";

interface Props {
  scanResult: ScanResult;
}

export default function ChatPanel({ scanResult }: Props) {
  const settings = useApp((s) => s.settings);
  // Chat session lives in the global store so it survives navigating away
  // from this panel and persists until the app is closed.
  const open = useApp((s) => s.chatOpen);
  const setOpen = useApp((s) => s.setChatOpen);
  const messages = useApp((s) => s.chatMessages);
  const input = useApp((s) => s.chatInput);
  const setInput = useApp((s) => s.setChatInput);
  const loading = useApp((s) => s.chatLoading);
  const sendChat = useApp((s) => s.sendChat);
  const clearChat = useApp((s) => s.clearChat);
  const [previewText, setPreviewText] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Local providers (Ollama) don't need an API key; remote providers do.
  const provider = settings?.llm_provider ?? null;
  const isLocalProvider = provider === "ollama";
  const llmConfigured = isLocalProvider || !!settings?.llm_api_key;

  useEffect(() => {
    if (open && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, open]);

  async function handleSend() {
    const question = input.trim();
    if (!question || loading) return;
    // Fire-and-forget into the store: the request keeps running even if this
    // panel unmounts (e.g. the user switches tabs), and the answer still lands
    // in the persisted chat history.
    await sendChat(scanResult, question);
    inputRef.current?.focus();
  }

  async function handlePreview() {
    setLoadingPreview(true);
    try {
      const text = await invoke<string>("get_payload_preview", { scanResult });
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

  return (
    <div className="rounded-xl bg-white dark:bg-gray-800 shadow-sm overflow-hidden">
      {/* Header / toggle */}
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        onClick={() => setOpen(!open)}
      >
        <span className="flex items-center gap-2 font-semibold text-sm text-gray-700 dark:text-gray-200">
          <MessageCircle className="w-4 h-4 text-indigo-500" />
          Ask AI about this scan
        </span>
        {open ? (
          <ChevronUp className="w-4 h-4 text-gray-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-400" />
        )}
      </button>

      {open && (
        <div className="border-t border-gray-100 dark:border-gray-700">
          {!llmConfigured ? (
            <div className="px-4 py-6 text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">
                No LLM provider configured.
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500">
                Open <span className="font-mono">Settings</span> and choose an OpenAI / Anthropic key, or Ollama (local).
              </p>
            </div>
          ) : (
            <>
              {/* Message list */}
              <div className="flex flex-col gap-3 px-4 py-3 max-h-72 overflow-y-auto">
                {messages.length > 0 && (
                  <div className="flex justify-end">
                    <button
                      onClick={() => clearChat()}
                      disabled={loading}
                      className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      title="Clear conversation"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Clear
                    </button>
                  </div>
                )}
                {messages.length === 0 && (
                  <p className="text-xs text-gray-400 dark:text-gray-500 italic text-center py-2">
                    Ask a question about the scan results above — e.g.{" "}
                    <em>"Why is my latency so high?"</em> or{" "}
                    <em>"What's the fastest fix I can do right now?"</em>
                  </p>
                )}
                {messages.map((m, i) => (
                  m.step ? (
                    <div key={i} className="flex justify-center">
                      <div className="flex items-center gap-1.5 text-[11px] text-gray-400 dark:text-gray-500 italic px-2 py-0.5">
                        <Terminal className="w-3 h-3" />
                        <span>{m.content}</span>
                      </div>
                    </div>
                  ) : (
                  <div
                    key={i}
                    className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[80%] rounded-2xl px-3 py-2 text-sm whitespace-pre-wrap leading-relaxed ${
                        m.role === "user"
                          ? "bg-indigo-500 text-white rounded-br-sm"
                          : m.isError
                            ? "bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 rounded-bl-sm"
                            : "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100 rounded-bl-sm"
                      }`}
                    >
                      {m.content}
                    </div>
                  </div>
                  )
                ))}
                {loading && (
                  <div className="flex justify-start">
                    <div className="flex items-center gap-1.5 bg-gray-100 dark:bg-gray-700 rounded-2xl rounded-bl-sm px-3 py-2">
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                      <span className="text-xs text-gray-400">Thinking…</span>
                    </div>
                  </div>
                )}
                <div ref={bottomRef} />
              </div>

              {/* Input row */}
              <div className="px-3 pb-3 flex items-end gap-2">
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask a follow-up question… (Enter to send, Shift+Enter for newline)"
                  rows={2}
                  className="flex-1 resize-none rounded-xl border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-900 text-sm text-gray-800 dark:text-gray-100 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 placeholder:text-gray-400"
                />
                <button
                  onClick={handleSend}
                  disabled={!input.trim() || loading}
                  className="p-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-600 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-colors"
                  title="Send (Enter)"
                >
                  <Send className="w-4 h-4" />
                </button>
                <button
                  onClick={handlePreview}
                  disabled={loadingPreview}
                  className="p-2.5 rounded-xl border border-gray-200 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 disabled:opacity-40 transition-colors"
                  title="Preview what will be sent to the LLM"
                >
                  {loadingPreview ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* Payload preview modal */}
      {previewText != null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100 dark:border-gray-700">
              <h2 className="font-semibold text-sm text-gray-700 dark:text-gray-200">
                Payload preview — what will be sent to the LLM
              </h2>
              <button
                onClick={() => setPreviewText(null)}
                className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre className="flex-1 overflow-auto p-4 text-xs font-mono text-gray-700 dark:text-gray-300 whitespace-pre-wrap leading-relaxed">
              {previewText}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
