/**
 * OnboardingWizard — first-run setup flow.
 *
 * Step 1: Welcome — explains what the app does and the three user modes.
 * Step 2: Profile — pick your environment (Home / Office / POS / Smart Home).
 * Step 3: AI (optional) — add an LLM key for AI explanations and chat.
 * Step 4: Ready — kick off the first scan.
 *
 * On completion writes settings (profile + optional key + onboarding_complete=true)
 * then calls onComplete() to dismiss.
 */
import { useState } from "react";
import { useApp } from "../store";
import {
  Wifi,
  Building2,
  ShoppingCart,
  Home,
  Cpu,
  Sparkles,
  ChevronRight,
  ChevronLeft,
  CheckCircle2,
  Eye,
  EyeOff,
} from "lucide-react";

interface Props {
  onComplete: () => void;
}

type Profile = {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
};

const PROFILES: Profile[] = [
  {
    id: "home",
    label: "Home",
    description: "Personal WiFi, streaming, remote work. Optimises for reliability and speed.",
    icon: <Home className="w-6 h-6" />,
  },
  {
    id: "office",
    label: "Office",
    description: "Corporate or SMB LAN. Monitors VoIP, cloud apps, and multi-SSID setups.",
    icon: <Building2 className="w-6 h-6" />,
  },
  {
    id: "retail_pos",
    label: "Retail / POS",
    description: "Point-of-sale terminals and payment processors. Checks card-network reachability.",
    icon: <ShoppingCart className="w-6 h-6" />,
  },
  {
    id: "smart_home",
    label: "Smart Home / IoT",
    description: "Many low-power devices. Detects congestion, rogue APs, and DHCP exhaustion.",
    icon: <Cpu className="w-6 h-6" />,
  },
];

const TOTAL_STEPS = 4;

export default function OnboardingWizard({ onComplete }: Props) {
  const { settings, saveSettings, runQuickScan } = useApp();

  const [step, setStep] = useState(1);
  const [profile, setProfile] = useState(settings?.industry_profile ?? "home");
  const [provider, setProvider] = useState("openai");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);

  async function handleFinish() {
    setSaving(true);
    try {
      await saveSettings({
        ...settings!,
        industry_profile: profile,
        llm_provider: apiKey.trim() ? provider : settings?.llm_provider ?? null,
        llm_api_key: apiKey.trim() || settings?.llm_api_key || null,
        onboarding_complete: true,
      });
      runQuickScan(); // fire-and-forget first scan
      onComplete();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-white dark:bg-gray-900 rounded-3xl shadow-2xl w-full max-w-lg overflow-hidden">
        {/* Progress bar */}
        <div className="h-1 bg-gray-100 dark:bg-gray-800">
          <div
            className="h-1 bg-indigo-500 transition-all duration-300"
            style={{ width: `${(step / TOTAL_STEPS) * 100}%` }}
          />
        </div>

        <div className="p-8">
          {step === 1 && <StepWelcome />}
          {step === 2 && (
            <StepProfile selected={profile} onSelect={setProfile} />
          )}
          {step === 3 && (
            <StepAI
              provider={provider}
              onProvider={setProvider}
              apiKey={apiKey}
              onApiKey={setApiKey}
              showKey={showKey}
              onToggleShow={() => setShowKey((v) => !v)}
            />
          )}
          {step === 4 && <StepReady profile={profile} hasKey={!!apiKey.trim()} />}

          {/* Navigation */}
          <div className="mt-8 flex items-center justify-between">
            {step > 1 ? (
              <button
                onClick={() => setStep((s) => s - 1)}
                className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                Back
              </button>
            ) : (
              <span />
            )}

            {step < TOTAL_STEPS ? (
              <button
                onClick={() => setStep((s) => s + 1)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-600 text-white text-sm font-medium transition-colors"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                onClick={handleFinish}
                disabled={saving}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-600 disabled:opacity-60 text-white text-sm font-medium transition-colors"
              >
                {saving ? "Starting…" : "Start scanning"}
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Step indicator dots */}
          <div className="mt-6 flex justify-center gap-1.5">
            {Array.from({ length: TOTAL_STEPS }, (_, i) => (
              <div
                key={i}
                className={`rounded-full transition-all duration-200 ${
                  i + 1 === step
                    ? "w-5 h-1.5 bg-indigo-500"
                    : i + 1 < step
                    ? "w-1.5 h-1.5 bg-indigo-300 dark:bg-indigo-700"
                    : "w-1.5 h-1.5 bg-gray-200 dark:bg-gray-700"
                }`}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Step components ────────────────────────────────────────────────────────────

function StepWelcome() {
  return (
    <div className="text-center">
      <div className="flex justify-center mb-5">
        <div className="p-4 rounded-2xl bg-indigo-50 dark:bg-indigo-900/30">
          <Wifi className="w-10 h-10 text-indigo-500" />
        </div>
      </div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">
        Welcome to WiFi Troubleshooter
      </h1>
      <p className="text-gray-500 dark:text-gray-400 text-sm leading-relaxed mb-6">
        This app continuously monitors your WiFi and LAN, detects issues before they
        become outages, and explains fixes in plain language.
      </p>
      <div className="grid grid-cols-3 gap-3 text-left">
        {[
          { label: "Simple", desc: "See the overall health status and top fix." },
          { label: "Pro", desc: "Live metrics, charts, and service status." },
          { label: "Admin", desc: "Full timeline, channel map, and device list." },
        ].map((m) => (
          <div key={m.label} className="rounded-xl bg-gray-50 dark:bg-gray-800 p-3">
            <p className="font-semibold text-xs text-indigo-500 mb-1">{m.label}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 leading-snug">{m.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function StepProfile({
  selected,
  onSelect,
}: {
  selected: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div>
      <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-1">
        What's your environment?
      </h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-5">
        This tunes the detection rules and recommendations for your situation.
      </p>
      <div className="grid grid-cols-2 gap-3">
        {PROFILES.map((p) => (
          <button
            key={p.id}
            onClick={() => onSelect(p.id)}
            className={`text-left rounded-2xl border-2 p-4 transition-all ${
              selected === p.id
                ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20"
                : "border-gray-200 dark:border-gray-700 hover:border-indigo-300 dark:hover:border-indigo-700"
            }`}
          >
            <div
              className={`mb-2 ${
                selected === p.id
                  ? "text-indigo-500"
                  : "text-gray-400 dark:text-gray-500"
              }`}
            >
              {p.icon}
            </div>
            <p className="font-semibold text-sm text-gray-800 dark:text-gray-100 mb-0.5">
              {p.label}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400 leading-snug">
              {p.description}
            </p>
          </button>
        ))}
      </div>
    </div>
  );
}

function StepAI({
  provider,
  onProvider,
  apiKey,
  onApiKey,
  showKey,
  onToggleShow,
}: {
  provider: string;
  onProvider: (v: string) => void;
  apiKey: string;
  onApiKey: (v: string) => void;
  showKey: boolean;
  onToggleShow: () => void;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <Sparkles className="w-5 h-5 text-indigo-500" />
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">AI explanations</h2>
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-5 leading-relaxed">
        Optionally add an API key to unlock plain-language explanations and interactive
        Q&A. Your key is stored locally and never leaves your device except to call the
        chosen provider directly.
      </p>

      <div className="space-y-4">
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1.5">
            Provider
          </label>
          <div className="flex gap-2">
            {["openai", "anthropic", "ollama"].map((p) => (
              <button
                key={p}
                onClick={() => onProvider(p)}
                className={`flex-1 py-2 rounded-xl text-xs font-medium border transition-all ${
                  provider === p
                    ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400"
                    : "border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-indigo-300"
                }`}
              >
                {p === "openai" ? "OpenAI" : p === "anthropic" ? "Anthropic" : "Ollama (local)"}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1.5">
            {provider === "ollama" ? "Base URL (optional, defaults to localhost:11434)" : "API key (optional — skip to set up later)"}
          </label>
          <div className="relative">
            <input
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => onApiKey(e.target.value)}
              placeholder={
                provider === "ollama"
                  ? "http://localhost:11434"
                  : provider === "anthropic"
                  ? "sk-ant-…"
                  : "sk-…"
              }
              className="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-sm px-3 py-2.5 pr-9 text-gray-800 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            />
            <button
              type="button"
              onClick={onToggleShow}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>

      <p className="mt-4 text-xs text-gray-400 dark:text-gray-500">
        You can always add or change the key later in Settings.
      </p>
    </div>
  );
}

function StepReady({ profile, hasKey }: { profile: string; hasKey: boolean }) {
  const profileLabel =
    PROFILES.find((p) => p.id === profile)?.label ?? profile;

  return (
    <div className="text-center">
      <div className="flex justify-center mb-5">
        <div className="p-4 rounded-2xl bg-emerald-50 dark:bg-emerald-900/20">
          <CheckCircle2 className="w-10 h-10 text-emerald-500" />
        </div>
      </div>
      <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">
        You're all set!
      </h2>
      <div className="text-sm text-gray-500 dark:text-gray-400 space-y-1 mb-6">
        <p>
          Profile: <span className="font-medium text-gray-700 dark:text-gray-200">{profileLabel}</span>
        </p>
        <p>
          AI explanations:{" "}
          <span className="font-medium text-gray-700 dark:text-gray-200">
            {hasKey ? "enabled" : "not configured (add later in Settings)"}
          </span>
        </p>
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 leading-relaxed">
        Clicking <strong>Start scanning</strong> will run your first diagnostic and
        show you the results immediately.
      </p>
    </div>
  );
}
