import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import "./styles/atlas-tokens.css";

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: string | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(e: unknown) {
    return { error: String(e) };
  }
  componentDidCatch(e: unknown, info: React.ErrorInfo) {
    console.error("React crash:", e, info);
    this.setState({ error: String(e) + "\n\n" + (info.componentStack ?? "") });
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ position: "fixed", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "#0b1020", color: "#f87171", fontFamily: "monospace", fontSize: 13, padding: 32, whiteSpace: "pre-wrap" }}>
          {"React Error:\n" + this.state.error}
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
