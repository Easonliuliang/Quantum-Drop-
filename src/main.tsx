import React from "react";
import ReactDOM from "react-dom/client";
import "./styles.css";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider } from "./lib/i18n";

// import App from "./App";           // 旧版本（MinimalUI 全屏模式）
import App from "./AppNew";            // 新版本（顶部 Tab 导航）

const container = document.getElementById("root");

if (!container) {
  throw new Error("Unable to find root mount node.");
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <I18nProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </I18nProvider>
  </React.StrictMode>
);
