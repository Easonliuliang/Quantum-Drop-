import type { ErrorInfo, ReactNode } from "react";
import { Component } from "react";

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback?: ReactNode;
  renderFallback?: (args: { reset: () => void; error?: string }) => ReactNode;
  onReset?: () => void;
};

type ErrorBoundaryState = {
  hasError: boolean;
  message?: string;
};

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error.message,
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info);
  }

  private handleReset = () => {
    this.setState({ hasError: false, message: undefined }, () => {
      if (this.props.onReset) {
        this.props.onReset();
      }
    });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.renderFallback) {
        return this.props.renderFallback({
          reset: this.handleReset,
          error: this.state.message,
        });
      }
      if (this.props.fallback) {
        return this.props.fallback;
      }
      return (
        <div className="error-boundary" role="alert">
          <h2>界面渲染出现问题</h2>
          <p>{this.state.message ?? "请稍后重试或反馈给我们。"}</p>
          <button type="button" onClick={this.handleReset}>
            重新加载
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
