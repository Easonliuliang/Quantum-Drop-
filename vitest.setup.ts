import "@testing-library/jest-dom";

const noop = () => {};

if (typeof window !== "undefined") {
  if (typeof window.matchMedia !== "function") {
    window.matchMedia = (query: string): MediaQueryList => {
      return {
        media: query,
        matches: false,
        addListener: noop,
        removeListener: noop,
        addEventListener: noop,
        removeEventListener: noop,
        dispatchEvent: () => false,
        onchange: null,
      } as unknown as MediaQueryList;
    };
  }

  if (typeof (window as unknown as { ResizeObserver?: unknown }).ResizeObserver !== "function") {
    class ResizeObserver {
      constructor(_callback: ResizeObserverCallback) {}
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    (window as unknown as { ResizeObserver: unknown }).ResizeObserver = ResizeObserver;
  }
}

if (typeof HTMLCanvasElement !== "undefined") {
  const createContext = () => {
    let filter = "";
    let globalCompositeOperation = "source-over";
    let globalAlpha = 1;
    let fillStyle = "#000";
    return {
      clearRect: noop,
      save: noop,
      restore: noop,
      beginPath: noop,
      arc: noop,
      fill: noop,
      get filter() {
        return filter;
      },
      set filter(value: string) {
        filter = value;
      },
      get globalCompositeOperation() {
        return globalCompositeOperation;
      },
      set globalCompositeOperation(value: string) {
        globalCompositeOperation = value;
      },
      get globalAlpha() {
        return globalAlpha;
      },
      set globalAlpha(value: number) {
        globalAlpha = value;
      },
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string | CanvasGradient | CanvasPattern) {
        fillStyle = typeof value === "string" ? value : fillStyle;
      },
    } as unknown as CanvasRenderingContext2D;
  };

  Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
    configurable: true,
    value: (contextId: string) => {
      if (contextId === "2d") {
        return createContext();
      }
      if (contextId === "webgl2") {
        return {
          canvas: document.createElement("canvas"),
          getExtension: noop,
          getParameter: () => 1,
          createShader: noop,
          createProgram: noop,
          shaderSource: noop,
          compileShader: noop,
          attachShader: noop,
          linkProgram: noop,
          useProgram: noop,
        } as unknown as WebGL2RenderingContext;
      }
      return null;
    },
  });
}
