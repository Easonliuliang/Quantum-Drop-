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
      if (contextId === "webgl" || contextId === "webgl2") {
        return {
          canvas: document.createElement("canvas"),
          drawingBufferWidth: 1,
          drawingBufferHeight: 1,
          getExtension: () => null,
          getParameter: (pname: number) => {
            // WebGL string parameters
            if (pname === 0x1F00) return "Mock Vendor";        // VENDOR
            if (pname === 0x1F01) return "Mock Renderer";      // RENDERER
            if (pname === 0x1F02) return "WebGL 2.0 (Mock)";   // VERSION
            if (pname === 0x8B8C) return "WebGL GLSL ES 3.00"; // SHADING_LANGUAGE_VERSION
            return 1;
          },
          getShaderPrecisionFormat: () => ({ rangeMin: 127, rangeMax: 127, precision: 23 }),
          getContextAttributes: () => ({}),
          createShader: () => ({}),
          createProgram: () => ({}),
          createBuffer: () => ({}),
          createFramebuffer: () => ({}),
          createRenderbuffer: () => ({}),
          createTexture: () => ({}),
          shaderSource: noop,
          compileShader: noop,
          getShaderParameter: () => true,
          attachShader: noop,
          linkProgram: noop,
          getProgramParameter: () => true,
          useProgram: noop,
          getAttribLocation: () => 0,
          getUniformLocation: () => ({}),
          uniform1f: noop,
          uniform1i: noop,
          uniform2f: noop,
          uniform2fv: noop,
          uniform3f: noop,
          uniform3fv: noop,
          uniform4f: noop,
          uniform4fv: noop,
          uniformMatrix3fv: noop,
          uniformMatrix4fv: noop,
          vertexAttribPointer: noop,
          enableVertexAttribArray: noop,
          disableVertexAttribArray: noop,
          activeTexture: noop,
          bindTexture: noop,
          bindBuffer: noop,
          bindFramebuffer: noop,
          bindRenderbuffer: noop,
          bufferData: noop,
          texImage2D: noop,
          texParameteri: noop,
          framebufferTexture2D: noop,
          renderbufferStorage: noop,
          framebufferRenderbuffer: noop,
          checkFramebufferStatus: () => 0x8CD5, // FRAMEBUFFER_COMPLETE
          viewport: noop,
          scissor: noop,
          clear: noop,
          clearColor: noop,
          clearDepth: noop,
          clearStencil: noop,
          enable: noop,
          disable: noop,
          blendFunc: noop,
          blendFuncSeparate: noop,
          blendEquation: noop,
          blendEquationSeparate: noop,
          depthFunc: noop,
          depthMask: noop,
          stencilFunc: noop,
          stencilMask: noop,
          stencilOp: noop,
          colorMask: noop,
          cullFace: noop,
          frontFace: noop,
          lineWidth: noop,
          pixelStorei: noop,
          drawArrays: noop,
          drawElements: noop,
          deleteShader: noop,
          deleteProgram: noop,
          deleteBuffer: noop,
          deleteTexture: noop,
          deleteFramebuffer: noop,
          deleteRenderbuffer: noop,
          generateMipmap: noop,
          getError: () => 0,
          isContextLost: () => false,
        } as unknown as WebGL2RenderingContext;
      }
      return null;
    },
  });
}
