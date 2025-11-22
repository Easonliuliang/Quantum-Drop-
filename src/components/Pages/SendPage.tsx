import { type ChangeEvent, type DragEvent, type KeyboardEvent, type RefObject } from "react";
import { useI18n } from "../../lib/i18n";
import { formatSize } from "../../lib/format";

type SendFile = {
  name: string;
  size?: number;
  path?: string;
};

interface SendPageProps {
  files: SendFile[];
  hovered: boolean;
  absorbing: boolean;
  onDrop: (event: DragEvent<HTMLDivElement>) => void;
  onDragOver: (event: DragEvent<HTMLDivElement>) => void;
  onDragLeave: (event: DragEvent<HTMLDivElement>) => void;
  onBrowse: () => void;
  onFileInputChange: (event: ChangeEvent<HTMLInputElement>) => void;
  fileInputRef: RefObject<HTMLInputElement>;
  showInlineStartButton: boolean;
  canStartTransfer: boolean;
  isSending: boolean;
  onStartTransfer: () => void;
}

export function SendPage({
  files,
  hovered,
  absorbing,
  onDrop,
  onDragOver,
  onDragLeave,
  onBrowse,
  onFileInputChange,
  fileInputRef,
  showInlineStartButton,
  canStartTransfer,
  isSending,
  onStartTransfer,
}: SendPageProps) {
  const { t } = useI18n();

  return (
    <div className="send-page">
      <div
        className={`${hovered ? "dropzone is-hovered" : "dropzone"} ${absorbing ? "is-absorbing" : ""}`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        role="button"
        tabIndex={0}
        onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onBrowse();
            return;
          }
        }}
        aria-label={t("dropzone.label", "拖拽或选择文件上传")}
      >
        <div className="rings">
          <span className="ring ring-outer" />
          <span className="ring ring-middle" />
          <span className="ring ring-inner" />
          <div className="quantum-core" />
          <div className="absorb-particles" aria-hidden="true">
            {Array.from({ length: 12 }).map((_, index) => (
              <span key={`particle-${index}`} className={`p p${index + 1}`} />
            ))}
          </div>
        </div>
        <div className="cta">
          <div className="cta-header">
            <h1>{t("app.title", "Quantum Drop · 量子快传")}</h1>
          </div>
          <p>{t("hero.tagline", "轻松拖拽，极速直达。")}</p>
          <button className="browse" onClick={onBrowse} type="button">
            {t("hero.selectFiles", "选择文件")}
          </button>
        </div>
        <input ref={fileInputRef} className="file-input" type="file" multiple onChange={onFileInputChange} />
      </div>
      {files.length > 0 && (
        <div className="file-panel" aria-live="polite">
          <h2>{t("filePanel.title", "已准备传输的文件")}</h2>
          <ul>
            {files.map((file) => (
              <li key={`${file.name}-${file.path ?? file.size ?? 0}`}>
                <span className="file-name">{file.name}</span>
                <span className="file-size">{file.size !== undefined ? formatSize(file.size) : file.path ?? ""}</span>
              </li>
            ))}
          </ul>
          {showInlineStartButton && (
            <div className="actions-row">
              <button
                className="primary"
                type="button"
                onClick={onStartTransfer}
                disabled={!canStartTransfer || isSending}
              >
                {isSending ? t("filePanel.starting", "启动中…") : t("filePanel.start", "启动传输")}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
