import { type FormEvent } from "react";
import { useI18n } from "../../lib/i18n";
import { formatRelativeTime } from "../../lib/format";

type IdentityInfo = {
  identityId: string;
  publicKey: string;
  label?: string | null;
};

type DeviceInfo = {
  deviceId: string;
  name?: string | null;
  status: string;
  lastSeenAt: number;
  capabilities: string[];
};

interface IdentityPageProps {
  identity: IdentityInfo | null;
  identityPrivateKeyAvailable: boolean;
  activeDeviceId: string | null;
  devices: DeviceInfo[];
  entitlement: { plan: string; features?: string[] } | null;
  isTauri: boolean;
  isRegisteringIdentity: boolean;
  isRegisteringDevice: boolean;
  isForgettingIdentity: boolean;
  isUpdatingEntitlement: boolean;
  importIdentityId: string;
  importPrivateKey: string;
  isImportingIdentity: boolean;
  selectedDevice: DeviceInfo | null;
  editDeviceName: string;
  editDeviceStatus: string;
  deviceStatusOptions: string[];
  isUpdatingDevice: boolean;
  onCopy: (label: string, value: string) => void;
  onRegisterIdentity: () => void;
  onRegisterDevice: () => void;
  onExportPrivateKey: () => void;
  onForgetIdentity: () => void;
  onSync: () => void;
  onTogglePlan: () => void;
  onImportIdentityIdChange: (value: string) => void;
  onImportPrivateKeyChange: (value: string) => void;
  onImportIdentity: (event: FormEvent<HTMLFormElement>) => void;
  onSelectDevice: (deviceId: string) => void;
  onEditDeviceNameChange: (value: string) => void;
  onEditDeviceStatusChange: (value: string) => void;
  onSubmitDeviceUpdate: () => void;
  onSetDeviceStandby: () => void;
  onMarkDeviceInactive: () => void;
}

export function IdentityPage({
  identity,
  identityPrivateKeyAvailable,
  activeDeviceId,
  devices,
  entitlement,
  isTauri,
  isRegisteringIdentity,
  isRegisteringDevice,
  isForgettingIdentity,
  isUpdatingEntitlement,
  importIdentityId,
  importPrivateKey,
  isImportingIdentity,
  selectedDevice,
  editDeviceName,
  editDeviceStatus,
  deviceStatusOptions,
  isUpdatingDevice,
  onCopy,
  onRegisterIdentity,
  onRegisterDevice,
  onExportPrivateKey,
  onForgetIdentity,
  onSync,
  onTogglePlan,
  onImportIdentityIdChange,
  onImportPrivateKeyChange,
  onImportIdentity,
  onSelectDevice,
  onEditDeviceNameChange,
  onEditDeviceStatusChange,
  onSubmitDeviceUpdate,
  onSetDeviceStandby,
  onMarkDeviceInactive,
}: IdentityPageProps) {
  const { t, locale } = useI18n();
  const planKey = entitlement?.plan?.toLowerCase() ?? "free";
  return (
    <div className="identity-page">
      <div className="identity-panel" aria-live="polite">
        <h3>{t("identity.heading", "Identity & Devices")}</h3>
        {identity ? (
          <div className="status-grid">
            <div>
              <span className="status-label">{t("identity.identityLabel", "Identity ID")}</span>
              <span className="status-value with-actions">
                <code>{identity.identityId}</code>
                <button
                  type="button"
                  className="copy-button"
                  onClick={() => onCopy(t("identity.identityLabel", "Identity ID"), identity.identityId)}
                >
                  {t("actions.copy", "Copy")}
                </button>
              </span>
            </div>
            <div>
              <span className="status-label">{t("identity.primaryKey", "Primary Public Key")}</span>
              <span className="status-value with-actions">
                <code>{identity.publicKey}</code>
                <button
                  type="button"
                  className="copy-button"
                  onClick={() => onCopy(t("identity.primaryKey", "Primary Public Key"), identity.publicKey)}
                >
                  {t("actions.copy", "Copy")}
                </button>
              </span>
            </div>
          </div>
        ) : (
          <p className="identity-empty">
            {t("identity.empty", "No identity yet. Click “Create Primary Identity” to generate one.")}
          </p>
        )}
        {identity && activeDeviceId && (
          <div className="active-device-banner">
            {t("identity.activeDevice", "Active device: {name}", {
              name: devices.find((device) => device.deviceId === activeDeviceId)?.name ?? activeDeviceId,
            })}
          </div>
        )}
        {!isTauri && <p className="identity-hint">{t("identity.browserHint", "Running in browser preview mode. Identity actions will guide you to desktop.")}</p>}
        <div className="actions-row identity-actions">
          <button type="button" className="secondary" onClick={onRegisterIdentity} disabled={isRegisteringIdentity}>
            {isRegisteringIdentity ? t("identity.actions.creating", "Creating…") : t("identity.actions.createPrimary", "Create Primary Identity")}
          </button>
          <button type="button" className="secondary" onClick={onRegisterDevice} disabled={!identity || isRegisteringDevice}>
            {isRegisteringDevice ? t("identity.actions.registering", "Registering…") : t("identity.actions.registerDevice", "Register New Device")}
          </button>
          <button type="button" className="plain" onClick={onExportPrivateKey} disabled={!identity || !identityPrivateKeyAvailable}>
            {t("identity.actions.export", "Export Private Key")}
          </button>
          <button type="button" className="plain" onClick={onForgetIdentity} disabled={!identity || isForgettingIdentity}>
            {isForgettingIdentity ? t("identity.actions.forgetting", "Removing…") : t("identity.actions.forget", "Forget Identity")}
          </button>
          <button type="button" className="plain" onClick={onSync} disabled={!identity}>
            {t("identity.actions.sync", "Resync")}
          </button>
          <button type="button" className="primary" onClick={onTogglePlan} disabled={!identity || isUpdatingEntitlement}>
            {isUpdatingEntitlement
              ? t("identity.actions.updating", "Updating…")
              : planKey === "pro"
              ? t("identity.actions.downgrade", "Downgrade to Free")
              : t("identity.actions.upgrade", "Upgrade to PRO")}
          </button>
        </div>
        <form className="identity-import" onSubmit={onImportIdentity}>
          <input
            type="text"
            placeholder={t("identity.import.idPlaceholder", "Identity ID")}
            value={importIdentityId}
            onChange={(event) => onImportIdentityIdChange(event.target.value)}
            autoComplete="off"
          />
          <input
            type="text"
            placeholder={t("identity.import.keyPlaceholder", "Private key (hex)")}
            value={importPrivateKey}
            onChange={(event) => onImportPrivateKeyChange(event.target.value)}
            autoComplete="off"
          />
          <button type="submit" className="secondary" disabled={isImportingIdentity}>
            {isImportingIdentity ? t("identity.import.submitting", "Importing…") : t("identity.import.submit", "Import Identity")}
          </button>
        </form>
        <div className="entitlement-panel">
          <span className="status-label">{t("identity.entitlement.label", "Current plan")}</span>
          <span className="status-value">
            {entitlement ? t(`identity.entitlement.plan.${planKey}`, entitlement.plan) : t("identity.entitlement.plan.free", "free")}
            {entitlement?.features?.length ? ` · ${entitlement.features.join(" · ")}` : ""}
          </span>
        </div>
        <div className="device-list" role="list">
          {identity ? (
            devices.length > 0 ? (
              devices.map((device) => (
                <div
                  key={device.deviceId}
                  className="device-item"
                  role="listitem"
                  data-active={device.deviceId === activeDeviceId}
                  onClick={() => onSelectDevice(device.deviceId)}
                >
                  <span className="device-name">{device.name ?? device.deviceId}</span>
                  <span className="device-meta">
                    <span className={`status-badge status-${device.status.toLowerCase()}`}>
                      {t(`identity.device.status.${device.status.toLowerCase()}`, device.status)}
                    </span>
                    <span className="device-meta-text">
                      {t("identity.devices.lastSeen", "Last heartbeat {time}", {
                        time: formatRelativeTime(device.lastSeenAt, locale),
                      })}
                    </span>
                    {device.capabilities.length > 0 && (
                      <span className="device-meta-text">
                        {t("identity.devices.capabilities", "Capabilities {list}", {
                          list: device.capabilities.join(locale.startsWith("zh") ? "，" : ", "),
                        })}
                      </span>
                    )}
                    {activeDeviceId === device.deviceId && (
                      <span className="device-active-flag">{t("identity.devices.activeFlag", "Current device")}</span>
                    )}
                  </span>
                </div>
              ))
            ) : (
              <p className="identity-empty">{t("identity.devices.empty", "No devices registered yet.")}</p>
            )
          ) : (
            <p className="identity-empty">{t("identity.devices.emptyNoIdentity", "Create an identity to see your devices here.")}</p>
          )}
        </div>
        {identity && selectedDevice && (
          <div className="device-editor" role="group" aria-label={t("identity.device.section", "Device settings")}>
            <div className="device-editor-grid">
              <label>
                <span>{t("identity.device.nameLabel", "Device name")}</span>
                <input
                  type="text"
                  value={editDeviceName}
                  onChange={(event) => onEditDeviceNameChange(event.target.value)}
                  placeholder={t("identity.device.namePlaceholder", "e.g. Workstation, Laptop")}
                />
              </label>
              <label>
                <span>{t("identity.device.statusLabel", "Device status")}</span>
                <select value={editDeviceStatus} onChange={(event) => onEditDeviceStatusChange(event.target.value)}>
                  {deviceStatusOptions.map((option) => (
                    <option key={option} value={option}>
                      {t(`identity.device.status.${option.toLowerCase()}`, option)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="device-editor-actions actions-row">
              <button type="button" className="secondary" onClick={onSubmitDeviceUpdate} disabled={isUpdatingDevice}>
                {isUpdatingDevice ? t("identity.device.saving", "Saving…") : t("identity.device.save", "Save Device")}
              </button>
              <button type="button" className="plain" onClick={onSetDeviceStandby} disabled={isUpdatingDevice || editDeviceStatus === "standby"}>
                {t("identity.device.setStandby", "Set Standby")}
              </button>
              <button type="button" className="plain" onClick={onMarkDeviceInactive} disabled={isUpdatingDevice || editDeviceStatus === "inactive"}>
                {t("identity.device.markInactive", "Mark Inactive")}
              </button>
            </div>
            <p className="device-editor-hint">
              {t(
                "identity.device.hint",
                "Updates are signed and submitted to auth_update_device. Keep names consistent to switch across devices easily.",
              )}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
