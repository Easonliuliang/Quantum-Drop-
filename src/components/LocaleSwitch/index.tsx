import { SUPPORTED_LOCALES, useI18n } from "../../lib/i18n";

export const LocaleSwitch = () => {
  const { locale, setLocale, t } = useI18n();
  return (
    <label className="locale-switch">
      <span>{t("locale.label", "界面语言")}</span>
      <select
        value={locale}
        onChange={(event) => setLocale(event.target.value)}
        aria-label={t("locale.label", "界面语言")}
      >
        {SUPPORTED_LOCALES.map((option) => (
          <option key={option.value} value={option.value}>
            {t(option.labelKey, option.fallback)}
          </option>
        ))}
      </select>
    </label>
  );
};
