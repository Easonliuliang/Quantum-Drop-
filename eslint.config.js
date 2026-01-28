import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import globals from "globals";
import prettierConfig from "eslint-config-prettier";

const sharedLanguageOptions = {
  ecmaVersion: "latest",
  sourceType: "module",
  globals: {
    ...globals.browser,
    ...globals.node
  }
};

const sharedReactRules = {
  ...reactPlugin.configs.recommended.rules,
  ...reactHooksPlugin.configs.recommended.rules,
  "react/react-in-jsx-scope": "off",
  "react/prop-types": "off"
};

export default [
  { ignores: ["dist", "node_modules", "src-tauri/**", "signaling-server/**", "signaling-server-cf/**"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx}"],
    languageOptions: sharedLanguageOptions,
    plugins: {
      react: reactPlugin,
      "react-hooks": reactHooksPlugin
    },
    settings: {
      react: {
        version: "detect"
      }
    },
    rules: {
      ...sharedReactRules,
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn"
    }
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ...sharedLanguageOptions,
      parser: tsParser,
      parserOptions: {
        project: ["./tsconfig.json", "./server/payment-gateway/tsconfig.json"],
        tsconfigRootDir: import.meta.dirname,
        ecmaFeatures: {
          jsx: true
        }
      }
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
      react: reactPlugin,
      "react-hooks": reactHooksPlugin
    },
    settings: {
      react: {
        version: "detect"
      }
    },
    rules: {
      ...sharedReactRules,
      ...tsPlugin.configs["recommended-type-checked"].rules,
      "no-undef": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", ignoreRestSiblings: true }
      ]
    }
  },
  {
    // three.js v0.182 ships without TS declarations, so `import * as THREE`
    // resolves to `any`. Disable type-checked rules for these visual-effect files.
    files: [
      "src/components/Hyperspeed/**/*.{ts,tsx}",
      "src/components/GridScan/**/*.{ts,tsx}",
      "src/components/ColorBends/**/*.{ts,tsx}"
    ],
    rules: {
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-redundant-type-constituents": "off",
      "@typescript-eslint/no-unnecessary-type-assertion": "off",
      "@typescript-eslint/unbound-method": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-misused-promises": "off",
      "@typescript-eslint/no-floating-promises": "off",
      "react-hooks/unsupported-syntax": "off"
    }
  },
  {
    files: ["**/*.{spec,test}.{ts,tsx}"],
    languageOptions: {
      ...sharedLanguageOptions,
      globals: {
        ...sharedLanguageOptions.globals,
        ...globals.vitest
      }
    }
  },
  prettierConfig
];
