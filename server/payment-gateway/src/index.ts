import "dotenv/config";
import express, { type NextFunction, type Request, type Response } from "express";
import crypto from "crypto";

import { issueLicense, LicenseTier } from "./license";

const PORT = Number(process.env.PORT ?? 8787);
const WEBHOOK_SECRET = process.env.WEBHOOK_HMAC_SECRET ?? "demo-secret";
const LICENSE_PRIVKEY = process.env.LICENSE_PRIVKEY ?? "";

if (LICENSE_PRIVKEY.length !== 64) {
  console.warn("[payment-gateway] LICENSE_PRIVKEY 未配置或长度不符，无法签发 License。");
}

const app = express();
app.use(express.json({ limit: "1mb" }));

type WebhookPayload = {
  identityId?: string;
  tier?: LicenseTier;
  validDays?: number;
};

const getWebhookPayload = (req: Request): WebhookPayload => {
  if (req.body && typeof req.body === "object") {
    return req.body as WebhookPayload;
  }
  return {};
};

const verifyWebhook = (req: Request, res: Response, next: NextFunction) => {
  if (!WEBHOOK_SECRET) {
    return next();
  }
  const signature = req.header("x-webhook-signature") ?? "";
  const payload = JSON.stringify(req.body ?? {});
  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(payload)
    .digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(computed))) {
    return res.status(401).json({ error: "invalid webhook signature" });
  }
  next();
};

const issueAndRespond = (res: Response, identityId: string, tier: LicenseTier = "PRO", validDays = 365) => {
  if (!LICENSE_PRIVKEY) {
    return res.status(500).json({ error: "server missing LICENSE_PRIVKEY" });
  }
  try {
    const license = issueLicense({ identityId, tier, validDays }, LICENSE_PRIVKEY);
    res.json({ license });
  } catch (err) {
    console.error("issue license failed", err);
    res.status(500).json({ error: "issue_license_failed" });
  }
};

app.post("/webhook/wechat", verifyWebhook, (req, res) => {
  const { identityId, tier } = getWebhookPayload(req);
  if (!identityId) {
    return res.status(400).json({ error: "identityId required" });
  }
  issueAndRespond(res, identityId, tier ?? "PRO");
});

app.post("/webhook/alipay", verifyWebhook, (req, res) => {
  const { identityId, tier } = getWebhookPayload(req);
  if (!identityId) {
    return res.status(400).json({ error: "identityId required" });
  }
  issueAndRespond(res, identityId, tier ?? "PRO");
});

app.post("/admin/issue", (req, res) => {
  const { identityId, tier, validDays } = getWebhookPayload(req);
  if (!identityId) {
    return res.status(400).json({ error: "identityId required" });
  }
  issueAndRespond(res, identityId, tier ?? "PRO", validDays ?? 365);
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", version: "0.1.0" });
});

app.listen(PORT, () => {
  console.log(`[payment-gateway] listening on http://localhost:${PORT}`);
});
