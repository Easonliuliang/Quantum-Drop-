# Payment Gateway (Demo)

轻量级支付回调示例，用于在收到微信/支付宝 Webhook 后签发 Quantum Drop License。

## 环境准备

```bash
cd server/payment-gateway
pnpm install # 或 npm install / yarn
cp .env.example .env
# 编辑 .env，填入 LICENSE_PRIVKEY (32 字节 Ed25519 种子) 与 WEBHOOK_HMAC_SECRET
pnpm dev
```

默认监听 `http://localhost:8787`。

## 接口

### `POST /webhook/wechat`

```json
{
  "identityId": "id_abc123",
  "tier": "PRO"
}
```

需在 Header 携带 `x-webhook-signature`（HMAC-SHA256）。成功后返回：

```json
{
  "license": {
    "key": "QD-PRO-ABCD-1234-5678",
    "tier": "PRO",
    "identityId": "id_abc123",
    "issuedAt": 1715057122,
    "expiresAt": 1746593122,
    "limits": {
      "maxFileSizeMb": null,
      "p2pMonthlyQuota": null,
      "maxDevices": null,
      "resumeEnabled": true,
      "historyDays": 90
    },
    "signature": "..."
  }
}
```

`/webhook/alipay` 同样逻辑。

### `POST /admin/issue`

测试/手动签发接口：

```json
{
  "identityId": "id_abc123",
  "tier": "ENTERPRISE",
  "validDays": 30
}
```

## 实际支付对接建议

1. 在支付平台后台配置 Webhook，指向 `/webhook/<provider>`。
2. 验签：本示例使用 `x-webhook-signature = HMAC(payload)`，可替换为微信/支付宝对应算法。
3. 记录 License：可扩展 `issueAndRespond` 将结果写入数据库/CRM，或调用外部邮件服务把 License 发送给用户。
4. Client 激活：用户在桌面端输入 License Key，或通过 API 自动写入（调用 `license_activate` Tauri 命令）。
