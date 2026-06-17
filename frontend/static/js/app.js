let token = "";
let lastJobId = "";
let lastUsername = "";
let selectedReviewId = "";
let selectedReview = null;
let currentView = "login";

const $ = (id) => document.getElementById(id);
const apiBase = () => $("apiBase").value.replace(/\/$/, "");
const authHeaders = () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` });
const jsonHeaders = () => ({ "Content-Type": "application/json" });

const samples = {
  normal: {
    action: "run_openclaw",
    params: { mode: "safe", input_name: "request.json" },
    inputText: { sample: "hello openclaw", intent: "safe demo", file: "request.json" },
  },
  mask: {
    action: "analyze_file",
    params: { mode: "report", input_name: "request.json" },
    inputText: {
      sample: "credential scan",
      token: "AKIA1234567890ABCDEF",
      note: "触发敏感字段识别，系统会记录脱敏后的审计信息",
    },
  },
  privateKey: {
    action: "run_openclaw",
    params: { mode: "strict", input_name: "request.json" },
    inputText: "-----BEGIN PRIVATE KEY-----\nexample-secret-material\n-----END PRIVATE KEY-----",
  },
  dangerousCommand: {
    action: "run_openclaw",
    params: { mode: "safe", input_name: "request.json; rm -rf /" },
    inputText: { sample: "dangerous command parameter" },
  },
};

function renderJson(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}
function updateTaskDetailMirror(value) {
  const el = $("taskDetailResultMirror");
  if (!el) return;

  // 字符串错误
  if (typeof value === "string") {
    el.className = "summary-box fail";
    el.innerHTML = `<strong>错误</strong><p>${escapeHtml(value)}</p>`;
    return;
  }

  // 无数据
  if (!value || Object.keys(value).length === 0) {
    el.className = "summary-box";
    el.innerHTML = `<strong>空结果</strong><p>暂无数据。</p>`;
    return;
  }

  let title = "";
  let detail = "";
  let state = "ok";

  if (value.job_id) {
    // ── 任务详情（状态/日志/结果）──
    const status = value.status || "UNKNOWN";
    const action = value.action || "-";
    const exitCode = value.exit_code !== undefined && value.exit_code !== null ? `退出码 ${value.exit_code}` : "";
    const riskScore = value.risk_score !== undefined ? ` | 风险评分 ${value.risk_score}` : "";

    title = `任务 ${status}`;
    detail = `Job: ${value.job_id} | 动作: ${action}`;
    if (exitCode) detail += ` | ${exitCode}`;
    if (riskScore) detail += riskScore;

    if (status === "SUCCESS") state = "ok";
    else if (status === "FAILED" || status === "ERROR") state = "fail";
    else state = "warn";

    // 追加额外信息
    const extras = [];
    if (value.params) extras.push(`参数: ${JSON.stringify(value.params)}`);
    if (value.input_text) extras.push(`输入: ${String(value.input_text).substring(0, 100)}${String(value.input_text).length > 100 ? "…" : ""}`);
    if (value.error_message) extras.push(`错误: ${value.error_message}`);
    if (value.summary) extras.push(`摘要: ${value.summary}`);
    if (value.created_at) extras.push(`创建: ${formatTime(value.created_at)}`);
    if (value.finished_at) extras.push(`完成: ${formatTime(value.finished_at)}`);

    // 日志（截取前 200 字）
    if (value.logs) {
      const logText = String(value.logs).substring(0, 200);
      extras.push(`<details class="detail-expand"><summary>日志 (${String(value.logs).length} 字符)</summary><pre class="log-snippet">${escapeHtml(logText)}${String(value.logs).length > 200 ? "…" : ""}</pre></details>`);
    }
    // 执行结果（截取前 200 字）
    if (value.result && typeof value.result === "object") {
      extras.push(`结果: ${JSON.stringify(value.result).substring(0, 150)}`);
    } else if (value.result && typeof value.result === "string") {
      extras.push(`<details class="detail-expand"><summary>执行结果</summary><pre class="log-snippet">${escapeHtml(value.result.substring(0, 500))}</pre></details>`);
    }

    detail += `<div class="mirror-extras small-text">${extras.join("<br>")}</div>`;

  } else if (value.review_id) {
    // ── 审核相关（捕获/审批/否决/修改）──
    const filterDecision = value.filter_decision || "-";
    const recommendation = value.recommendation || "-";
    const status = value.status || "PENDING";
    const action = value.action || "-";

    if (status === "APPROVED" && value.job_id) {
      title = `✅ 已同意 — 任务已生成`;
      detail = `Review: ${value.review_id} | Job: ${value.job_id}`;
      state = "ok";
    } else if (status === "REJECTED") {
      title = `❌ 已否决`;
      detail = `Review: ${value.review_id}`;
      state = "fail";
    } else if (status === "APPROVED") {
      title = `✅ 已同意（待执行）`;
      detail = `Review: ${value.review_id}`;
      state = "ok";
    } else {
      title = `⏳ 待审核 — ${recommendation}`;
      detail = `Review: ${value.review_id} | 动作: ${action} | 过滤: ${filterDecision}`;
      state = recommendation === "reject" ? "fail" : recommendation === "modify" ? "warn" : "neutral";
    }

    const extras = [];
    if (value.params) extras.push(`参数: ${JSON.stringify(value.params).substring(0, 100)}`);
    if (value.input_text) extras.push(`输入: ${String(value.input_text).substring(0, 100)}${String(value.input_text).length > 100 ? "…" : ""}`);
    if (value.note) extras.push(`备注: ${value.note}`);
    if (value.created_at) extras.push(`时间: ${formatTime(value.created_at)}`);

    // 分析结果
    const analysis = value.analysis || {};
    if (analysis.risk_level) extras.push(`风险等级: ${analysis.risk_level}`);
    if (analysis.reasons && analysis.reasons.length) {
      extras.push(`<div class="mirror-reasons">拦截原因:<ul>${analysis.reasons.map(r => `<li>⚠️ ${escapeHtml(r)}</li>`).join("")}</ul></div>`);
    }
    if (analysis.filter_result && analysis.filter_result.findings && analysis.filter_result.findings.length) {
      extras.push(`<div class="mirror-reasons">匹配规则:<ul>${analysis.filter_result.findings.slice(0, 5).map(f => `<li>${f.level === "high" ? "🔴" : "🟡"} [${escapeHtml(f.level)}] ${escapeHtml((f.rule || "").substring(0, 60))}</li>`).join("")}</ul></div>`);
    }

    detail += `<div class="mirror-extras small-text">${extras.join("<br>")}</div>`;

  } else {
    // ── 其他对象 ├──
    el.className = "summary-box neutral";
    const entries = Object.entries(value).slice(0, 8);
    const lines = entries.map(([k, v]) => {
      const label = k.replace(/_/g, " ");
      const val = typeof v === "object" ? JSON.stringify(v).substring(0, 80) : String(v).substring(0, 80);
      return `<span class="mirror-line"><strong>${escapeHtml(label)}</strong>: ${escapeHtml(val)}</span>`;
    }).join("<br>");
    el.innerHTML = `<strong>响应摘要</strong><div class="mirror-extras small-text">${lines}</div>`;
    return;
  }

  el.className = `summary-box ${state}`.trim();
  el.innerHTML = `<strong>${escapeHtml(title)}</strong><div class="mirror-detailed">${detail}</div>`;
}

function formatTime(value) {
  if (!value) return "未记录时间";
  const raw = String(value);
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
  const date = new Date(hasTimezone ? raw : `${raw}Z`);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function setView(viewName) {
  if (viewName !== "login" && !token) {
    viewName = "login";
    setSummary("loginSummary", "请先登录", "完成身份认证后才能进入后续操作界面。", "warn");
  }
  currentView = viewName;
  document.querySelectorAll(".app-view").forEach((view) => {
    view.classList.toggle("active", view.id === `view-${viewName}`);
  });
  document.querySelectorAll(".workflow-step").forEach((step) => {
    step.classList.toggle("active", step.dataset.view === viewName);
    step.classList.toggle("locked", step.dataset.view !== "login" && !token);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle("sidebar-collapsed", collapsed);
  const toggle = $("sidebarToggle");
  if (!toggle) return;
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.setAttribute("aria-label", collapsed ? "展开侧边栏" : "收起侧边栏");
  toggle.textContent = collapsed ? "›" : "‹";
}

function toggleSidebar() {
  const collapsed = !document.body.classList.contains("sidebar-collapsed");
  setSidebarCollapsed(collapsed);
  localStorage.setItem("clawguard.sidebarCollapsed", collapsed ? "1" : "0");
}

async function openView(viewName) {
  setView(viewName);
  if (currentView === "review" && token) {
    try {
      await loadReviewQueue();
    } catch (error) {
      setSummary("reviewDecisionSummary", "队列刷新失败", error.message, "fail");
    }
  }
  if (currentView === "security" && token && $("analyticsBtn")) {
    try {
      await loadAnalytics();
    } catch (error) {
      $("analyticsSummary").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }
}

function setPill(id, text, state = "muted") {
  const el = $(id);
  el.textContent = text;
  el.className = `status-pill ${state}`;
}

function setCard(id, title, detail, state = "") {
  const card = $(id);
  card.className = `status-card ${state}`.trim();
  card.querySelector("strong").textContent = title;
  card.querySelector("small").textContent = detail;
}

function setSummary(id, title, detail, state = "") {
  const el = $(id);
  if (!el) return;
  el.className = `summary-box ${state}`.trim();
  el.innerHTML = `<strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function request(path, options = {}) {
  const response = await fetch(`${apiBase()}${path}`, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json().catch(() => ({})) : await response.text();
  if (!response.ok) {
    const detail = typeof body === "object" ? body.detail || body.message : body;
    throw new Error(detail || response.statusText || `HTTP ${response.status}`);
  }
  return body;
}

function parseParams() {
  try {
    return JSON.parse($("params").value);
  } catch (error) {
    throw new Error(`运行参数不是合法 JSON：${error.message}`);
  }
}

function parseReviewParams() {
  try {
    return JSON.parse($("reviewParams").value || "{}");
  } catch (error) {
    throw new Error(`审核修改参数不是合法 JSON：${error.message}`);
  }
}

function getInputText() {
  const value = $("inputText").value.trim();
  if (!value) return "";
  try {
    return JSON.stringify(JSON.parse(value));
  } catch {
    return value;
  }
}

function getReviewInputText() {
  const value = $("reviewInputText").value.trim();
  if (!value) return "";
  try {
    return JSON.stringify(JSON.parse(value));
  } catch {
    return value;
  }
}

function requireLogin() {
  if (!token) throw new Error("请先登录，再执行这个操作。");
}

function activateSample(name) {
  const sample = samples[name];
  if (!sample) return;
  document.querySelectorAll(".sample-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.sample === name);
  });
  $("action").value = sample.action;
  $("params").value = JSON.stringify(sample.params, null, 2);
  $("inputText").value = typeof sample.inputText === "string" ? sample.inputText : JSON.stringify(sample.inputText, null, 2);
  setPill("filterBadge", "样例已载入", "neutral");
  setSummary("taskSubmitSummary", "样例已载入", "低风险会自动通过，有风险会自动拦截进入审核队列。", "warn");
}

function summarizeTaskResult(body) {
  const status = body.status || "UNKNOWN";
  const ok = status === "SUCCESS" || status === "RUNNING" || body.message;
  setCard("taskCard", status, body.job_id ? `Job ID：${body.job_id}` : "任务已返回响应", ok ? "ok" : "warn");
  setSummary(
    "taskSubmitSummary",
    status === "RUNNING" ? "任务已提交" : "提交完成",
    body.job_id ? `系统已创建任务 ${body.job_id}，可以继续查看状态、日志和结果。` : body.message || "任务接口已响应。",
    "ok",
  );
}

function summarizeReview(body) {
  selectedReviewId = body.review_id;
  selectedReview = body;
  $("reviewId").value = body.review_id;
  $("action").value = body.action;
  $("params").value = JSON.stringify(body.params || {}, null, 2);
  $("inputText").value = body.input_text || "";
  if ($("reviewAction")) $("reviewAction").value = body.action;
  if ($("reviewParams")) $("reviewParams").value = JSON.stringify(body.params || {}, null, 2);
  if ($("reviewInputText")) $("reviewInputText").value = body.input_text || "";
  const recommendationText = {
    approve: "建议同意",
    modify: "建议修改",
    reject: "建议否决",
  }[body.recommendation] || body.recommendation;
  const autoApproved = body.status === "APPROVED" && body.job_id;
  const state = autoApproved || body.recommendation === "approve" ? "ok" : body.recommendation === "modify" ? "warn" : "fail";
  const reasons = (body.analysis?.reasons || []).join("；");
  const capturedAt = `捕获时间：${formatTime(body.created_at)}`;
  if (autoApproved) {
    setPill("filterBadge", "自动通过", "ok");
    setCard("taskCard", "自动放行", body.job_id ? `Job ID：${body.job_id}` : body.review_id, "ok");
    setSummary("taskSubmitSummary", "低风险自动通过", `${capturedAt}。${reasons} 已进入沙箱执行。`, "ok");
    setSummary("taskDetailSummary", "自动通过", `${capturedAt}。任务已生成，可以查看状态、日志和结果。`, "ok");
    return;
  }
  setPill("filterBadge", recommendationText, state);
  setCard("taskCard", "已拦截待审核", `${recommendationText}：${body.review_id}`, state);
  setSummary("taskSubmitSummary", "有风险，已拦截待审核", `${capturedAt}。${recommendationText}。${reasons}`, state);
  setSummary("reviewDecisionSummary", "待审核请求已选中", `${capturedAt}。${recommendationText}。${reasons}`, state);
}

function statusLabel(item) {
  if (item.status === "APPROVED" && item.job_id) return "自动通过";
  if (item.status === "APPROVED") return "已同意";
  if (item.status === "REJECTED") return "已否决";
  if (item.recommendation === "modify") return "待修改";
  if (item.recommendation === "reject") return "待审核";
  return "待审核";
}

function statusState(item) {
  if (item.status === "APPROVED") return "ok";
  if (item.status === "REJECTED" || item.recommendation === "reject") return "fail";
  if (item.recommendation === "modify") return "warn";
  return "neutral";
}

function renderReviewQueue(items) {
  if (!items.length) {
    $("reviewQueue").innerHTML = '<div class="empty-state">暂无待审核任务。捕获 OpenClaw 请求后会显示在这里。</div>';
    return;
  }
  $("reviewQueue").innerHTML = items
    .map((item) => {
      const state = statusState(item);
      const active = item.review_id === selectedReviewId ? " active" : "";
      const label = item.recommendation === "approve" ? "建议同意" : item.recommendation === "modify" ? "建议修改" : "建议否决";
      return `<button class="review-item${active}" data-review-id="${escapeHtml(item.review_id)}" type="button">
        <span class="status-pill ${state}">${escapeHtml(label)}</span>
        <strong>${escapeHtml(item.action)}</strong>
        <small>${escapeHtml(item.review_id)}<br />捕获：${escapeHtml(formatTime(item.created_at))}<br />过滤：${escapeHtml(item.filter_decision)}</small>
      </button>`;
    })
    .join("");
  document.querySelectorAll(".review-item").forEach((button) => {
    button.addEventListener("click", () => {
      const item = items.find((entry) => entry.review_id === button.dataset.reviewId);
      if (item) {
        summarizeReview(item);
        updateTaskDetailMirror(item);
        renderReviewQueue(items);
        openDecisionPanel();
      }
    });
  });
}

function openDecisionPanel() {
  const panel = $("reviewDecisionPanel");
  const backdrop = $("reviewDecisionBackdrop");
  if (panel) panel.classList.add("active");
  if (backdrop) backdrop.classList.add("active");
  const queue = document.querySelector(".review-queue-panel");
  if (queue) queue.classList.add("has-decision");
}

function closeDecisionPanel() {
  const panel = $("reviewDecisionPanel");
  const backdrop = $("reviewDecisionBackdrop");
  if (panel) panel.classList.remove("active");
  if (backdrop) backdrop.classList.remove("active");
  const queue = document.querySelector(".review-queue-panel");
  if (queue) queue.classList.remove("has-decision");
}

function renderCaptureRecords(items) {
  const target = $("captureRecords");
  if (!target) return;
  if (!items.length) {
    target.innerHTML = '<div class="empty-state">暂无捕获记录。每次捕获都会在这里留下时间和处理结果。</div>';
    return;
  }
  target.innerHTML = items
    .slice(0, 8)
    .map((item) => {
      const state = statusState(item);
      return `<button class="review-item" data-review-id="${escapeHtml(item.review_id)}" type="button">
        <span class="status-pill ${state}">${escapeHtml(statusLabel(item))}</span>
        <strong>${escapeHtml(item.action)}</strong>
        <small>捕获：${escapeHtml(formatTime(item.created_at))}<br />过滤：${escapeHtml(item.filter_decision)}${item.job_id ? `<br />任务：${escapeHtml(item.job_id)}` : ""}</small>
      </button>`;
    })
    .join("");
}

function summarizeTaskStatus(body) {
  const state = body.status === "SUCCESS" ? "ok" : body.status === "FAILED" ? "fail" : "warn";
  setCard("taskCard", body.status || "任务状态", body.job_id || "已读取任务状态", state);
  const detail = body.error_message
    ? `任务执行结束，但返回提示：${body.error_message}`
    : `动作 ${body.action || "未知"}，退出码 ${body.exit_code ?? "未返回"}。`;
  setSummary("taskDetailSummary", `任务状态：${body.status || "UNKNOWN"}`, detail, state);
}

function summarizeLogs(body) {
  const text = typeof body === "string" ? body : body.logs || renderJson(body);
  setSummary("taskDetailSummary", "任务日志已读取", text.trim() ? "日志可用于查看沙箱执行过程和排查失败原因。" : "当前没有可展示的日志。", "ok");
}

function summarizeResult(body) {
  const risk = body.risk_score ?? body.risk ?? "未标注";
  const engine = body.engine || body.action || "OpenClaw 沙箱";
  const summary = body.summary || body.message || "沙箱结果已生成。";
  setSummary("taskDetailSummary", "结果已生成", `${engine} 返回：${summary} 风险评分：${risk}。`, "ok");
  setCard("taskCard", "结果可读", `风险评分：${risk}`, "ok");
}

function summarizeCflStatus(body) {
  const mode = body.mode || "unknown";
  const helper = body.using_helper ? "x86 helper 已启用" : "本进程直连 DLL";
  const loadable = body.loadable ?? body.dll_loadable;
  const dll = loadable === false ? "DLL 不可加载" : "DLL 可加载";
  const state = body.mode === "real" && loadable !== false ? "ok" : body.mode === "mock" ? "warn" : "fail";
  setPill("cflModeBadge", mode === "real" ? "真实 CFL" : "模拟 CFL", state);
  setCard("cflCard", mode === "real" ? "真实模式" : "模拟模式", `${dll}，${helper}`, state);
  setSummary("cflSummary", "CFL 状态已读取", `当前运行在 ${mode} 模式，${dll}，${helper}。`, state);
}

function summarizeCflDiag(body) {
  const connectHex = body.connect_hex || body.connect_code || "未返回";
  const exportHex = body.sign_export_hex || body.sign_export_code || "未返回";
  const signAllZero = [body.sign_x, body.sign_y].some((value) => typeof value === "string" && /^0+$/.test(value));
  const encAllZero = [body.enc_x, body.enc_y].some((value) => typeof value === "string" && /^0+$/.test(value));
  const allZero = body.sign_public_key_all_zero || body.encrypt_public_key_all_zero || signAllZero || encAllZero;
  const hasErrorCode = Boolean(body.connect_code || body.sign_export_code || body.enc_export_code);
  const state = allZero || hasErrorCode || body.connect_ok === false ? "warn" : "ok";
  const detail = allZero
    ? `已到达真实 DLL，但公钥返回全 0。连接码 ${connectHex}，导出码 ${exportHex}，需要继续检查 UKey 应用或容器初始化。`
    : `连接码 ${connectHex}，导出码 ${exportHex}，诊断未发现全 0 公钥。`;
  setCard("cflCard", state === "ok" ? "CFL 可用" : "CFL 需复核", detail, state);
  setSummary("cflSummary", "CFL 诊断完成", detail, state);
}

function renderAudit(body) {
  const items = body.items || body.audit || body.logs || [];
  const list = Array.isArray(items) ? items : [];
  if (!list.length) {
    $("auditSummary").innerHTML = '<div class="empty-state">没有匹配的审计记录。</div>';
    return;
  }
  $("auditSummary").innerHTML = list
    .map((item) => {
      const state = item.risk_level === "high" ? "fail" : item.risk_level === "medium" ? "warn" : "ok";
      const job = item.job_id ? `任务：${item.job_id}` : "系统事件";
      return `<article class="audit-item">
        <span class="status-pill ${state}">${escapeHtml(item.risk_level || "info")}</span>
        <strong>${escapeHtml(item.event_type || "AUDIT")}</strong>
        <p>${escapeHtml(item.message || item.result || "已记录事件")}<br />${escapeHtml(job)}</p>
      </article>`;
    })
    .join("");
}

function parseRecordTime(value) {
  if (!value) return null;
  const raw = String(value);
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
  const date = new Date(hasTimezone ? raw : `${raw}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function beijingDateParts(date) {
  const parts = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  return Object.fromEntries(parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
}

function beijingDateLabel(date) {
  const parts = beijingDateParts(date);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function periodBucket(date, period) {
  const parts = beijingDateParts(date);
  if (period === "month") {
    return { label: `${parts.year}-${parts.month}`, sort: Number(`${parts.year}${parts.month}00`) };
  }
  if (period === "week") {
    const weekday = new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Shanghai", weekday: "short" }).format(date);
    const weekdayIndex = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[weekday] ?? 1;
    const mondayOffset = (weekdayIndex + 6) % 7;
    const midnight = new Date(`${parts.year}-${parts.month}-${parts.day}T00:00:00+08:00`);
    const start = new Date(midnight.getTime() - mondayOffset * 86400000);
    const end = new Date(start.getTime() + 6 * 86400000);
    return { label: `${beijingDateLabel(start)} ~ ${beijingDateLabel(end)}`, sort: start.getTime() };
  }
  return { label: `${parts.year}-${parts.month}-${parts.day}`, sort: Number(`${parts.year}${parts.month}${parts.day}`) };
}

function reviewRisk(item) {
  const analysis = item.analysis || {};
  return (analysis.risk_level || item.risk_level || "low").toLowerCase();
}

function reviewIsAttack(item) {
  const decision = String(item.filter_decision || "").toUpperCase();
  const recommendation = String(item.recommendation || item.analysis?.recommendation || "").toLowerCase();
  const risk = reviewRisk(item);
  return decision === "DENY" || decision === "MASK" || risk === "high" || risk === "medium" || recommendation === "reject" || recommendation === "modify";
}

function matchesAnalyticsFilter(item, source, riskFilter) {
  const isAttack = reviewIsAttack(item);
  const risk = reviewRisk(item);
  if (source === "attack" && !isAttack) return false;
  if (source === "capture" && isAttack) return false;
  if (riskFilter && risk !== riskFilter) return false;
  return true;
}

function renderLineChart(rows) {
  const width = 820;
  const height = 300;
  const pad = { left: 48, right: 28, top: 28, bottom: 46 };
  const max = Math.max(...rows.map((row) => row.count), 1);
  const xSpan = Math.max(rows.length - 1, 1);
  const points = rows.map((row, index) => {
    const x = pad.left + (index / xSpan) * (width - pad.left - pad.right);
    const y = pad.top + (1 - row.count / max) * (height - pad.top - pad.bottom);
    return { ...row, x, y };
  });
  const polyline = points.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  const area = `${pad.left},${height - pad.bottom} ${polyline} ${width - pad.right},${height - pad.bottom}`;
  const labelEvery = Math.max(1, Math.ceil(rows.length / 6));
  const labels = points
    .filter((_, index) => index % labelEvery === 0 || index === points.length - 1)
    .map((point) => `<text class="analytics-line-label" x="${point.x.toFixed(1)}" y="${height - 16}" text-anchor="middle">${escapeHtml(point.label)}</text>`)
    .join("");
  const circles = points
    .map((point) => `<g>
      <circle class="analytics-line-dot" cx="${point.x.toFixed(1)}" cy="${point.y.toFixed(1)}" r="4.5"></circle>
      <text class="analytics-line-value" x="${point.x.toFixed(1)}" y="${(point.y - 10).toFixed(1)}" text-anchor="middle">${point.count}</text>
    </g>`)
    .join("");
  const gridLines = [0, 0.25, 0.5, 0.75, 1]
    .map((ratio) => {
      const y = pad.top + ratio * (height - pad.top - pad.bottom);
      const value = Math.round(max * (1 - ratio));
      return `<line class="analytics-grid-line" x1="${pad.left}" y1="${y.toFixed(1)}" x2="${width - pad.right}" y2="${y.toFixed(1)}"></line>
        <text class="analytics-y-label" x="${pad.left - 10}" y="${(y + 4).toFixed(1)}" text-anchor="end">${value}</text>`;
    })
    .join("");
  return `<svg class="analytics-line-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="历史事件折线图">
    <defs>
      <linearGradient id="trendLineGradient" x1="0" x2="1" y1="0" y2="0">
        <stop offset="0%" stop-color="#d94444"></stop>
        <stop offset="100%" stop-color="#d48a3a"></stop>
      </linearGradient>
      <linearGradient id="trendAreaGradient" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0%" stop-color="#d94444" stop-opacity="0.28"></stop>
        <stop offset="100%" stop-color="#d48a3a" stop-opacity="0.02"></stop>
      </linearGradient>
    </defs>
    ${gridLines}
    <polygon class="analytics-line-area" points="${area}"></polygon>
    <polyline class="analytics-line-path" points="${polyline}"></polyline>
    ${circles}
    ${labels}
  </svg>`;
}

function stageStats(items) {
  return items.reduce(
    (acc, item) => {
      acc.captured += 1;
      const decision = String(item.filter_decision || "").toUpperCase();
      const status = String(item.status || "").toUpperCase();
      const recommendation = String(item.recommendation || item.analysis?.recommendation || "").toLowerCase();
      if (decision === "DENY" || recommendation === "reject") acc.blocked += 1;
      if (status === "PENDING") acc.pending += 1;
      if (status === "APPROVED") acc.approved += 1;
      if (item.job_id) acc.executed += 1;
      if (status === "REJECTED") acc.rejected += 1;
      return acc;
    },
    { captured: 0, blocked: 0, pending: 0, approved: 0, executed: 0, rejected: 0 },
  );
}

function renderAnalytics(items, period, source, riskFilter, audits = []) {
  const filtered = items.filter((item) => matchesAnalyticsFilter(item, source, riskFilter));
  const stats = filtered.reduce(
    (acc, item) => {
      const risk = reviewRisk(item);
      const isAttack = reviewIsAttack(item);
      acc.total += 1;
      if (isAttack) acc.attack += 1;
      else acc.capture += 1;
      acc.risk[risk] = (acc.risk[risk] || 0) + 1;
      return acc;
    },
    { total: 0, attack: 0, capture: 0, risk: { high: 0, medium: 0, low: 0 } },
  );

  $("analyticsSummary").innerHTML = `
    <div class="analytics-stat"><span>总记录数</span><strong>${stats.total}</strong></div>
    <div class="analytics-stat"><span>自动捕获</span><strong>${stats.capture}</strong></div>
    <div class="analytics-stat"><span>攻击拦截</span><strong>${stats.attack}</strong></div>
    <div class="analytics-stat"><span>审计事件</span><strong>${audits.length}</strong></div>
  `;

  const buckets = new Map();
  filtered.forEach((item) => {
    const date = parseRecordTime(item.created_at);
    if (!date) return;
    const bucket = periodBucket(date, period);
    const current = buckets.get(bucket.label) || { label: bucket.label, sort: bucket.sort, count: 0 };
    current.count += 1;
    buckets.set(bucket.label, current);
  });
  const rows = [...buckets.values()].sort((a, b) => a.sort - b.sort);
  if (!rows.length) {
    $("analyticsChart").innerHTML = '<div class="empty-state">当前筛选条件下没有可统计的数据。</div>';
    $("analyticsPie").innerHTML = '<div class="empty-state">当前筛选条件下没有风险分布数据。</div>';
    $("analyticsStage").innerHTML = '<div class="empty-state">当前筛选条件下没有阶段数据。</div>';
    setPill("analyticsTrendBadge", "暂无数据", "muted");
    return;
  }
  setPill("analyticsTrendBadge", `${rows.length} 个时间段`, "ok");
  $("analyticsChart").innerHTML = renderLineChart(rows);

  const totalRisk = Math.max(stats.risk.high + stats.risk.medium + stats.risk.low, 1);
  const highDeg = Math.round((stats.risk.high / totalRisk) * 360);
  const mediumDeg = Math.round((stats.risk.medium / totalRisk) * 360);
  $("analyticsPie").innerHTML = `
    <div class="analytics-pie" style="--high:${highDeg}deg;--medium:${mediumDeg}deg">
      <div class="analytics-pie-center"><strong>${stats.total}</strong><span>历史记录</span></div>
    </div>
    <div class="analytics-legend">
      <div class="analytics-legend-item"><span class="legend-dot high"></span><span>高危</span><strong>${stats.risk.high || 0}</strong></div>
      <div class="analytics-legend-item"><span class="legend-dot medium"></span><span>中危</span><strong>${stats.risk.medium || 0}</strong></div>
      <div class="analytics-legend-item"><span class="legend-dot low"></span><span>低危</span><strong>${stats.risk.low || 0}</strong></div>
    </div>
  `;

  const stages = stageStats(filtered);
  const stageRows = [
    ["捕获进入", stages.captured],
    ["自动拦截", stages.blocked],
    ["等待审核", stages.pending],
    ["审核通过", stages.approved],
    ["沙箱执行", stages.executed],
    ["人工否决", stages.rejected],
  ];
  const maxStage = Math.max(...stageRows.map((entry) => entry[1]), 1);
  $("analyticsStage").innerHTML = stageRows
    .map(([label, count]) => {
      const width = Math.max(4, Math.round((count / maxStage) * 100));
      return `<div class="stage-row">
        <span class="stage-label">${escapeHtml(label)}</span>
        <div class="stage-track"><div class="stage-fill" style="width:${width}%"></div></div>
        <span class="stage-value">${count}</span>
      </div>`;
    })
    .join("");
}

async function loadAnalytics() {
  requireLogin();
  const period = $("analyticsPeriod").value;
  const source = $("analyticsSource").value;
  const risk = $("analyticsRisk").value;
  const [reviews, audits] = await Promise.all([
    request("/api/reviews?status=ALL", { headers: authHeaders() }),
    request("/api/audit", { headers: authHeaders() }).catch(() => ({ items: [] })),
  ]);
  renderAnalytics(reviews.items || [], period, source, risk, audits.items || []);
}

async function healthCheck() {
  try {
    const body = await request("/api/health");
    setCard("backendCard", "连接正常", body.status || "后端 API 可访问", "ok");
    setPill("navApiBadge", `API ${apiBase().replace(/^https?:\/\//, "")}`, "ok");
    setSummary("loginSummary", "后端连接正常", "可以继续登录并提交沙箱任务。", "ok");
  } catch (error) {
    setCard("backendCard", "连接失败", error.message, "fail");
    setPill("navApiBadge", "API 不可用", "fail");
    setSummary("loginSummary", "后端连接失败", error.message, "fail");
  }
}

async function login(username, password) {
  const body = await request("/api/auth/login", {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ username, password }),
  });
  token = body.access_token;
  lastUsername = username;
  setPill("navLoginBadge", `${username} / ${body.role}`, "ok");
  setCard("loginCard", "已登录", `${username}，角色 ${body.role}`, "ok");
  setSummary("loginSummary", "登录成功", "即将进入 OpenClaw 捕获界面。", "ok");
  // Show agent config panel
  setCard("agentCard", "就绪", "已登录，可配置 Agent 或运行模拟测试", "ok");
  refreshAgentStatus();
  setView("agent");
  return body;
}

async function refreshAgentStatus() {
  try {
    const body = await request("/api/agents/status", { headers: authHeaders() });
    const agents = body.agents || [];
    const count = agents.length;
    $("agentSummary").innerHTML =
      `<strong>Agent 状态</strong><p>已注册 ${count} 个 Agent${count ? "：" + agents.map(a => a.name + "@" + (a.address || "local")).join(", ") : ""} | 内置模拟可用: ${body.local_stub_available ? "✅" : "❌"} | 攻击模板: ${body.demo_attacks_count} 种</p>`;
    setCard("agentCard", count > 0 ? `${count} 个 Agent 在线` : "本地模式", count > 0 ? agents.map(a => a.name).join(", ") : "未注册远程 Agent，使用本地模拟", count > 0 ? "ok" : "warn");
    setPill("agentStatusBadge", count > 0 ? "已连接" : "未连接", count > 0 ? "ok" : "muted");
  } catch (error) {
    $("agentSummary").innerHTML = `<strong>Agent 状态</strong><p>${escapeHtml(error.message)}</p>`;
  }
}

async function submitTask() {
  requireLogin();
  const params = parseParams();
  const body = await request("/api/tasks", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ action: $("action").value, params, input_text: getInputText() }),
  });
  lastJobId = body.job_id;
  $("jobId").value = body.job_id;
  setPill("filterBadge", "已通过", "ok");
  summarizeTaskResult(body);
}

async function captureTask() {
  requireLogin();
  const params = parseParams();
  const body = await request("/api/reviews/capture", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ action: $("action").value, params, input_text: getInputText(), source: "openclaw_web" }),
  });
  summarizeReview(body);
  if (body.job_id) {
    lastJobId = body.job_id;
    $("jobId").value = body.job_id;
    updateTaskDetailMirror(body);
    try {
      await loadTask("/result", "result");
    } catch {
      updateTaskDetailMirror(body);
    }
  }
  await loadReviewQueue();
  await loadCaptureRecords();
  setView(body.status === "APPROVED" && body.job_id ? "result" : "review");
}

async function loadReviewQueue() {
  requireLogin();
  const body = await request("/api/reviews?status=PENDING", { headers: authHeaders() });
  renderReviewQueue(body.items || []);
  return body;
}

async function loadCaptureRecords() {
  requireLogin();
  const body = await request("/api/reviews?status=ALL", { headers: authHeaders() });
  renderCaptureRecords(body.items || []);
  return body;
}

async function approveReview() {
  requireLogin();
  const reviewId = $("reviewId").value || selectedReviewId;
  if (!reviewId) throw new Error("请先选择一条待审核任务。");
  const body = await request(`/api/reviews/${reviewId}/approve`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ note: $("reviewNote").value || undefined }),
  });
  selectedReview = body;
  selectedReviewId = body.review_id;
  if (body.job_id) {
    lastJobId = body.job_id;
    $("jobId").value = body.job_id;
  }
  setPill("filterBadge", "已同意", "ok");
  setCard("taskCard", "已放行执行", body.job_id ? `Job ID：${body.job_id}` : body.review_id, "ok");
  setSummary("taskDetailSummary", "审核通过", "任务已进入 Docker 沙箱执行，可以查看状态、日志和结果。", "ok");
  updateTaskDetailMirror(body);
  await loadReviewQueue();
  setView("result");
}

async function rejectReview() {
  requireLogin();
  const reviewId = $("reviewId").value || selectedReviewId;
  if (!reviewId) throw new Error("请先选择一条待审核任务。");
  const body = await request(`/api/reviews/${reviewId}/reject`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ note: $("reviewNote").value || undefined }),
  });
  setPill("filterBadge", "已否决", "fail");
  setCard("taskCard", "已否决", body.review_id, "fail");
  setSummary("reviewDecisionSummary", "审核否决", "该 OpenClaw 请求不会进入沙箱执行。", "fail");
  updateTaskDetailMirror(body);
  await loadReviewQueue();
}

async function modifyReview() {
  requireLogin();
  const reviewId = $("reviewId").value || selectedReviewId;
  if (!reviewId) throw new Error("请先选择一条待审核任务。");
  const body = await request(`/api/reviews/${reviewId}`, {
    method: "PATCH",
    headers: authHeaders(),
    body: JSON.stringify({
      action: $("reviewAction").value,
      params: parseReviewParams(),
      input_text: getReviewInputText(),
      note: $("reviewNote").value || undefined,
    }),
  });
  summarizeReview(body);
  await loadReviewQueue();
}

async function resubmitReview() {
  requireLogin();
  const reviewId = $("reviewId").value || selectedReviewId;
  if (!reviewId) throw new Error("请先选择一条待审核任务。");
  const body = await request(`/api/reviews/${reviewId}/resubmit`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      action: $("reviewAction").value,
      params: parseReviewParams(),
      input_text: getReviewInputText(),
      note: $("reviewNote").value || undefined,
    }),
  });
  summarizeReview(body);
  updateTaskDetailMirror(body);
  if (body.job_id) {
    lastJobId = body.job_id;
    $("jobId").value = body.job_id;
    try {
      await loadTask("/result", "result");
    } catch {
      updateTaskDetailMirror(body);
    }
  }
  await loadReviewQueue();
  await loadCaptureRecords();
  setView(body.status === "APPROVED" && body.job_id ? "result" : "review");
}

async function loadTask(suffix, mode) {
  requireLogin();
  const jobId = $("jobId").value || lastJobId;
  if (!jobId) throw new Error("还没有 Job ID，请先提交任务。");
  const body = await request(`/api/tasks/${jobId}${suffix}`, { headers: authHeaders() });
  if (mode === "status") summarizeTaskStatus(body);
  if (mode === "logs") summarizeLogs(body);
  if (mode === "result") summarizeResult(body);
  updateTaskDetailMirror(body);
}

function bindEvents() {
  if ($("sidebarToggle")) {
    $("sidebarToggle").addEventListener("click", toggleSidebar);
  }

  document.querySelectorAll(".workflow-step").forEach((step) => {
    step.addEventListener("click", () => openView(step.dataset.view));
  });

  $("apiBase").addEventListener("input", () => {
    setPill("navApiBadge", `API ${apiBase().replace(/^https?:\/\//, "")}`, "neutral");
  });

  document.querySelectorAll(".sample-button").forEach((button) => {
    button.addEventListener("click", () => activateSample(button.dataset.sample));
  });

  $("healthBtn").onclick = () => healthCheck();
  $("loginBtn").onclick = async () => {
    try {
      await login($("username").value, $("password").value);
    } catch (error) {
      setCard("loginCard", "登录失败", error.message, "fail");
      setSummary("loginSummary", "登录失败", error.message, "fail");
    }
  };

  $("demoLoginBtn").onclick = async () => {
    $("username").value = "admin";
    $("password").value = "admin123";
    $("loginBtn").click();
  };

  $("captureTaskBtn").onclick = async () => {
    try {
      await captureTask();
    } catch (error) {
      setPill("filterBadge", "已拦截", "fail");
      setCard("taskCard", "捕获失败", error.message, "fail");
      setSummary("taskSubmitSummary", "捕获失败", error.message, "fail");
    }
  };

  $("reviewQueueBtn").onclick = async () => {
    try {
      setView("review");
      await loadReviewQueue();
      await loadCaptureRecords();
      setSummary("taskSubmitSummary", "队列已刷新", "待审核请求已更新。", "ok");
    } catch (error) {
      setSummary("taskSubmitSummary", "队列刷新失败", error.message, "fail");
    }
  };

  $("approveReviewBtn").onclick = async () => {
    try {
      await approveReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "同意失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("rejectReviewBtn").onclick = async () => {
    try {
      await rejectReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "否决失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("modifyReviewBtn").onclick = async () => {
    try {
      await modifyReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "修改失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("resubmitReviewBtn").onclick = async () => {
    try {
      await resubmitReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "重新投递失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("statusBtn").onclick = async () => {
    try {
      await loadTask("", "status");
    } catch (error) {
      setSummary("taskDetailSummary", "状态读取失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("logsBtn").onclick = async () => {
    try {
      await loadTask("/logs", "logs");
    } catch (error) {
      setSummary("taskDetailSummary", "日志读取失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("resultBtn").onclick = async () => {
    try {
      await loadTask("/result", "result");
    } catch (error) {
      setSummary("taskDetailSummary", "结果读取失败", error.message, "fail");
      updateTaskDetailMirror(error.message);
    }
  };

  $("refreshTaskBtn").onclick = async () => {
    if (currentView === "review") {
      try {
        await loadReviewQueue();
        setSummary("reviewDecisionSummary", "队列已刷新", "待审核请求已更新。", "ok");
      } catch (error) {
        setSummary("reviewDecisionSummary", "队列刷新失败", error.message, "fail");
      }
      return;
    }
    $("statusBtn").click();
  };

  $("goCaptureBtn").onclick = () => { closeDecisionPanel(); setView("capture"); };
  $("goSecurityFromReviewBtn").onclick = () => { closeDecisionPanel(); setView("security"); };
  $("closeDecisionBtn").onclick = () => closeDecisionPanel();
  $("reviewDecisionBackdrop").onclick = () => closeDecisionPanel();
  $("goReviewFromResultBtn").onclick = () => setView("review");
  $("goSecurityFromResultBtn").onclick = () => setView("security");

  $("captureRecordsBtn").onclick = async () => {
    try {
      await loadCaptureRecords();
      setSummary("taskSubmitSummary", "捕获记录已刷新", "无风险自动通过，有风险待审核。", "ok");
    } catch (error) {
      setSummary("taskSubmitSummary", "捕获记录刷新失败", error.message, "fail");
    }
  };

  $("auditBtn").onclick = async () => {
    try {
      requireLogin();
      const risk = $("riskLevel").value;
      const body = await request(`/api/audit${risk ? `?risk_level=${risk}` : ""}`, { headers: authHeaders() });
      renderAudit(body);
    } catch (error) {
      $("auditSummary").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  };

  $("analyticsBtn").onclick = async () => {
    try {
      await loadAnalytics();
    } catch (error) {
      $("analyticsSummary").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      $("analyticsChart").innerHTML = '<div class="empty-state">图表生成失败。</div>';
    }
  };

  ["analyticsPeriod", "analyticsSource", "analyticsRisk"].forEach((id) => {
    $(id).onchange = () => {
      if (currentView === "security" && token) $("analyticsBtn").click();
    };
  });

  $("cflStatusBtn").onclick = async () => {
    try {
      const body = await request("/api/auth/cfl/status");
      summarizeCflStatus(body);
    } catch (error) {
      setCard("cflCard", "CFL 状态失败", error.message, "fail");
      setSummary("cflSummary", "CFL 状态读取失败", error.message, "fail");
    }
  };

  $("cflDiagBtn").onclick = async () => {
    try {
      requireLogin();
      const body = await request("/api/auth/cfl/diagnostics", { headers: authHeaders() });
      summarizeCflDiag(body);
    } catch (error) {
      setSummary("cflSummary", "CFL 诊断失败", error.message, "fail");
    }
  };

  // ─── Step 6: 外来攻击拦截 ───
  function renderThreatQueue(items) {
    const list = $("threatList");
    if (!items || items.length === 0) {
      list.innerHTML = '<div class="empty-state">暂无拦截记录。安全。</div>';
      $("threatCountBadge").textContent = "0 次拦截";
      return;
    }
    $("threatCountBadge").textContent = `${items.length} 次拦截`;
    list.innerHTML = items.map((item) => {
      const analysis = item.analysis || {};
      const risk = analysis.risk_level || "?";
      const ts = formatTime(item.created_at);
      const isDeny = item.filter_decision === "DENY";
      return `<button class="review-item${isDeny ? " review-item-danger" : ""}" data-review-id="${escapeHtml(item.review_id)}" type="button">
        <div class="review-meta">
          <span class="status-pill ${isDeny ? "fail" : "warn"}">${escapeHtml(item.filter_decision)}</span>
          <small>${escapeHtml(ts)}</small>
        </div>
        <strong style="color:${isDeny ? "#dc3545" : "#fd7e14"}">${escapeHtml(item.action || "?")}</strong>
        <small>风险: ${escapeHtml(risk)} | 建议: ${escapeHtml(item.recommendation || "?")}</small>
      </button>`;
    }).join("");

    // Click handler
    list.querySelectorAll(".review-item").forEach((btn) => {
      btn.onclick = () => showThreatDetail(items.find((i) => i.review_id === btn.dataset.reviewId));
    });
  }

  function showThreatDetail(item) {
    if (!item) return;
    selectedReview = item;
    selectedReviewId = item.review_id;
    const analysis = item.analysis || {};
    const filterResult = analysis.filter_result || {};
    const findings = filterResult.findings || [];
    const reasons = analysis.reasons || [];

    let html = `<strong>Review ID:</strong> ${escapeHtml(item.review_id)}<br>`;
    html += `<strong>时间:</strong> ${formatTime(item.created_at)}<br>`;
    html += `<strong>过滤裁决:</strong> ${escapeHtml(item.filter_decision)}<br>`;
    html += `<strong>风险等级:</strong> ${escapeHtml(analysis.risk_level || "?")}<br>`;
    html += `<strong>操作:</strong> ${escapeHtml(item.action || "?")}<br>`;
    html += `<strong>来源:</strong> ${escapeHtml(analysis.source || "openclaw-main")}<br>`;
    if (item.params) {
      html += `<strong>参数:</strong> ${escapeHtml(JSON.stringify(item.params))}<br>`;
    }
    if (item.input_text) {
      html += `<strong>输入内容:</strong> ${escapeHtml(item.input_text.substring(0, 200))}<br>`;
    }
    if (reasons.length) {
      html += `<strong>拦截原因:</strong><ul>`;
      reasons.forEach((r) => { html += `<li>⚠️ ${escapeHtml(r)}</li>`; });
      html += `</ul>`;
    }
    if (findings.length) {
      html += `<strong>匹配规则:</strong><ul>`;
      findings.forEach((f) => {
        const icon = f.level === "high" ? "🔴" : "🟡";
        html += `<li>${icon} [${escapeHtml(f.level)}] ${escapeHtml((f.rule || "").substring(0, 80))}</li>`;
      });
      html += `</ul>`;
    }
    $("threatDetail").innerHTML = html;
  }

  async function loadThreatQueue(filterDecision) {
    try {
      requireLogin();
      let url = "/api/reviews?status=PENDING";
      if (filterDecision && filterDecision !== "ALL") {
        url += `&filter_decision=${encodeURIComponent(filterDecision)}`;
      }
      const body = await request(url, { headers: authHeaders() });
      renderThreatQueue(body.items || []);
    } catch (error) {
      $("threatList").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }

  $("refreshThreatBtn").onclick = () => {
    loadThreatQueue($("threatFilter").value);
  };

  $("threatFilter").onchange = () => {
    loadThreatQueue($("threatFilter").value);
  };

  // Load threat data when switching to threat view
  $("registerAgentBtn").onclick = async () => {
    try {
      requireLogin();
      const address = $("agentAddress").value;
      const body = await request("/api/agents/register", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ address, name: "OpenClaw Agent" }),
      });
      setSummary("agentSummary", "Agent 注册成功", `ID: ${body.agent.agent_id} | 地址: ${body.agent.address || "local"}`);
      refreshAgentStatus();
    } catch (error) {
      $("agentSummary").innerHTML = `<strong>注册失败</strong><p>${escapeHtml(error.message)}</p>`;
    }
  };

  $("refreshAgentBtn").onclick = () => refreshAgentStatus();

  $("demoAttacksBtn").onclick = async () => {
    try {
      requireLogin();
      const body = await request("/api/agents/demo/run-attacks", {
        method: "POST",
        headers: authHeaders(),
      });
      const results = body.results || [];
      const denied = results.filter(r => r.filter_decision === "DENY").length;
      const approved = results.filter(r => r.filter_decision === "ALLOW" && r.recommendation === "approve").length;
      $("agentSummary").innerHTML =
        `<strong>攻击样本已生成</strong><p>共 ${results.length} 条 | 拦截 ${denied} 条 | 放行 ${approved} 条</p>`;
      setCard("agentCard", "测试完成", `${results.length} 条请求已进入审核队列`, "ok");
    } catch (error) {
      $("agentSummary").innerHTML = `<strong>生成失败</strong><p>${escapeHtml(error.message)}</p>`;
    }
  };

  $("demoSafeBtn").onclick = async () => {
    try {
      requireLogin();
      const body = await request("/api/agents/demo/run-safe", {
        method: "POST",
        headers: authHeaders(),
      });
      const review = body.review || {};
      $("agentSummary").innerHTML =
        `<strong>正常请求已生成</strong><p>Review: ${review.review_id} | Filter: ${review.filter_decision} | Rec: ${review.recommendation}</p>`;
    } catch (error) {
      $("agentSummary").innerHTML = `<strong>生成失败</strong><p>${escapeHtml(error.message)}</p>`;
    }
  };

  const origSetView = setView;
  setView = function(viewName) {
    origSetView(viewName);
    closeDecisionPanel();
    if (viewName === "threat") {
      loadThreatQueue($("threatFilter").value);
    } else if (viewName === "agent") {
      refreshAgentStatus();
    }
  };
}

bindEvents();
activateSample("normal");
setSidebarCollapsed(localStorage.getItem("clawguard.sidebarCollapsed") === "1");
setView("login");
healthCheck();
