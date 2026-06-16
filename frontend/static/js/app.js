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

function showRaw(id, value) {
  $(id).textContent = renderJson(value);
  if (id === "taskDetail" && $("taskDetailResultMirror")) {
    $("taskDetailResultMirror").textContent = renderJson(value);
  }
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

async function openView(viewName) {
  setView(viewName);
  if (currentView === "review" && token) {
    try {
      await loadReviewQueue();
    } catch (error) {
      setSummary("reviewDecisionSummary", "队列刷新失败", error.message, "fail");
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
        showRaw("taskSubmitResult", item);
        showRaw("taskDetail", item);
        renderReviewQueue(items);
      }
    });
  });
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
  setSummary("securitySummary", "CFL 状态已读取", `当前运行在 ${mode} 模式，${dll}，${helper}。`, state);
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
  setSummary("securitySummary", "CFL 诊断完成", detail, state);
}

function summarizePolicy(body) {
  const roles = body.roles ? Object.keys(body.roles).join("、") : "已读取";
  setSummary("securitySummary", "策略已读取", `当前策略包含角色：${roles}。任务提交时会按动作、角色和沙箱限制进行授权。`, "ok");
}

function renderAudit(body) {
  const items = body.items || body.audit || body.logs || [];
  const list = Array.isArray(items) ? items.slice(0, 6) : [];
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

async function healthCheck() {
  try {
    const body = await request("/api/health");
    setCard("backendCard", "连接正常", body.status || "后端 API 可访问", "ok");
    setPill("navApiBadge", `API ${apiBase().replace(/^https?:\/\//, "")}`, "ok");
    setSummary("loginSummary", "后端连接正常", "可以继续登录并提交沙箱任务。", "ok");
    showRaw("securityRaw", body);
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
  setView("capture");
  return body;
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
  showRaw("taskSubmitResult", body);
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
  showRaw("taskSubmitResult", body);
  if (body.job_id) {
    lastJobId = body.job_id;
    $("jobId").value = body.job_id;
    showRaw("taskDetail", body);
    try {
      await loadTask("/result", "result");
    } catch {
      showRaw("taskDetail", body);
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
  showRaw("taskDetail", body);
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
  showRaw("taskDetail", body);
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
  showRaw("taskSubmitResult", body);
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
  showRaw("taskDetail", body);
  showRaw("taskSubmitResult", body);
  if (body.job_id) {
    lastJobId = body.job_id;
    $("jobId").value = body.job_id;
    try {
      await loadTask("/result", "result");
    } catch {
      showRaw("taskDetail", body);
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
  showRaw("taskDetail", body);
}

function bindEvents() {
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
      showRaw("taskSubmitResult", error.message);
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
      showRaw("taskDetail", error.message);
    }
  };

  $("rejectReviewBtn").onclick = async () => {
    try {
      await rejectReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "否决失败", error.message, "fail");
      showRaw("taskDetail", error.message);
    }
  };

  $("modifyReviewBtn").onclick = async () => {
    try {
      await modifyReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "修改失败", error.message, "fail");
      showRaw("taskDetail", error.message);
    }
  };

  $("resubmitReviewBtn").onclick = async () => {
    try {
      await resubmitReview();
    } catch (error) {
      setSummary("reviewDecisionSummary", "重新投递失败", error.message, "fail");
      showRaw("taskDetail", error.message);
    }
  };

  $("statusBtn").onclick = async () => {
    try {
      await loadTask("", "status");
    } catch (error) {
      setSummary("taskDetailSummary", "状态读取失败", error.message, "fail");
      showRaw("taskDetail", error.message);
    }
  };

  $("logsBtn").onclick = async () => {
    try {
      await loadTask("/logs", "logs");
    } catch (error) {
      setSummary("taskDetailSummary", "日志读取失败", error.message, "fail");
      showRaw("taskDetail", error.message);
    }
  };

  $("resultBtn").onclick = async () => {
    try {
      await loadTask("/result", "result");
    } catch (error) {
      setSummary("taskDetailSummary", "结果读取失败", error.message, "fail");
      showRaw("taskDetail", error.message);
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

  $("goCaptureBtn").onclick = () => setView("capture");
  $("goSecurityFromReviewBtn").onclick = () => setView("security");
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
      showRaw("auditResult", body);
    } catch (error) {
      $("auditSummary").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
      showRaw("auditResult", error.message);
    }
  };

  $("policyBtn").onclick = async () => {
    try {
      requireLogin();
      const body = await request("/api/policies", { headers: authHeaders() });
      summarizePolicy(body);
      showRaw("securityRaw", body);
    } catch (error) {
      setSummary("securitySummary", "策略读取失败", error.message, "fail");
      showRaw("securityRaw", error.message);
    }
  };

  $("cflStatusBtn").onclick = async () => {
    try {
      const body = await request("/api/auth/cfl/status");
      summarizeCflStatus(body);
      showRaw("securityRaw", body);
    } catch (error) {
      setCard("cflCard", "CFL 状态失败", error.message, "fail");
      setSummary("securitySummary", "CFL 状态读取失败", error.message, "fail");
      showRaw("securityRaw", error.message);
    }
  };

  $("cflDiagBtn").onclick = async () => {
    try {
      requireLogin();
      const body = await request("/api/auth/cfl/diagnostics", { headers: authHeaders() });
      summarizeCflDiag(body);
      showRaw("securityRaw", body);
    } catch (error) {
      setSummary("securitySummary", "CFL 诊断失败", error.message, "fail");
      showRaw("securityRaw", error.message);
    }
  };
}

bindEvents();
activateSample("normal");
setView("login");
healthCheck();
