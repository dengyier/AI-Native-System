const byId = (id) => document.getElementById(id);
const value = (id) => byId(id).value.trim();
const part = (name) => encodeURIComponent(name);
const taskPath = (id, suffix = "") => "/v1/tasks/" + part(id) + suffix;
const releasePath = (id, suffix = "") => "/v1/releases/" + part(id) + suffix;

const states = {
  planning: "正在规划", awaiting_approval: "待审批", ready: "待执行", reconciling: "结果未知",
  completed: "已完成", blocked: "已阻止", failed: "执行失败", rejected: "已拒绝", cancelled: "已取消",
  no_action: "无待执行动作", pending: "待补证", signed: "已签署", verified: "已验证", unverified: "待验证",
  delivered: "已提交证据", absent: "暂无证据", unknown: "未知", matched: "已匹配", conflict: "存在冲突",
  stale: "已过期", fresh: "有效", known: "已确认", incomplete: "覆盖不完整", complete: "覆盖完整",
  accept: "人工接受", reject: "人工拒绝", accepted: "人工接受", denied: "已拒绝",
  draft: "草稿", published: "已发布", deprecated: "已停用", revoked: "已撤销",
  reconciliation_conflict: "回执存在冲突", insufficient_evidence: "依据不足",
  no_evidence: "依据不足", unavailable: "暂不可用", not_available: "暂无可核验证据",
  recorded: "已保存证据", invalid: "验证失败", generated: "已生成", observed: "已有来源记录",
  source_conflict: "来源存在冲突", authoritative_agreement: "权威来源一致", authority_preferred: "采用优先来源",
  authoritative_tombstone: "权威来源已撤回", allow: "已授权", deny: "授权拒绝", manual: "待人工处理",
  available: "可用", withdrawn: "已撤回", partial: "部分覆盖", authorized_subset: "权限内对象",
  satisfied: "满足条件", not_satisfied: "不满足条件", insufficient: "依据不足",
  not_displayable: "当前无法展示规则判断",
};
const factReasons = {
  no_authority: "未配置权威来源", insufficient_authoritative_coverage: "权威来源覆盖不足", human_correction: "采用人工修正",
  object_existence_unavailable: "对象存在状态暂不可用", state_unavailable: "对象状态暂不可用",
  property_unavailable: "所需字段暂不可用", relationship_collection_unavailable: "关系集合暂不可用",
  relationship_collection_incomplete: "关系覆盖不完整", relationship_target_unavailable: "关联对象状态暂不可用",
};
const authorizationReasons = {
  authorization_required: "等待 OpenWorkProof 签名授权", authorization_revoked: "签名授权已撤销",
  authorization_outside_validity: "签名授权超出有效期", prior_action_incomplete: "等待前序动作完成",
  source_guards_unavailable: "源端条件保护暂不可用", lookup_only: "此操作可核对原回执",
  reconciliation_queued: "等待核对原回执", restore_epoch_changed: "恢复代次已变更",
};
const resourceLabels = {object: "对象", field: "字段", metadata: "元数据", edge: "关系", document: "文档", rule: "规则"};
const eventNames = {
  "release.bound": "已绑定发布版本", "request.accepted": "已接收任务",
  "request.blocked": "已阻止任务提交", "approval.requested": "已发起审批",
  "approval.recorded": "已保存审批决定", "effect.recorded": "已保存业务结果",
  "task.approved": "审批通过", "task.completed": "任务完成", "task.cancelled": "任务已取消",
  "agent.planned": "Agent 已完成规划", "action.proposed": "已生成提议",
  "policy.blocked": "策略已阻止执行", "remote.dispatched": "远端操作已发送",
  "remote.reconciled": "已核对远端操作", "model.started": "已请求模型", "model.completed": "已收到模型结果",
};
const kindText = {question: "权限问答", artifact: "指定文档生成", action: "受控对象操作"};
let credential = "";
let sessionId = 0;
let taskRevision = 0;
let factsRevision = 0;
let applications = [];
let currentTask = null;
let eventCursor = null;
let exportProof = null;
let handoff = null;
let decisionRetry = null;
let inspectedRelease = null;
const requests = new Set();
const working = new Set();

class RequestFailure extends Error {
  constructor(status) {
    super("Request failed");
    this.status = status;
  }
}

class InputFailure extends Error {}

function statusText(status) {
  return states[status] || (typeof status === "string" && status ? status : "未提供");
}

function notice(message, tone = "") {
  const el = byId("notice");
  el.textContent = message;
  el.dataset.tone = tone;
}

async function api(path, {method = "GET", body, token = credential} = {}) {
  if (!token) throw new RequestFailure(401);
  const revision = sessionId;
  const controller = new AbortController();
  requests.add(controller);
  const timer = setTimeout(() => controller.abort("timeout"), 45000);
  try {
    const headers = {Authorization: "Bearer " + token, Accept: "application/json"};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store", redirect: "error", credentials: "omit", signal: controller.signal,
    });
    if (revision !== sessionId) return null;
    if (!response.ok) throw new RequestFailure(response.status);
    const result = await response.json();
    return revision === sessionId ? result : null;
  } catch (error) {
    if (revision !== sessionId) return null;
    if (error instanceof RequestFailure) throw error;
    throw new RequestFailure(0);
  } finally {
    clearTimeout(timer);
    requests.delete(controller);
  }
}

function errorText(error) {
  if (error instanceof InputFailure) return error.message;
  const messages = {
    0: "连接中断。请先查看当前状态，再重试原请求。",
    400: "请求无法处理。请核对标识、版本和当前状态。",
    401: "访问凭证已失效。请切换身份后重新连接。",
    403: "当前身份没有这项操作权限。",
    404: "未找到该记录，或此服务未开放这项功能。",
    409: "状态已变化。请刷新记录后重新确认。",
    429: "当前请求较多。请稍后重试。",
    503: "服务暂不可用。请刷新状态后重试。",
  };
  return messages[error.status] || "服务未完成请求。请先核对当前状态。";
}

async function run(button, operation) {
  if (!button || working.has(button) || button.disabled) return;
  const revision = sessionId;
  working.add(button);
  button.disabled = true;
  updateTaskActions();
  updateReleaseActions();
  try {
    await operation();
  } catch (error) {
    if (revision === sessionId) notice(errorText(error), "problem");
  } finally {
    working.delete(button);
    button.disabled = false;
    updateTaskActions();
    updateReleaseActions();
  }
}

function element(tag, content, className) {
  const node = document.createElement(tag);
  if (content !== undefined) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function displayed(data) {
  if (typeof data === "boolean") return data ? "是" : "否";
  if (data === undefined || data === null) return "未提供";
  if (typeof data === "object") return JSON.stringify(data);
  return String(data);
}

function localTime(time) {
  if (time === undefined || time === null) return undefined;
  const date = new Date(typeof time === "number" ? time * 1000 : time);
  return Number.isNaN(date.getTime()) ? undefined : date.toLocaleString("zh-CN");
}

function pairs(entries) {
  const list = element("dl", undefined, "pairs");
  for (const [label, item] of entries) {
    if (item === undefined || item === null || item === "") continue;
    list.append(element("dt", label), element("dd", displayed(item)));
  }
  return list;
}

function detail(label, data) {
  const box = element("details");
  box.append(element("summary", label), element("pre", JSON.stringify(data, null, 2)));
  return box;
}

function readable(container, text) {
  if (typeof text === "string" && text) container.append(element("p", text, "readable"));
}

function selectApp() {
  return applications.find((app) => app.id === byId("app").value);
}

function prepareLaunch() {
  const app = selectApp();
  const kind = app?.kind;
  const isAction = kind === "action";
  const isRead = kind === "question" || kind === "artifact";
  byId("query-field").hidden = !isRead;
  byId("question").required = isRead;
  byId("object-field").hidden = !isAction;
  byId("version-field").hidden = !isAction;
  byId("object").required = isAction;
  byId("object-version").required = isAction;
  byId("request-field").hidden = !isAction;
  byId("request-key").required = isAction;
  byId("launch-options").hidden = !isAction;
  byId("launch-options").open = !!app?.uses_knowledge_citations && isAction;
  byId("launch-button").disabled = !app;
  byId("app-description").hidden = !app;
  byId("app-description").textContent = kindText[kind] || "";
  byId("launch-release").value = app?.release_digest || "";
  byId("launch-citations").value = "";
  byId("object-version").value = "";
  const sourceList = byId("document-choices");
  sourceList.replaceChildren();
  const documents = Array.isArray(app?.documents) ? app.documents : [];
  if (isRead) {
    for (const reference of documents) {
      const id = typeof reference === "string" ? reference : reference.id;
      if (typeof id !== "string") continue;
      const label = element("label", undefined, "choice");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = id;
      label.append(input, element("span", typeof reference === "object" && reference.label || id));
      sourceList.append(label);
    }
  }
  byId("source-fields").hidden = !isRead || sourceList.children.length === 0;
}

function newKey() {
  byId("request-key").value = crypto.randomUUID();
}

function loadCatalog(data) {
  applications = Array.isArray(data.applications) ? data.applications.filter(
    (row) => row && typeof row.id === "string" && typeof row.label === "string" && Object.hasOwn(kindText, row.kind),
  ) : [];
  const select = byId("app");
  select.replaceChildren(element("option", "选择应用"));
  select.firstElementChild.value = "";
  const operatorOptions = byId("app-options");
  operatorOptions.replaceChildren();
  for (const app of applications) {
    const option = element("option", app.label);
    option.value = app.id;
    select.append(option);
    const catalogOption = element("option", app.label);
    catalogOption.value = app.application || app.id;
    operatorOptions.append(catalogOption);
  }
  if (applications.length === 1) select.value = applications[0].id;
  byId("actor").textContent = typeof data.actor === "string" && data.actor ? data.actor : "已连接";
  byId("release-controls").hidden = false;
  prepareLaunch();
}

function clearTask() {
  taskRevision++;
  currentTask = null;
  eventCursor = null;
  exportProof = null;
  handoff = null;
  decisionRetry = null;
  for (const id of ["events", "review-details", "proof-details", "handoff-details", "result-details", "task-facts"]) {
    byId(id).replaceChildren();
  }
  for (const id of ["task-content", "app-result", "activity", "proof", "review", "handoff", "more-events", "download-proof"]) {
    byId(id).hidden = true;
  }
  byId("task-empty").hidden = false;
  byId("task-status").textContent = "";
  byId("task-id").textContent = "";
  byId("handoff-reason").value = "";
}

function disconnect() {
  sessionId++;
  credential = "";
  for (const request of requests) request.abort();
  for (const form of document.querySelectorAll("form")) form.reset();
  for (const fieldset of document.querySelectorAll("[data-needs-session]")) fieldset.disabled = true;
  byId("actor").textContent = "";
  byId("connect-form").hidden = false;
  byId("session").hidden = true;
  byId("release-result").replaceChildren(element("p", "输入发布摘要查看定义或影响。", "hint"));
  prepareFactsQuery();
  clearFactsResult();
  loadCatalog({applications: []});
  byId("release-controls").hidden = true;
  inspectedRelease = null;
  updateReleaseActions();
  clearTask();
  notice("请输入企业访问凭证。");
  byId("credential").focus();
}

byId("connect-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const token = value("credential");
  run(event.submitter, async () => {
    const data = await api("/v1/applications", {token});
    if (!data) return;
    credential = token;
    byId("credential").value = "";
    byId("connect-form").hidden = true;
    byId("session").hidden = false;
    for (const fieldset of document.querySelectorAll("[data-needs-session]")) fieldset.disabled = false;
    loadCatalog(data);
    newKey();
    notice(applications.length ? "已连接。请选择应用或查看任务。" : "已连接。可按标识查看获准访问的任务或发布。", "ok");
  });
});

byId("disconnect").addEventListener("click", disconnect);
byId("app").addEventListener("change", prepareLaunch);
byId("new-key").addEventListener("click", newKey);

for (const item of document.querySelectorAll("[data-view]")) {
  item.addEventListener("click", () => {
    for (const page of document.querySelectorAll(".page")) page.hidden = page.id !== item.dataset.view;
    for (const button of document.querySelectorAll("[data-view]")) button.removeAttribute("aria-current");
    item.setAttribute("aria-current", "page");
  });
}

function readJson(id, message) {
  const raw = value(id);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new InputFailure(message);
  }
}

function renderCitations(target, citations) {
  if (!Array.isArray(citations) || !citations.length) return;
  target.append(element("h3", "引用依据"));
  const list = element("ul");
  citations.forEach((reference) => {
    const citation = reference?.citation || reference;
    if (typeof citation === "string") {
      list.append(element("li", citation));
      return;
    }
    if (!citation || typeof citation !== "object") return;
    const item = element("li", citation.document_id || citation.id || "文档片段");
    item.append(pairs([
      ["来源", citation.source_id], ["文档版本", citation.document_version || citation.version],
      ["字符范围", Number.isInteger(citation.start_char) && Number.isInteger(citation.end_char) ? citation.start_char + "–" + citation.end_char : undefined],
      ["片段标识", citation.chunk_id || citation.id],
    ]));
    readable(item, reference.text || citation.text);
    list.append(item);
  });
  target.append(list);
}

function renderAppResult(data) {
  clearTask();
  byId("task-empty").hidden = true;
  byId("app-result").hidden = false;
  const target = byId("result-details");
  target.replaceChildren(pairs([
    ["应用", applications.find((app) => app.id === data.application)?.label || data.application],
    ["状态", statusText(data.status)], ["发布摘要", data.release_digest],
  ]));
  readable(target, data.text);
  renderCitations(target, data.citations);
  const available = applications.filter((app) => app.kind === "action" && app.uses_knowledge_citations);
  if (Array.isArray(data.citations) && available.length) {
    const actions = element("div", undefined, "actions");
    for (const app of available) {
      const allowed = data.citations.filter((citation) => app.documents?.includes(citation?.document_id)).slice(0, 10);
      if (!allowed.length) continue;
      const button = element("button", "用于" + app.label, "button button-subtle");
      button.type = "button";
      button.addEventListener("click", () => {
        byId("app").value = app.id;
        prepareLaunch();
        byId("launch-citations").value = JSON.stringify(allowed, null, 2);
        byId("object").focus();
      });
      actions.append(button);
    }
    if (actions.children.length) target.append(actions);
  }
}

byId("launch-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(event.submitter, async () => {
    const app = selectApp();
    if (!app) throw new InputFailure("请选择已获准的应用。");
    const body = {};
    if (app.kind === "action") {
      body.object_id = value("object");
      body.expected_version = Number(value("object-version"));
      if (!Number.isInteger(body.expected_version) || body.expected_version < 1) throw new InputFailure("请输入正整数对象版本。");
      body.request_key = value("request-key");
      const release = value("launch-release");
      if (release) body.release_digest = release;
      const citations = readJson("launch-citations", "请填写检索返回的 JSON 引用数组。");
      if (citations !== undefined) {
        if (!Array.isArray(citations)) throw new InputFailure("知识引用需要 JSON 数组。");
        body.knowledge_citations = citations;
      }
    } else {
      body.query = value("question");
      const selected = Array.from(byId("document-choices").querySelectorAll("input:checked"), (item) => item.value);
      if (app.kind === "artifact" && selected.length === 0) throw new InputFailure("请选择本次生成允许使用的文档。");
      if (selected.length) body.document_ids = selected;
    }
    const data = await api("/v1/applications/" + part(app.id) + "/run", {method: "POST", body});
    if (!data) return;
    if (typeof data.id === "string" && app.kind === "action") {
      byId("task-input").value = data.id;
      openTask(data.id);
      await refreshTask();
      if (currentTask?.id === data.id) notice("任务已提交。保留请求标识可核对同一次提交。", "ok");
    } else {
      renderAppResult(data);
      notice("应用已返回结果。", "ok");
    }
  });
});

function openTask(id) {
  clearTask();
  currentTask = {id};
}

async function refreshTask() {
  const id = currentTask.id;
  const revision = taskRevision;
  const data = await api(taskPath(id));
  if (!data || revision !== taskRevision) return;
  if (data.status !== currentTask.status) clearProof();
  currentTask = data;
  renderTask();
}

byId("load-task-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(event.submitter, async () => {
    const task = value("task-input");
    openTask(task);
    await refreshTask();
    if (currentTask?.id === task && currentTask.status) notice("已更新任务详情。", "ok");
  });
});

function hasAction(action) {
  const actions = currentTask?.available_actions;
  return Array.isArray(actions) && actions.includes(action);
}

function clearProof() {
  exportProof = null;
  byId("proof-details").replaceChildren();
  byId("download-proof").hidden = true;
}

function updateTaskActions() {
  if (!currentTask?.status) return;
  const busy = [...working].some((button) => button.closest("#task-actions, #review, #handoff-form"));
  for (const button of document.querySelectorAll("[data-operation]")) {
    button.disabled = !hasAction(button.dataset.operation) || busy;
  }
  for (const button of document.querySelectorAll("[data-decision]")) {
    button.disabled = !currentTask.review?.proposal_digest || !!decisionRetry ||
      !(hasAction("decision") || hasAction("approve")) || busy;
  }
  byId("load-handoff").hidden = !(hasAction("handover") || hasAction("review"));
  byId("load-proof").disabled = !hasAction("evidence") || working.has(byId("load-proof"));
  byId("retry-decision").hidden = !decisionRetry;
  byId("retry-decision").disabled = busy;
  for (const button of byId("handoff-form").querySelectorAll("button")) button.disabled = busy;
}

function renderReview(review) {
  const target = byId("review-details");
  target.replaceChildren();
  if (!review) {
    if (decisionRetry) readable(target, "原审批结果尚待核对。重试会使用原决定和提议摘要。");
    return;
  }
  const proposal = review.proposal || {};
  const scope = review.scope || {};
  const grounding = review.grounding || {};
  target.append(pairs([
    ["提议动作", proposal.action], ["执行对象", proposal.object_id],
    ["对象版本", proposal.object_version], ["起始状态", proposal.from_state],
    ["目标状态", proposal.to_state], ["提议摘要", review.proposal_digest],
    ["规则版本", scope.rule_versions], ["读取范围", scope.reads],
    ["写入范围", scope.writes], ["参数", scope.parameters], ["参数摘要", scope.parameters_digest],
    ["有效期", localTime(scope.expires_at ?? scope.deadline)], ["审核状态", scope.status ? statusText(scope.status) : undefined],
  ]));
  readable(target, proposal.rationale);
  renderCitations(target, grounding.knowledge || proposal.evidence_ids);
  if (Array.isArray(scope.resources) && scope.resources.length) {
    const list = element("ul");
    for (const resource of scope.resources) {
      const name = [resourceLabels[resource.kind] || resource.kind, resource.resource_id, resource.member].filter(Boolean);
      list.append(element("li", name.join(" · ")));
    }
    target.append(element("h3", "授权资源"), list);
  }
  if (grounding.object || grounding.related) {
    target.append(detail("查看授权对象与相关事实", {
      object: grounding.object, related: grounding.related,
    }));
  }
  if (Object.keys(scope).length) target.append(detail("查看完整授权范围", scope));
}

function renderTask() {
  const task = currentTask;
  byId("task-empty").hidden = true;
  byId("task-content").hidden = false;
  byId("activity").hidden = false;
  byId("proof").hidden = !hasAction("evidence");
  if (byId("proof").hidden) clearProof();
  if (!(hasAction("handover") || hasAction("review"))) {
    handoff = null;
    byId("handoff").hidden = true;
    byId("handoff-details").replaceChildren();
    byId("handoff-reason").value = "";
  }
  byId("task-heading").textContent = applications.find((app) => app.application === task.application || app.id === task.application)?.label || task.application || "任务详情";
  byId("task-id").textContent = task.id;
  byId("task-status").textContent = statusText(task.status);
  byId("task-status").dataset.state = task.status;
  byId("task-facts").replaceChildren(pairs([
    ["发布摘要", task.release_digest], ["已记录阶段", task.next_stage], ["任务截止", localTime(task.deadline)],
    ["授权状态", task.authorization?.verdict ? statusText(task.authorization.verdict) : undefined],
    ["后续处理", authorizationReasons[task.authorization?.reason]],
  ]));
  byId("review").hidden = !task.review && !decisionRetry;
  renderReview(task.review);
  updateTaskActions();
}

for (const button of document.querySelectorAll("[data-operation]")) {
  button.addEventListener("click", () => {
    run(button, async () => {
      const revision = taskRevision;
      const result = await api(taskPath(currentTask.id, "/" + button.dataset.operation), {method: "POST", body: {}});
      if (!result || revision !== taskRevision) return;
      await refreshTask();
      if (revision !== taskRevision) return;
      const reason = result.authorization?.reason;
      if (reason) {
        currentTask.authorization = result.authorization;
        renderTask();
      }
      notice(authorizationReasons[reason] || (reason ? "当前处理结果需要核对。" : "已更新任务状态。"), "ok");
    });
  });
}

async function saveDecision(payload) {
  const revision = taskRevision;
  const result = await api(taskPath(currentTask.id, "/decision"), {method: "POST", body: payload});
  if (!result || revision !== taskRevision) return;
  decisionRetry = null;
  await refreshTask();
  if (revision === taskRevision) notice("已确认原提议的审批决定。", "ok");
}

for (const button of document.querySelectorAll("[data-decision]")) {
  button.addEventListener("click", () => {
    run(button, async () => {
      const revision = taskRevision;
      const payload = {verdict: button.dataset.decision, proposal_digest: currentTask.review.proposal_digest};
      try {
        await saveDecision(payload);
      } catch (error) {
        if (revision === taskRevision && (error.status === 0 || error.status >= 500)) {
          decisionRetry = payload;
          renderTask();
          throw new InputFailure("审批返回结果未知。重试原审批会使用同一提议摘要与决定。");
        }
        throw error;
      }
    });
  });
}

byId("retry-decision").addEventListener("click", () => {
  run(byId("retry-decision"), async () => {
    if (decisionRetry) await saveDecision(decisionRetry);
  });
});

async function loadEvents(append) {
  const revision = taskRevision;
  const query = new URLSearchParams({limit: "20"});
  if (append && eventCursor) query.set("cursor", eventCursor);
  const page = await api(taskPath(currentTask.id, "/events") + "?" + query);
  if (!page || revision !== taskRevision) return;
  const list = byId("events");
  if (!append) list.replaceChildren();
  for (const event of page.events || []) {
    const item = element("li");
    const time = element("time", event.time || "", "mono");
    if (typeof event.time === "string") time.dateTime = event.time;
    item.append(time, element("strong", eventNames[event.event] || event.event));
    if (event.detail && Object.keys(event.detail).length) item.append(detail("查看事件详情", event.detail));
    list.append(item);
  }
  eventCursor = typeof page.next_cursor === "string" && page.next_cursor ? page.next_cursor : null;
  byId("more-events").hidden = page.has_more !== true || !eventCursor;
  notice(list.children.length ? "已读取任务事件。" : "当前没有获准查看的任务事件。", "ok");
}

byId("load-events").addEventListener("click", () => run(byId("load-events"), () => loadEvents(false)));
byId("more-events").addEventListener("click", () => run(byId("more-events"), () => loadEvents(true)));

byId("load-proof").addEventListener("click", () => {
  run(byId("load-proof"), async () => {
    const revision = taskRevision;
    const proof = await api(taskPath(currentTask.id, "/evidence"));
    if (!proof || revision !== taskRevision) return;
    exportProof = proof;
    const target = byId("proof-details");
    const verification = proof.verification?.status || proof.verification;
    target.replaceChildren(pairs([
      ["任务状态", statusText(proof.status)], ["已记录效果", proof.effect_recorded],
      ["回执", proof.receipt?.operation_id || proof.operation_id],
      ["证据核验", verification ? statusText(verification) : undefined],
      ["证据状态", proof.owp_evidence ? statusText(proof.owp_evidence) : undefined],
      ["源端回流", proof.source_feedback ? statusText(proof.source_feedback) : undefined],
      ["人工接管", proof.handover?.decision ? statusText(proof.handover.decision) : undefined],
    ]));
    if (proof.receipt) target.append(detail("查看获准导出的回执摘要", proof.receipt));
    byId("download-proof").hidden = false;
    notice("已读取证据与回执状态。", "ok");
  });
});

byId("download-proof").addEventListener("click", () => {
  if (!exportProof || !currentTask) return;
  const blob = new Blob([JSON.stringify(exportProof, null, 2) + "\n"], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "evidence-" + currentTask.id.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) + ".json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});

function renderHandoff(record) {
  handoff = record;
  byId("handoff").hidden = false;
  byId("handoff-form").hidden = record.eligible !== true || record.decision?.current === true ||
    typeof record.assessment_digest !== "string";
  byId("handoff-details").replaceChildren(pairs([
    ["远端状态", record.remote_status ? statusText(record.remote_status) : undefined],
    ["接管决定", record.decision?.verdict ? statusText(record.decision.verdict) :
      typeof record.decision === "string" ? statusText(record.decision) : undefined],
    ["评估摘要", record.assessment_digest],
    ["处理说明", record.decision?.reason],
    ["登记时间", localTime(record.decision?.recorded_at)],
    ["可以处理", record.eligible],
  ]));
}

byId("load-handoff").addEventListener("click", () => {
  run(byId("load-handoff"), async () => {
    const revision = taskRevision;
    const record = await api(taskPath(currentTask.id, "/handover"));
    if (record && revision === taskRevision) renderHandoff(record);
  });
});

byId("handoff-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(event.submitter, async () => {
    if (!handoff?.eligible) return;
    const revision = taskRevision;
    const record = await api(taskPath(currentTask.id, "/handover"), {method: "POST", body: {
      verdict: event.submitter.value, reason: value("handoff-reason"), assessment_digest: handoff.assessment_digest,
    }});
    if (!record || revision !== taskRevision) return;
    byId("handoff-reason").value = "";
    renderHandoff(record);
    notice("已登记人工接管决定。", "ok");
  });
});

function updateReleaseActions() {
  const actions = inspectedRelease?.digest === value("release-id") ? inspectedRelease.actions : [];
  byId("rule-options").hidden = !actions.includes("bind-rule");
  for (const button of document.querySelectorAll("[data-release-action]")) {
    button.disabled = !actions.includes(button.value) || working.has(button);
  }
}

byId("release-id").addEventListener("input", updateReleaseActions);

function renderRelease(result, operation) {
  const target = byId("release-result");
  const snapshot = result.snapshot || result.release?.snapshot;
  const digest = result.digest || result.release_digest || result.release?.digest;
  target.replaceChildren(pairs([
    ["应用", result.application || result.release?.application || snapshot?.application],
    ["生命周期", result.status ? statusText(result.status) : undefined], ["发布摘要", digest],
    ["影响", result.classification], ["受影响应用", result.affected_applications],
    ["知识策略", result.knowledge_strategy], ["OpenWorkProof 配置", result.owp_profile],
  ]));
  if (typeof digest === "string") {
    inspectedRelease = {digest, actions: Array.isArray(result.available_actions) ? result.available_actions : []};
    byId("release-id").value = digest;
  }
  updateReleaseActions();
  if (operation === "impact" || result.impact) target.append(detail("查看影响范围", result.impact || result));
  if (snapshot) {
    const ontology = snapshot.ontology;
    if (ontology) target.append(detail("查看本体定义", ontology));
    if (snapshot.definition) target.append(detail("查看应用定义", snapshot.definition));
    if (snapshot.knowledge) target.append(detail("查看知识策略", snapshot.knowledge));
  } else if (result.ontology) {
    target.append(element("h3", "本体版本"), pairs([
      ["命名空间", result.ontology.namespace], ["版本", result.ontology.version], ["摘要", result.ontology.digest],
    ]));
  } else if (!target.querySelector("dd") && operation !== "impact") {
    target.append(element("p", "版本操作已完成。", "hint"));
  }
}

byId("release-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(event.submitter, async () => {
    const operation = event.submitter.value;
    const digest = value("release-id");
    let options;
    let path;
    if (operation === "draft") {
      const application = value("release-app");
      if (!application) throw new InputFailure("请填写要生成草稿的应用标识。");
      options = {method: "POST", body: {application}};
      const ontology = readJson("draft-ontology", "请检查本体定义的 JSON 格式。");
      if (ontology !== undefined) options.body.ontology = ontology;
      for (const [field, id] of [["knowledge_strategy", "knowledge-strategy"], ["policy_version", "draft-policy-version"], ["owp_profile", "draft-profile"]]) {
        const text = value(id);
        if (text) options.body[field] = text;
      }
      path = "/v1/releases/draft";
    } else {
      if (!digest) throw new InputFailure("请填写发布摘要。");
      const suffix = operation === "show" ? "" : "/" + operation;
      path = releasePath(digest, suffix);
      if (["publish", "select", "deprecate", "revoke", "bind-rule"].includes(operation)) {
        options = {method: "POST", body: {}};
        if (operation === "publish" && value("migration-ref")) options.body.migration_ref = value("migration-ref");
        if (operation === "bind-rule") {
          if (!value("bind-rule-id")) throw new InputFailure("请输入规则标识。");
          options.body.rule_id = value("bind-rule-id");
          if (value("bind-feedback-source")) options.body.feedback_source = value("bind-feedback-source");
          if (value("bind-feedback-stream")) options.body.feedback_stream = value("bind-feedback-stream");
        }
      }
    }
    const result = await api(path, options);
    if (!result) return;
    if (operation === "bind-rule") {
      const updated = await api(releasePath(digest));
      if (!updated) return;
      renderRelease(updated, "show");
      byId("release-result").append(detail("已绑定的事实规则", result));
    } else {
      renderRelease(result, operation);
    }
    if (["select", "deprecate", "revoke"].includes(operation)) {
      const catalog = await api("/v1/applications");
      if (!catalog) return;
      loadCatalog(catalog);
    }
    notice({draft: "草稿已生成。", publish: "发布已完成。", select: "已更新当前版本。", deprecate: "已停止新任务使用该版本。",
      revoke: "发布已撤销。", "bind-rule": "事实规则已绑定。"}[operation] || "已读取发布信息。", "ok");
  });
});

function clearFactsResult(message = "指定对象后查看事实与新鲜度。") {
  byId("facts-result").replaceChildren(element("p", message, "hint"));
  return ++factsRevision;
}

function prepareFactsQuery() {
  const appSelected = !!value("fact-app");
  byId("fact-authoritative-options").hidden = !appSelected;
  const field = byId("fact-field");
  field.required = !appSelected;
  field.maxLength = appSelected ? 3215 : 200;
  if (appSelected) field.setAttribute("aria-describedby", "fact-field-help");
  else field.removeAttribute("aria-describedby");
}

function renderFactStatus(target, fact) {
  target.replaceChildren(pairs([
    ["当前状态", statusText(fact.status)], ["覆盖度", typeof fact.coverage === "string" ? statusText(fact.coverage) : fact.coverage],
    ["已明确", fact.known], ["存在", fact.present], ["值", fact.value],
    ["有效至", localTime(fact.fresh_until)], ["来源", fact.source || fact.sources],
    ["冲突数", typeof fact.conflicts === "number" ? fact.conflicts : undefined],
  ]));
  if (Array.isArray(fact.conflicts) && fact.conflicts.length) target.append(detail("查看获准访问的冲突", fact.conflicts));
}

function factLabel(field) {
  return field === "$state" ? "对象状态" : field;
}

function factReason(reason) {
  return factReasons[reason] || states[reason] || "所需依据暂不可用";
}

function renderAuthority(target, result) {
  target.replaceChildren(pairs([
    ["对象类型", result.object?.type], ["对象标识", result.object?.id], ["发布摘要", result.release_digest],
  ]));
  for (const [field, fact] of Object.entries(result.facts)) {
    const provenance = fact.provenance;
    const sources = provenance?.sources?.map(({source, version}) => [source, version].join(" · ")).join("、");
    target.append(element("h3", factLabel(field), "mono"), pairs([
      ["当前状态", statusText(fact.status)], ["值", fact.value === null ? "空值" : fact.value],
      ["覆盖度", provenance?.coverage && statusText(provenance.coverage)],
      ["来源状态", provenance?.reason && factReason(provenance.reason)],
      ["有效至", localTime(provenance?.fresh_until)], ["来源与版本", sources],
    ]));
  }
  const relation = result.relation;
  if (relation) {
    target.append(element("h3", "关系成员"), pairs([
      ["关系", relation.name], ["范围", statusText(relation.scope)],
      ["来源覆盖度", relation.coverage && statusText(relation.coverage)],
    ]));
    const members = element("ul");
    for (const member of relation.members) members.append(element("li", member.type + " · " + member.id));
    target.append(members.children.length ? members : element("p", "暂无可展示的关联对象。", "hint"));
  }
  const preview = result.preview;
  if (preview) {
    target.append(element("h3", "动作规则预览"), pairs([["规则判断", statusText(preview.status)]]));
    if (preview.status === "not_displayable") return;
    const versions = Object.entries(preview.rule_versions || {}).map(([rule, version]) => rule + " · " + version);
    target.append(pairs([
      ["动作", preview.action], ["规则版本", versions.join("、")],
      ["预期变更", preview.effect && factLabel(preview.effect.field) + " → " + displayed(preview.effect.value)],
      ["依据状态", preview.reasons?.map(factReason).join("、")],
    ]));
    if (preview.conditions?.length) {
      const conditions = element("ul");
      for (const condition of preview.conditions) {
        const scope = [condition.rule, factLabel(condition.field), condition.relation, statusText(condition.status)];
        conditions.append(element("li", scope.filter(Boolean).join(" · ")));
      }
      target.append(conditions);
    }
  }
}

byId("facts-form").addEventListener("input", () => {
  prepareFactsQuery();
  clearFactsResult();
});

byId("facts-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(event.submitter, async () => {
    const revision = clearFactsResult("正在查询…");
    const application = value("fact-app");
    const field = value("fact-field");
    const object = {object_type: value("fact-type"), object_id: value("fact-object")};
    try {
      let result;
      if (application) {
        const fields = field.split(/[,，]/).map((name) => name.trim()).filter(Boolean);
        const relation = value("fact-relation");
        const preview = byId("fact-preview").checked;
        if (!fields.length && !relation && !preview) throw new InputFailure("请选择字段、关系或规则预览。");
        const authoritative = {fields, preview, ...(relation ? {relation} : {})};
        result = await api("/v1/query", {method: "POST", body: {application, ...object, authoritative}});
      } else {
        result = await api("/v1/facts/status", {method: "POST", body: {...object, field}});
      }
      if (!result || revision !== factsRevision) return;
      const target = byId("facts-result");
      if (application) renderAuthority(target, result);
      else renderFactStatus(target, result);
      notice("已读取当前事实。", "ok");
    } catch (error) {
      if (revision !== factsRevision) return;
      clearFactsResult("查询未完成。");
      throw error;
    }
  });
});

prepareLaunch();
