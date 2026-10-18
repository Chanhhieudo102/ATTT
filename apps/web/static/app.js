(() => {
  const state = {
    mode: document.body.dataset.defaultMode === "demo" ? "demo" : "live",
    view: "monitor",
    filter: "all",
    paused: false,
    snapshot: null,
    rows: [],
    events: [],
    history: [],
    selectedPid: null,
    noticeDismissed: false,
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const make = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  };
  const safeNumber = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const percent = (value, digits = 1) => `${safeNumber(value).toFixed(digits)}%`;
  const prettyTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };
  const age = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "thời gian không rõ";
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 60) return `${seconds} giây trước`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} phút trước`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} giờ trước`;
    return date.toLocaleString("vi-VN");
  };
  const initials = (name) => (String(name || "PR").replace(/\.exe$/i, "").match(/[a-z0-9]+/gi) || ["PR"])
    .slice(0, 2).map((piece) => piece[0]).join("").toUpperCase();
  const riskLevel = (score) => score >= .75 ? "high" : score >= .45 ? "medium" : "low";
  const riskLabel = (score) => score >= .65 ? "Xem xét" : score >= .4 ? "Theo dõi" : "Bình thường";

  function setView(view) {
    state.view = view;
    $$(".view").forEach((element) => element.classList.toggle("active", element.id === `${view}-view`));
    $$(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.view === view));
    const labels = { monitor: "Giám sát", research: "Nghiên cứu ML", events: "Nhật ký cảnh báo" };
    $("#breadcrumb-current").textContent = labels[view] || "Giám sát";
    if (view === "events") loadEvents(true);
    if (view === "research") loadResearch();
  }

  function setMode(mode) {
    if (!new Set(["live", "demo"]).has(mode)) return;
    state.mode = mode;
    $$(".mode-button").forEach((element) => element.classList.toggle("active", element.dataset.mode === mode));
    $("#source-mode-label").textContent = mode === "demo" ? "Safe demo fixtures" : "Live host";
    $("#source-model-label").textContent = mode === "demo" ? "Synthetic PID model · demo only" : "Local process telemetry";
    const notice = $("#mode-notice");
    notice.classList.toggle("demo-notice", mode === "demo");
    notice.querySelector("span:last-of-type").textContent = mode === "demo"
      ? "Chế độ demo dùng bản ghi synthetic; không tiến trình hay payload nào được chạy. Model score chỉ minh họa."
      : "Live đọc telemetry của máy này. Điểm cảnh báo là tín hiệu cần kiểm tra, không phải kết luận malware.";
    if (!state.noticeDismissed) notice.classList.remove("hidden");
    state.selectedPid = null;
    closeDrawer();
    refreshSnapshot(true);
  }

  async function refreshSnapshot(force = false) {
    if (state.paused && !force) return;
    try {
      const response = await fetch(`/api/processes?mode=${state.mode}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      if (state.mode !== payload.mode) return;
      state.snapshot = payload;
      state.rows = payload.processes || [];
      state.history.push({ cpu: safeNumber(payload.summary?.host_cpu), memory: safeNumber(payload.summary?.host_memory) });
      state.history = state.history.slice(-30);
      updateDashboard(payload);
      renderRows();
      renderChart();
      await loadEvents(false);
      if (state.selectedPid !== null) {
        const selected = state.rows.find((row) => Number(row.pid) === Number(state.selectedPid));
        if (selected) renderDetails(selected);
        else closeDrawer();
      }
    } catch (error) {
      $("#updated-label").textContent = `Mất kết nối API · ${error.message}`;
      $("#collector-status").textContent = "Không kết nối";
      $("#collector-status").style.color = "#c45c62";
    }
  }

  function updateDashboard(payload) {
    const summary = payload.summary || {};
    $("#stat-processes").textContent = safeNumber(summary.process_count).toLocaleString("vi-VN");
    $("#stat-alerts").textContent = safeNumber(summary.alert_count).toLocaleString("vi-VN");
    $("#stat-cpu").textContent = safeNumber(summary.host_cpu).toFixed(1);
    $("#stat-memory").textContent = safeNumber(summary.host_memory).toFixed(1);
    $("#cpu-meter").style.width = `${Math.min(100, safeNumber(summary.host_cpu))}%`;
    $("#memory-meter").style.width = `${Math.min(100, safeNumber(summary.host_memory))}%`;
    $("#updated-label").textContent = `Cập nhật ${prettyTime(payload.updated_at)}`;
    $("#table-updated").textContent = `Snapshot ${prettyTime(payload.updated_at)}`;
    $("#table-count").textContent = String(state.rows.length);
    $("#filter-alert-count").textContent = String(summary.alert_count || 0);
    const alertBadge = $("#nav-alert-count");
    alertBadge.textContent = String(summary.alert_count || 0);
    alertBadge.classList.toggle("visible", safeNumber(summary.alert_count) > 0);
    $("#model-status").textContent = payload.model || "Rules";
    $("#source-model-label").textContent = payload.model || "Rules";
    $("#scan-time").textContent = `${safeNumber(summary.scan_ms).toFixed(0)} ms`;
    $("#footer-resource").textContent = `Monitor ${safeNumber(summary.app_cpu).toFixed(1)}% CPU · ${safeNumber(summary.app_memory_mb).toFixed(1)} MB`;
    $("#table-footer-label").textContent = payload.mode === "demo"
      ? `${state.rows.length} bản ghi mô phỏng · dữ liệu không chạy trên hệ điều hành`
      : `${state.rows.length.toLocaleString("vi-VN")} tiến trình trong snapshot`;
    $("#health-title").textContent = payload.mode === "demo" ? "Demo an toàn đang chạy" : "Collector đang hoạt động";
    $("#health-description").textContent = payload.mode === "demo"
      ? "Fixture process và model synthetic được bật cho minh họa."
      : payload.model || "Đang thu thập telemetry bằng psutil.";
    $("#collector-status").textContent = "Đang hoạt động";
    $("#collector-status").style.color = "#2b9d80";
    $("#health-score").textContent = "OK";
    $(".health-ring").style.background = "conic-gradient(#25b995 0deg, #25b995 360deg)";
    $("#chart-current").textContent = `CPU ${percent(summary.host_cpu)} · RAM ${percent(summary.host_memory)}`;
    const notice = $("#mode-notice");
    if (payload.mode === "demo") {
      notice.querySelector("span:last-of-type").textContent = payload.notice;
      notice.classList.add("demo-notice");
    } else if (!state.noticeDismissed) {
      notice.querySelector("span:last-of-type").textContent = payload.notice;
    }
    renderRecentAlerts();
  }

  function renderRows() {
    const body = $("#process-table");
    body.replaceChildren();
    const query = $("#global-search").value.trim().toLocaleLowerCase("vi");
    const visible = state.rows.filter((row) => {
      const score = safeNumber(row.score);
      if (state.filter === "alerts" && score < .65) return false;
      if (state.filter === "cpu" && safeNumber(row.cpu_percent) < 50) return false;
      if (state.filter === "network" && safeNumber(row.connection_count) < 1) return false;
      if (query) {
        const haystack = [row.name, row.exe, row.pid, row.ppid, row.cmdline].join(" ").toLocaleLowerCase("vi");
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
    if (!visible.length) {
      const row = make("tr");
      const cell = make("td", "loading-cell", state.rows.length ? "Không có tiến trình khớp bộ lọc." : "Đang chờ snapshot tiến trình…");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
      return;
    }
    const fragment = document.createDocumentFragment();
    visible.forEach((process) => {
      const row = make("tr");
      row.dataset.pid = String(process.pid);
      if (Number(process.pid) === Number(state.selectedPid)) row.classList.add("selected");
      const score = safeNumber(process.score);
      const level = riskLevel(score);
      const processCell = make("td");
      const wrap = make("div", "process-cell");
      const indent = make("span", "tree-indent");
      indent.style.width = `${Math.min(12, safeNumber(process.depth)) * 13}px`;
      wrap.append(indent);
      if (safeNumber(process.depth) > 0) wrap.append(make("span", "tree-branch", "↳"));
      const icon = make("span", `process-app-icon${score >= .65 ? " suspicious" : ""}`, initials(process.name));
      wrap.append(icon);
      const nameWrap = make("span", "process-name-wrap");
      const name = make("span", "process-name", process.name || "Unknown process");
      name.title = process.name || "";
      nameWrap.append(name);
      const exe = make("span", "process-exe", process.exe || "Đường dẫn không truy cập được");
      exe.title = process.exe || "";
      nameWrap.append(exe);
      wrap.append(nameWrap);
      if (state.mode === "demo") wrap.append(make("span", "demo-row-mark", "DEMO"));
      processCell.append(wrap);
      const pidCell = make("td", "pid-cell");
      pidCell.append(document.createTextNode(String(process.pid)));
      pidCell.append(make("small", "", `PPID ${process.ppid ?? "—"}`));
      const cpuCell = resourceCell(process.cpu_percent, "cpu");
      const memoryCell = resourceCell(process.memory_percent, "memory");
      const networkCell = make("td", "network-count", `${safeNumber(process.connection_count)} conn`);
      const riskCell = make("td");
      const pill = make("span", `risk-pill ${level}${state.mode === "demo" ? " demo-pill" : ""}`, `${Math.round(score * 100)}%`);
      pill.title = `${riskLabel(score)} · Rule ${Math.round(safeNumber(process.rule_score) * 100)}% · ML ${Math.round(safeNumber(process.ml_score) * 100)}%`;
      riskCell.append(pill);
      row.append(processCell, pidCell, cpuCell, memoryCell, networkCell, riskCell);
      row.addEventListener("click", () => selectProcess(process));
      fragment.append(row);
    });
    body.append(fragment);
  }

  function resourceCell(value, kind) {
    const cell = make("td", "resource-cell");
    cell.append(document.createTextNode(percent(value)));
    const track = make("span", `resource-track${kind === "memory" ? " memory-track" : ""}`);
    const fill = make("span");
    fill.style.width = `${Math.min(100, Math.max(0, safeNumber(value)))}%`;
    track.append(fill);
    cell.append(track);
    return cell;
  }

  function selectProcess(process) {
    state.selectedPid = process.pid;
    renderRows();
    renderDetails(process);
    $("#detail-drawer").classList.add("open");
    $("#detail-drawer").setAttribute("aria-hidden", "false");
    $("#drawer-scrim").classList.add("open");
  }

  function detailTile(label, value) {
    const tile = make("div", "detail-tile");
    tile.append(make("span", "", label), make("strong", "", value));
    return tile;
  }

  function detailLine(parent, label, value) {
    const line = make("div", "detail-line");
    line.append(make("span", "", label), make("p", "", value || "Không có dữ liệu / không đủ quyền đọc."));
    parent.append(line);
  }

  function renderDetails(process) {
    $("#drawer-icon").textContent = initials(process.name);
    $("#drawer-name").textContent = process.name || "Unknown process";
    $("#drawer-path").textContent = process.exe || "Đường dẫn không truy cập được";
    const container = $("#drawer-content");
    container.replaceChildren();
    if (state.mode === "demo") {
      const disclaimer = make("div", "demo-disclaimer", "Fixture tổng hợp để minh họa. PID này không tồn tại trên host; không thể kiểm tra file, Sysmon hay kết thúc tiến trình.");
      container.append(disclaimer);
    }
    const stats = make("section", "drawer-section");
    stats.append(make("h3", "", "Runtime snapshot"));
    const grid = make("div", "detail-grid");
    grid.append(detailTile("PROCESS ID", String(process.pid)), detailTile("PARENT PID", String(process.ppid ?? "—")),
      detailTile("CPU", percent(process.cpu_percent)), detailTile("RAM", percent(process.memory_percent)),
      detailTile("CPU AVG / PEAK · UP TO 5 SCANS", `${percent(process.cpu_avg_percent ?? process.cpu_percent)} / ${percent(process.cpu_peak_percent ?? process.cpu_percent)}`),
      detailTile("RAM AVG / PEAK · UP TO 5 SCANS", `${percent(process.memory_avg_percent ?? process.memory_percent)} / ${percent(process.memory_peak_percent ?? process.memory_percent)}`),
      detailTile("THREADS", String(process.thread_count ?? "—")), detailTile("HANDLES", String(process.handle_count ?? "—")),
      detailTile("NETWORK", `${safeNumber(process.connection_count)} kết nối`), detailTile("CHILDREN", String(process.child_count ?? "—")),
      detailTile("RULE SCORE", percent(safeNumber(process.rule_score) * 100, 0)), detailTile("ML SCORE", percent(safeNumber(process.ml_score) * 100, 0)));
    stats.append(grid);
    container.append(stats);

    const signals = make("section", "drawer-section");
    signals.append(make("h3", "", `Tín hiệu · ${riskLabel(safeNumber(process.score))}`));
    if ((process.reasons || []).length) {
      process.reasons.forEach((reason) => signals.append(make("span", "reason-chip", reason)));
    } else {
      signals.append(make("div", "detail-line", "Không có rule nào kích hoạt."));
    }
    detailLine(signals, "MODEL", process.model_name || "Rules only");
    detailLine(signals, "PARENT PROCESS", process.parent_name || "Không xác định");
    detailLine(signals, "STARTED", process.create_time ? new Date(process.create_time * 1000).toLocaleString("vi-VN") : "Không xác định");
    detailLine(signals, "USERNAME", process.username || "Không xác định");
    container.append(signals);

    const command = make("section", "drawer-section");
    command.append(make("h3", "", "Execution context"));
    detailLine(command, "COMMAND LINE", process.cmdline || "Không truy cập được");
    detailLine(command, "READ / WRITE", `${safeNumber(process.file_read_rate_kbps).toFixed(1)} / ${safeNumber(process.file_write_rate_kbps).toFixed(1)} KB/s`);
    detailLine(command, "READ / WRITE OPS", `${safeNumber(process.file_read_ops_per_sec).toFixed(1)} / ${safeNumber(process.file_write_ops_per_sec).toFixed(1)} ops/s`);
    container.append(command);

    const connections = make("section", "drawer-section");
    connections.append(make("h3", "", `Network connections · ${safeNumber(process.connection_count)}`));
    const list = process.connections || [];
    if (list.length) {
      list.slice(0, 15).forEach((connection) => {
        const line = make("div", "connection-item");
        line.append(document.createTextNode(`${connection.local || "?"} → ${connection.remote || "local/listen"} `));
        line.append(make("small", "", connection.status || ""));
        connections.append(line);
      });
    } else {
      connections.append(make("div", "detail-line", "Không có kết nối hiển thị hoặc thiếu quyền đọc."));
    }
    container.append(connections);
  }

  function closeDrawer() {
    $("#detail-drawer").classList.remove("open");
    $("#detail-drawer").setAttribute("aria-hidden", "true");
    $("#drawer-scrim").classList.remove("open");
    $$("#process-table tr.selected").forEach((row) => row.classList.remove("selected"));
    state.selectedPid = null;
  }

  function renderChart() {
    const canvas = $("#resource-chart");
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    const width = rect.width;
    const height = rect.height;
    const left = 8, right = width - 6, top = 8, bottom = height - 11;
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = "#edf1f5";
    ctx.lineWidth = 1;
    for (let index = 0; index < 4; index += 1) {
      const y = top + (bottom - top) * index / 3;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
    }
    if (state.history.length < 2) {
      $("#chart-empty").classList.remove("hidden");
      return;
    }
    $("#chart-empty").classList.add("hidden");
    const line = (key, color) => {
      ctx.beginPath();
      state.history.forEach((point, index) => {
        const x = left + (right - left) * index / Math.max(1, state.history.length - 1);
        const y = bottom - Math.min(100, Math.max(0, point[key])) / 100 * (bottom - top);
        if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke();
    };
    line("cpu", "#5889eb");
    line("memory", "#28b995");
  }

  async function loadEvents(renderFull) {
    try {
      const response = await fetch("/api/events", { cache: "no-store" });
      if (!response.ok) return;
      const events = await response.json();
      state.events = Array.isArray(events) ? events : [];
      renderRecentAlerts();
      if (renderFull || state.view === "events") renderFullEvents();
    } catch (_error) { /* Event log is supplementary; keep the monitor usable. */ }
  }

  function relevantEvents() {
    return state.events.filter((event) => state.mode === "demo" ? event.demo_only === true : event.demo_only !== true);
  }

  function renderRecentAlerts() {
    const container = $("#recent-alerts");
    if (!container) return;
    container.replaceChildren();
    const alerts = relevantEvents().slice(0, 5);
    if (!alerts.length) {
      const empty = make("div", "empty-state");
      empty.append(make("span", "", "✓"), make("strong", "", "Chưa có cảnh báo"),
        make("small", "", state.mode === "demo" ? "Chạy demo để xem bản ghi cảnh báo minh họa." : "Tiến trình đáng chú ý sẽ xuất hiện tại đây."));
      container.append(empty);
      return;
    }
    alerts.forEach((event) => {
      const item = make("div", "alert-item");
      item.append(make("span", "alert-marker", "!"));
      const copy = make("div", "alert-copy");
      const title = make("strong");
      title.append(document.createTextNode(event.name || "Process alert"), make("span", "", `${Math.round(safeNumber(event.score) * 100)}%`));
      copy.append(title, make("p", "", `PID ${event.pid ?? "—"} · ${(event.reasons || []).slice(0, 2).join(" · ") || event.model || "Tín hiệu cần xem xét"}`),
        make("time", "", age(event.timestamp)));
      item.append(copy);
      container.append(item);
    });
  }

  function renderFullEvents() {
    const container = $("#event-list");
    if (!container) return;
    container.replaceChildren();
    const events = [...state.events];
    $("#event-count-badge").textContent = `${events.length} EVENTS`;
    if (!events.length) {
      const empty = make("div", "empty-state");
      empty.append(make("span", "", "◷"), make("strong", "", "Chưa có sự kiện"),
        make("small", "", "Sự kiện sẽ xuất hiện khi điểm cảnh báo vượt ngưỡng."));
      container.append(empty);
      return;
    }
    events.forEach((event) => {
      const item = make("article", "full-event");
      item.append(make("span", "alert-marker", event.demo_only ? "D" : "!"));
      const copy = make("div", "full-event-copy");
      copy.append(make("strong", "", event.name || event.event || "Process alert"));
      const reasons = (event.reasons || []).join(" · ") || event.model || "Điểm tín hiệu vượt ngưỡng";
      copy.append(make("p", "", `PID ${event.pid ?? "—"} · ${event.exe || "Đường dẫn không có trong log"} · ${reasons}`));
      copy.append(make("small", "", `${age(event.timestamp)}${event.demo_only ? " · DEMO SYNTHETIC" : " · LIVE"}`));
      item.append(copy, make("span", "event-score", `${Math.round(safeNumber(event.score) * 100)}%`));
      container.append(item);
    });
  }

  async function loadResearch() {
    try {
      const response = await fetch("/api/research", { cache: "no-store" });
      const report = await response.json();
      const stats = $("#research-stats");
      stats.replaceChildren();
      [
        ["Mẫu sau làm sạch", "4.620", "11 sample_id xung đột đã loại"],
        ["Train / test", "4.099 / 521", "Theo split test_set công bố"],
        ["Cửa sổ đặc trưng", "5 giây", "Telemetry runtime từ sandbox"],
      ].forEach(([label, value, note]) => {
        const card = make("article", "research-stat");
        card.append(make("span", "", label), make("strong", "", value), make("small", "", note));
        stats.append(card);
      });
      const body = $("#research-table");
      body.replaceChildren();
      if (!report.metrics?.length) {
        const row = make("tr"), cell = make("td", "loading-cell", "Chưa tìm thấy báo cáo. Chạy python scripts/train_models.py --seconds 5.");
        cell.colSpan = 7; row.append(cell); body.append(row);
        $("#research-footnote").textContent = "Báo cáo local chưa được tạo; web không tự chạy huấn luyện.";
        return;
      }
      const bestF1 = Math.max(...report.metrics.map((item) => safeNumber(item.f1)));
      report.metrics.forEach((metric) => {
        const row = make("tr");
        row.append(make("td", "", metric.model || "—"));
        ["accuracy", "precision", "recall", "f1", "false_positive_rate"].forEach((key) => {
          const cell = make("td", key === "f1" && safeNumber(metric.f1) === bestF1 ? "best-model" : "",
            percent(safeNumber(metric[key]) * 100, 2));
          row.append(cell);
        });
        row.append(make("td", "", safeNumber(metric.inference_ms_per_sample).toFixed(3)));
        body.append(row);
      });
      $("#research-footnote").textContent = "Nguồn: artifacts/reports/cardiff/cardiff_model_comparison.csv · Published test_set. Inference đo estimator predict trên một mẫu, đã warm-up; thời gian phụ thuộc máy và không gồm collector/UI.";
    } catch (_error) {
      $("#research-table").replaceChildren(make("tr"));
      $("#research-footnote").textContent = "Không tải được báo cáo nghiên cứu local.";
    }
  }

  async function exportPerformance() {
    const status = $("#performance-export-status");
    try {
      const response = await fetch("/api/performance", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const samples = await response.json();
      if (!samples.length) {
        status.textContent = "Chưa có snapshot để xuất; đợi collector chạy vài chu kỳ.";
        return;
      }
      const columns = ["timestamp", "scan_ms", "process_count", "app_cpu_percent",
        "app_memory_mb", "host_cpu_percent", "host_memory_percent"];
      const cell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
      const csv = [columns.map(cell).join(","),
        ...samples.map((sample) => columns.map((column) => cell(sample[column])).join(","))].join("\r\n");
      const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "processguard-performance.csv";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      status.textContent = `Đã xuất ${samples.length} snapshot; mỗi dòng cách nhau khoảng 3 giây.`;
    } catch (_error) {
      status.textContent = "Không tải được báo cáo hiệu năng local.";
    }
  }

  $$(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-view-link]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.viewLink)));
  $$(".mode-button").forEach((button) => button.addEventListener("click", () => setMode(button.dataset.mode)));
  $$(".filter-pill").forEach((button) => button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    $$(".filter-pill").forEach((pill) => pill.classList.toggle("active", pill === button));
    renderRows();
  }));
  $("#global-search").addEventListener("input", renderRows);
  $("#clear-search").addEventListener("click", () => {
    $("#global-search").value = "";
    state.filter = "all";
    $$(".filter-pill").forEach((pill) => pill.classList.toggle("active", pill.dataset.filter === "all"));
    renderRows();
  });
  $("#refresh-button").addEventListener("click", () => refreshSnapshot(true));
  $("#export-performance").addEventListener("click", exportPerformance);
  $("#events-refresh").addEventListener("click", () => loadEvents(true));
  $("#pause-button").addEventListener("click", () => {
    state.paused = !state.paused;
    $("#pause-button").textContent = state.paused ? "▶ Tiếp tục" : "Ⅱ Tạm dừng";
    if (!state.paused) refreshSnapshot();
  });
  $("#dismiss-notice").addEventListener("click", () => {
    state.noticeDismissed = true;
    $("#mode-notice").classList.add("hidden");
  });
  $("#close-drawer").addEventListener("click", closeDrawer);
  $("#drawer-scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault(); $("#global-search").focus();
    }
    if (event.key === "Escape") closeDrawer();
  });
  window.addEventListener("resize", renderChart);
  setMode(state.mode);
  window.setInterval(() => { if (!state.paused) refreshSnapshot(); }, 3000);
})();
