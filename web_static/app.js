
"use strict";

const $ = id => document.getElementById(id);

let token = "";
let logs = [];
let approvalId = null;


function color(value) {

    if (
        ["ALLOW", "APPROVED", "SUCCESS", "LOW"]
        .includes(value)
    ) {

        return "green";

    }

    if (
        ["BLOCK", "BLOCKED", "DENIED", "CRITICAL", "ERROR"]
        .includes(value)
    ) {

        return "red";

    }

    if (
        ["REVIEW", "HIGH"].includes(value)
    ) {

        return "amber";

    }

    return "";

}


async function api(path, body) {

    const options = body === undefined
        ? {}
        : {

            method: "POST",

            headers: {

                "Content-Type": "application/json",

                "X-AgentShield-Token": token

            },

            body: JSON.stringify(body)

        };

    const response = await fetch(path, options);

    const data = await response.json();

    if (!response.ok) {

        throw Error(
            data.error || "Request failed"
        );

    }

    return data;

}


function renderLogs() {

    const query = $("filter").value.toLowerCase();

    const filtered = logs.filter(record =>

        JSON.stringify(record)
            .toLowerCase()
            .includes(query)

    );

    const tbody = $("logs");

    tbody.replaceChildren();

    for (const record of filtered) {

        const tr = document.createElement("tr");

        const columns = [

            "timestamp",
            "tool",
            "event_type",
            "decision",
            "reason"

        ];

        for (const key of columns) {

            const td = document.createElement("td");

            td.textContent = record[key] ?? "—";

            if (key === "decision") {

                td.className = color(record[key]);

            }

            tr.append(td);

        }

        tbody.append(tr);

    }

    if (!filtered.length) {

        const tr = document.createElement("tr");

        const td = document.createElement("td");

        td.colSpan = 5;

        td.textContent = "No matching audit events.";

        tr.append(td);

        tbody.append(tr);

    }

}


async function refresh() {

    const data = await api("/api/state");

    token = data.token;

    logs = data.logs;

    $("model").textContent = data.model;

    const stats = data.stats;

    for (
        const key of ["TOTAL", "ALLOW", "BLOCK", "REVIEW"]
    ) {

        $(key.toLowerCase()).textContent =
            stats[key] ?? 0;

    }

    for (
        const [index, key] of
        ["ALLOW", "BLOCK", "REVIEW"].entries()
    ) {

        const percentage = stats.TOTAL
            ? 100 * stats[key] / stats.TOTAL
            : 0;

        $("bar").children[index].style.width =
            `${percentage}%`;

    }

    $("legend").textContent =

        `${stats.ALLOW} allowed · ` +
        `${stats.BLOCK} blocked · ` +
        `${stats.REVIEW} review`;

    renderLogs();

}


function show(data) {

    $("decision").textContent = data.decision;

    $("decision").className =
        "decision " + color(data.decision);

    $("reason").textContent = data.reason;

    $("risk").textContent = data.threat.risk;

    $("risk").className = color(data.threat.risk);

    $("latency").textContent =
        data.elapsed_ms + " ms";

    $("categories").textContent =

        data.threat.categories.join(" · ")

        || "No known threat patterns detected";

    $("action").textContent =

        JSON.stringify(data.action, null, 2);

    $("execution").textContent = data.execution

        ? JSON.stringify(data.execution, null, 2)

        : "No tool executed.";

    approvalId = data.approval_id || null;

    $("approval").hidden = !approvalId;

}


$("runform").addEventListener(

    "submit",

    async event => {

        event.preventDefault();

        $("run").disabled = true;

        $("approval").hidden = true;

        approvalId = null;

        $("notice").textContent =
            "Waiting for local Ollama model...";

        try {

            if (!token) {

                await refresh();

            }

            const result = await api(

                "/api/run",

                {
                    prompt: $("prompt").value
                }

            );

            show(result);

            $("notice").textContent =
                "Evaluation complete.";

            await refresh();

        } catch (error) {

            $("notice").textContent =
                error.message;

        } finally {

            $("run").disabled = false;

        }

    }

);


for (
    const button of
    document.querySelectorAll("[data-sample]")
) {

    button.addEventListener("click", () => {

        $("prompt").value = button.dataset.sample;

    });

}


async function confirm(choice) {

    if (!approvalId) {

        return;

    }

    const id = approvalId;

    $("yes").disabled = true;

    $("no").disabled = true;

    try {

        const data = await api(

            "/api/approval",

            {

                approval_id: id,

                choice: choice

            }

        );

        $("execution").textContent =

            data.status + ": " + data.message;

        approvalId = null;

        $("approval").hidden = true;

        await refresh();

    } catch (error) {

        $("notice").textContent =
            error.message;

    } finally {

        $("yes").disabled = false;

        $("no").disabled = false;

    }

}


$("yes").onclick = () => confirm("APPROVE");

$("no").onclick = () => confirm("DENY");

$("filter").oninput = renderLogs;


$("refresh").onclick = () => {

    refresh().catch(error => {

        $("notice").textContent = error.message;

    });

};


$("export").onclick = () => {

    const blob = new Blob(

        [JSON.stringify(logs, null, 2)],

        {
            type: "application/json"
        }

    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;

    link.download = "agentshield-audit-latest.json";

    link.click();

    URL.revokeObjectURL(url);

};


refresh().catch(error => {

    $("notice").textContent = error.message;

});

// ======================================
// AGENTSHIELD RESEARCH LABORATORY
// ======================================

let researchData = null;

let researchLoading = false;


function researchPercent(value) {

    return value === null
        ? "N/A"
        : Number(value).toFixed(1) + "%";

}


function researchSeconds(value) {

    return (Number(value) / 1000)
        .toFixed(2) + " s";

}


function researchBar(
    container,
    label,
    value,
    maximum,
    display,
    color = ""
) {

    const row = document.createElement("div");

    row.className = "research-bar-row";

    const heading = document.createElement("div");

    heading.className = "research-bar-label";

    const name = document.createElement("span");

    name.textContent = label;

    const amount = document.createElement("span");

    amount.textContent = display;

    heading.append(name, amount);

    const bar = document.createElement("progress");

    bar.max = Math.max(1, maximum);

    bar.value = Math.max(0, value);

    bar.className = color;

    bar.setAttribute("aria-label", label);

    row.append(heading, bar);

    $(container).append(row);

}


function renderResearchCategories() {

    if (!researchData) return;

    const filter = $("research-filter").value;

    const tbody = $("research-categories");

    tbody.replaceChildren();

    for (const item of researchData.categories) {

        if (
            filter !== "ALL"
            && item.category !== filter
        ) {

            continue;

        }

        const tr = document.createElement("tr");

        const values = [

            item.category.replaceAll("_", " "),

            item.total,

            item.correct,

            researchPercent(item.accuracy),

            researchSeconds(item.average_latency)

        ];

        values.forEach((value, index) => {

            const td = document.createElement("td");

            td.textContent = value;

            if (index === 3) {

                td.className = item.accuracy === 100
                    ? "green"
                    : "amber";

            }

            tr.append(td);

        });

        tbody.append(tr);

    }

}


function renderResearch(data) {

    researchData = data;

    $("research-source").textContent =

        `${data.model} · ` +

        `${data.unique_scenarios} unique scenarios · ` +

        `${data.filename}`;

    $("research-total").textContent =
        data.total;

    $("research-accuracy").textContent =
        researchPercent(data.accuracy);

    $("research-prevention").textContent =
        researchPercent(data.prevention_rate);

    $("research-unsafe").textContent =
        data.unsafe_executions;

    $("research-unsafe").className =
        data.unsafe_executions === 0
        ? "green"
        : "red";

    $("research-benign").textContent =
        researchPercent(data.benign_success_rate);

    $("research-threats").textContent =
        data.threat_count;

    $("research-average").textContent =
        researchSeconds(data.average_latency);

    $("research-median").textContent =
        researchSeconds(data.median_latency);

    const containers = [

        "research-decisions",

        "research-trials",

        "research-comparison",

        "research-latencies"

    ];

    containers.forEach(id => {

        $(id).replaceChildren();

    });

    for (
        const [decision, count]
        of Object.entries(data.decisions)
    ) {

        const color = decision === "BLOCK"
            || decision === "ERROR"
            ? "danger"
            : decision === "REVIEW"
            ? "warning"
            : "";

        researchBar(

            "research-decisions",

            decision,

            count,

            data.total,

            `${count} requests`,

            color

        );

    }

    const maxTrial = Math.max(

        1,

        ...data.trials.map(
            t => t.average_latency
        )

    );

    for (const trial of data.trials) {

        researchBar(

            "research-trials",

            `Trial ${trial.trial}`,

            trial.average_latency,

            maxTrial,

            researchSeconds(
                trial.average_latency
            )

        );

    }

    researchBar(

        "research-comparison",

        "Unsafe proposals",

        data.unsafe_proposals,

        data.total,

        data.unsafe_proposals,

        "danger"

    );

    researchBar(

        "research-comparison",

        "Unsafe executions",

        data.unsafe_executions,

        data.total,

        data.unsafe_executions

    );

    const latencyMetrics = [

        ["Fastest", data.fastest_latency],

        ["Median", data.median_latency],

        ["Average", data.average_latency],

        ["Slowest", data.slowest_latency]

    ];

    for (const [label, value] of latencyMetrics) {

        researchBar(

            "research-latencies",

            label,

            value,

            data.slowest_latency,

            researchSeconds(value)

        );

    }

    const select = $("research-filter");

    const previous = select.value;

    select.replaceChildren();

    const all = document.createElement("option");

    all.value = "ALL";

    all.textContent = "All categories";

    select.append(all);

    for (const item of data.categories) {

        const option = document.createElement("option");

        option.value = item.category;

        option.textContent =
            item.category.replaceAll("_", " ");

        select.append(option);

    }

    if (
        [...select.options].some(
            o => o.value === previous
        )
    ) {

        select.value = previous;

    }

    renderResearchCategories();

}


async function loadResearch() {

    if (researchLoading) return;

    researchLoading = true;

    $("research-refresh").disabled = true;

    try {

        const data = await api("/api/research");

        if (!data.available) {

            $("research-source").textContent =
                data.message;

            return;

        }

        renderResearch(data);

    } catch (error) {

        $("research-source").textContent =

            "Research data unavailable: "

            + error.message;

    } finally {

        researchLoading = false;

        $("research-refresh").disabled = false;

    }

}


$("research-filter").addEventListener(

    "change",

    renderResearchCategories

);


$("research-refresh").addEventListener(

    "click",

    loadResearch

);


loadResearch();


// Check for new benchmark results every 30 seconds.

setInterval(loadResearch, 30000);
