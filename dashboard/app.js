/* Vault-proxy dashboard — shared utilities */

/**
 * Fetch JSON from a dashboard API path.
 * Redirects to /login on 401.
 */
async function api(path) {
    const resp = await fetch(path, { credentials: "same-origin" });
    if (resp.status === 401 || resp.status === 303) {
        window.location.href = "/login";
        throw new Error("unauthorized");
    }
    return resp.json();
}

/**
 * Safely escape a string for display (returns safe text, never HTML).
 * Uses a DOM text node to guarantee no injection.
 */
function esc(s) {
    if (s == null) return "";
    const node = document.createElement("span");
    node.textContent = String(s);
    return node.textContent;
}

/**
 * Create a table row from an array of cell values (text only, no innerHTML).
 * Returns a <tr> element.
 */
function createRow(cells, tag) {
    tag = tag || "td";
    const tr = document.createElement("tr");
    for (let i = 0; i < cells.length; i++) {
        const cell = document.createElement(tag);
        cell.textContent = String(cells[i] != null ? cells[i] : "");
        tr.appendChild(cell);
    }
    return tr;
}

/**
 * Open a Server-Sent Events connection to /api/events.
 * On each heartbeat, re-fetch the status so the dashboard stays current.
 * Reconnects automatically after 5 s if the connection drops.
 */
function connectSSE() {
    const es = new EventSource('/api/events');
    es.onmessage = (e) => {
        // On any event, refresh status
        if (typeof loadOverview === 'function') loadOverview();
    };
    es.onerror = () => { es.close(); setTimeout(connectSSE, 5000); };
}
connectSSE();
