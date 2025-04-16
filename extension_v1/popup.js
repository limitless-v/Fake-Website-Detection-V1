chrome.storage.local.get("siteRisk", (data) => {
    document.getElementById("status").innerText = data.siteRisk || "Unknown";
});
