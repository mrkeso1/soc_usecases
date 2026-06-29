(function () {
    function renderIcons(scope) {
        if (window.lucide) {
            window.lucide.createIcons({ root: scope || document });
        }
    }

    function showToast(message, tone) {
        if (!message) return;
        var current = document.querySelector(".soc-toast");
        if (current) current.remove();

        var toast = document.createElement("div");
        toast.className = "soc-toast " + (tone || "success");
        toast.textContent = message;
        document.body.appendChild(toast);
        requestAnimationFrame(function () {
            toast.classList.add("visible");
        });
        setTimeout(function () {
            toast.classList.remove("visible");
            setTimeout(function () {
                toast.remove();
            }, 180);
        }, 3200);
    }

    function parseTriggerHeader(raw) {
        if (!raw) return {};
        try {
            return JSON.parse(raw);
        } catch (_error) {
            var eventMap = {};
            raw.split(",").map(function (item) { return item.trim(); }).filter(Boolean).forEach(function (eventName) {
                eventMap[eventName] = {};
            });
            return eventMap;
        }
    }

    document.addEventListener("DOMContentLoaded", function () {
        renderIcons(document);

        document.querySelectorAll("[data-tabs]").forEach(function (tabs) {
            var scope = tabs.parentElement || document;
            tabs.querySelectorAll("[data-tab]").forEach(function (button) {
                button.addEventListener("click", function () {
                    tabs.querySelectorAll("[data-tab]").forEach(function (item) {
                        item.classList.toggle("active", item === button);
                    });
                    scope.querySelectorAll("[data-panel]").forEach(function (panel) {
                        panel.hidden = panel.dataset.panel !== button.dataset.tab;
                    });
                });
            });
        });

        document.querySelectorAll("form[method='get'], form:not([method])").forEach(function (form) {
            if (form.dataset.liveSearch === "off") return;
            var searchInput = form.querySelector("input[name='q'], input[type='search']");
            if (!searchInput) return;

            var timer = null;
            var submitForm = function () {
                if (form.requestSubmit) {
                    form.requestSubmit();
                } else {
                    form.submit();
                }
            };

            searchInput.addEventListener("input", function () {
                clearTimeout(timer);
                timer = setTimeout(submitForm, 450);
            });

            form.querySelectorAll("select").forEach(function (select) {
                select.addEventListener("change", submitForm);
            });
        });
    });

    document.body.addEventListener("htmx:afterSwap", function (event) {
        renderIcons(event.detail.target || document);
    });

    document.body.addEventListener("htmx:afterRequest", function (event) {
        var xhr = event.detail && event.detail.xhr;
        if (!xhr) return;
        var triggers = parseTriggerHeader(xhr.getResponseHeader("HX-Trigger"));
        if (triggers["soc-toast"]) {
            showToast(triggers["soc-toast"].message, triggers["soc-toast"].tone);
        }
    });

    document.body.addEventListener("htmx:responseError", function () {
        showToast("No se pudo completar la operacion.", "error");
    });

    document.body.addEventListener("htmx:sendError", function () {
        showToast("No se pudo conectar con el servidor.", "error");
    });

    window.socToast = showToast;
})();
