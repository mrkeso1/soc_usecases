(function () {
    function renderIcons(scope) {
        if (window.lucide) {
            window.lucide.createIcons({ root: scope || document });
        }
    }

    function normalizeTone(tone) {
        var value = String(tone || "").toLowerCase();
        if (value.indexOf("error") !== -1) return "error";
        if (value.indexOf("warning") !== -1) return "warning";
        if (value.indexOf("success") !== -1) return "success";
        return "info";
    }

    function notificationTitle(tone) {
        if (tone === "error") return "No se pudo completar";
        if (tone === "warning") return "Atención";
        if (tone === "success") return "Listo";
        return "Información";
    }

    function ensureNotificationStack() {
        var stack = document.querySelector("[data-soc-notifications]");
        if (stack) return stack;

        stack = document.createElement("div");
        stack.className = "soc-notification-stack";
        stack.dataset.socNotifications = "";
        stack.setAttribute("role", "region");
        stack.setAttribute("aria-label", "Notificaciones");
        document.body.appendChild(stack);
        return stack;
    }

    function dismissNotification(notification) {
        if (!notification || notification.dataset.dismissing === "1") return;
        notification.dataset.dismissing = "1";
        notification.classList.remove("visible");
        setTimeout(function () {
            var stack = notification.parentElement;
            notification.remove();
            if (stack && !stack.querySelector("[data-server-message], [data-client-message]")) {
                stack.remove();
            }
        }, 180);
    }

    function bindNotification(notification) {
        if (!notification || notification.dataset.bound === "1") return;
        notification.dataset.bound = "1";
        var tone = normalizeTone(notification.dataset.tone || notification.className);
        var closeButton = notification.querySelector("[data-notification-close]");
        if (closeButton) {
            closeButton.addEventListener("click", function () {
                dismissNotification(notification);
            });
        }

        if (tone === "error") return;
        var delay = tone === "warning" ? 9000 : (tone === "info" ? 6500 : 5000);
        var timer = null;
        var armTimer = function (timeout) {
            clearTimeout(timer);
            timer = setTimeout(function () {
                dismissNotification(notification);
            }, timeout);
        };
        notification.addEventListener("mouseenter", function () {
            clearTimeout(timer);
        });
        notification.addEventListener("mouseleave", function () {
            armTimer(1800);
        });
        armTimer(delay);
    }

    function trimNotificationStack(stack) {
        var notifications = Array.prototype.slice.call(
            stack.querySelectorAll("[data-server-message], [data-client-message]")
        );
        var seen = {};
        notifications.forEach(function (notification) {
            var message = notification.querySelector("p");
            var key = message ? message.textContent.trim() : notification.textContent.trim();
            if (seen[key]) {
                notification.remove();
                return;
            }
            seen[key] = true;
        });

        notifications = Array.prototype.slice.call(
            stack.querySelectorAll("[data-server-message], [data-client-message]")
        );
        notifications.slice(0, Math.max(0, notifications.length - 4)).forEach(function (notification) {
            notification.remove();
        });
    }

    function initializeNotifications() {
        var stack = document.querySelector("[data-soc-notifications]");
        if (!stack) return;
        trimNotificationStack(stack);
        stack.querySelectorAll("[data-server-message], [data-client-message]").forEach(function (notification) {
            bindNotification(notification);
        });
    }

    function showToast(message, tone) {
        if (!message) return;
        var normalizedTone = normalizeTone(tone || "success");
        var stack = ensureNotificationStack();
        var toast = document.createElement("article");
        toast.className = "soc-notification " + normalizedTone;
        toast.dataset.clientMessage = "";
        toast.dataset.tone = normalizedTone;
        toast.setAttribute("role", normalizedTone === "error" || normalizedTone === "warning" ? "alert" : "status");
        toast.innerHTML =
            '<span class="soc-notification-indicator" aria-hidden="true"></span>' +
            '<div class="soc-notification-copy">' +
            '<strong class="soc-notification-title"></strong>' +
            '<p></p>' +
            '</div>' +
            '<button type="button" class="soc-notification-close" data-notification-close ' +
            'aria-label="Cerrar notificación">×</button>';
        toast.querySelector(".soc-notification-title").textContent = notificationTitle(normalizedTone);
        toast.querySelector("p").textContent = message;
        stack.appendChild(toast);
        trimNotificationStack(stack);
        bindNotification(toast);
        requestAnimationFrame(function () {
            toast.classList.add("visible");
        });
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
        initializeNotifications();

        document.querySelectorAll("[data-tabs]").forEach(function (tabs) {
            var scope = tabs.parentElement || document;
            var selectedTab = new URLSearchParams(window.location.search).get("tab");
            var selectedButton = selectedTab ? tabs.querySelector("[data-tab='" + selectedTab + "']") : null;
            var activateTab = function (button) {
                tabs.querySelectorAll("[data-tab]").forEach(function (item) {
                    item.classList.toggle("active", item === button);
                });
                scope.querySelectorAll("[data-panel]").forEach(function (panel) {
                    panel.hidden = panel.dataset.panel !== button.dataset.tab;
                });
            };

            tabs.querySelectorAll("[data-tab]").forEach(function (button) {
                button.addEventListener("click", function () {
                    activateTab(button);
                });
            });
            if (selectedButton) {
                activateTab(selectedButton);
            }
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
