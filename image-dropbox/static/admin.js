// 共有URLを「今開いているアドレス（trycloudflare 等）」付きの完全なURLにしてコピーする
document.querySelectorAll('.copy-link').forEach(function (button) {
    button.addEventListener('click', function () {
        const url = location.origin + button.dataset.path;
        const done = function () { button.textContent = 'コピーしました'; };
        if (navigator.clipboard) {
            navigator.clipboard.writeText(url).then(done, function () { prompt('このURLをコピーしてください', url); });
        } else {
            prompt('このURLをコピーしてください', url);
        }
    });
});
