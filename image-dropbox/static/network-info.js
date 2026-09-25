// クライアント側のネットワーク情報を取得し、フォームの hidden 項目に設定する。
// Network Information API は Chrome/Edge/Android 系のみ対応（Safari/Firefox では空のまま送信される）。
// effectiveType は実測速度からの推定値で、Wi-Fi/モバイル回線の区別ではない。
(function () {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) return;
    const typeField = document.getElementById('net_type');
    const downlinkField = document.getElementById('net_downlink');
    if (typeField && connection.effectiveType) typeField.value = connection.effectiveType;
    if (downlinkField && typeof connection.downlink === 'number') downlinkField.value = String(connection.downlink);
})();
