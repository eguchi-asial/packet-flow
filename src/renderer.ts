/**
 * レンダラープロセス
 * UIの制御とパケット表示を担当
 */

// グローバルな型定義
interface WindowWithAPI extends Window {
  api: {
    version: NodeJS.ProcessVersions;
    capture: {
      getDevices: () => Promise<any[]>;
      startCapture: (deviceName?: string) => Promise<boolean>;
      stopCapture: () => Promise<boolean>;
      isCapturing: () => Promise<boolean>;
      onPacketCaptured: (callback: (packet: any) => void) => void;
      getLocalIP: () => Promise<string[]>;
    };
  };
}

// windowをWindowWithAPIとして扱う
const win = window as unknown as WindowWithAPI;

// パケットデータを保存する配列（全パケット）
let packets: any[] = [];

// 自分のローカルIPアドレス一覧
let localIPs: string[] = [];

// 統計情報
const stats = {
  total: 0,
  tcp: 0,
  udp: 0,
  icmp: 0,
  other: 0,
};

// DOM要素の取得
const deviceSelect = document.getElementById('device-select') as HTMLSelectElement;
const startBtn = document.getElementById('start-btn') as HTMLButtonElement;
const stopBtn = document.getElementById('stop-btn') as HTMLButtonElement;
const clearBtn = document.getElementById('clear-btn') as HTMLButtonElement;
const statusEl = document.getElementById('status') as HTMLDivElement;
const packetTbody = document.getElementById('packet-tbody') as HTMLTableSectionElement;
const detailModal = document.getElementById('detail-modal') as HTMLDivElement;
const modalCloseBtn = document.getElementById('modal-close-btn') as HTMLButtonElement;
const modalBody = document.getElementById('modal-body') as HTMLDivElement;
const aboutBtn = document.getElementById('about-btn') as HTMLButtonElement;
const aboutModal = document.getElementById('about-modal') as HTMLDivElement;
const aboutModalCloseBtn = document.getElementById('about-modal-close-btn') as HTMLButtonElement;
const stateModal = document.getElementById('state-modal') as HTMLDivElement;
const stateModalCloseBtn = document.getElementById('state-modal-close-btn') as HTMLButtonElement;
const stateExplanation = document.getElementById('state-explanation') as HTMLDivElement;

// 統計要素
const totalPacketsEl = document.getElementById('total-packets') as HTMLSpanElement;
const tcpCountEl = document.getElementById('tcp-count') as HTMLSpanElement;
const udpCountEl = document.getElementById('udp-count') as HTMLSpanElement;
const icmpCountEl = document.getElementById('icmp-count') as HTMLSpanElement;
const otherCountEl = document.getElementById('other-count') as HTMLSpanElement;

// 状態説明のマッピング
const stateExplanations: { [key: string]: string } = {
  // TCP フラグ
  'SYN': '<strong>SYN (Synchronize)</strong><br>TCP接続の開始を要求するフラグです。クライアントがサーバーに接続を確立しようとする際に送信されます。',
  'ACK': '<strong>ACK (Acknowledgment)</strong><br>データの受信確認を示すフラグです。相手から受け取ったデータを正常に受信したことを通知します。',
  'FIN': '<strong>FIN (Finish)</strong><br>TCP接続の終了を要求するフラグです。データの送信が完了し、接続を閉じる準備ができたことを示します。',
  'RST': '<strong>RST (Reset)</strong><br>TCP接続を強制的にリセットするフラグです。エラーや予期しない状況で接続を即座に終了する際に使用されます。',
  'PSH': '<strong>PSH (Push)</strong><br>データを即座にアプリケーションに渡すよう要求するフラグです。バッファリングせずにデータを処理する必要がある場合に使用されます。',
  'URG': '<strong>URG (Urgent)</strong><br>緊急データが含まれていることを示すフラグです。通常のデータより優先的に処理されます。',

  // TCP フラグの組み合わせ
  'SYN,ACK': '<strong>SYN+ACK</strong><br>TCP 3ウェイハンドシェイクの2番目のステップです。サーバーがクライアントからのSYNを受け取り、接続を承認する応答です。',
  'FIN,ACK': '<strong>FIN+ACK</strong><br>TCP接続の正常な終了プロセスの一部です。接続終了要求を確認しながら、自分も終了する準備ができていることを示します。',
  'PSH,ACK': '<strong>PSH+ACK</strong><br>データの即座の転送と、以前のデータの受信確認を同時に行います。HTTPリクエスト/レスポンスなどでよく見られます。',

  // TLS/SSL ハンドシェイク
  'Client Hello': '<strong>TLS Client Hello</strong><br>クライアントがサーバーにTLS/SSL接続を開始するメッセージです。サポートする暗号スイートやTLSバージョンなどを通知します。',
  'Server Hello': '<strong>TLS Server Hello</strong><br>サーバーがクライアントのHelloに応答するメッセージです。使用する暗号スイートやTLSバージョンを決定して通知します。',
  'Certificate': '<strong>TLS Certificate</strong><br>サーバーが自身の公開鍵証明書をクライアントに送信します。これによりサーバーの身元を証明します。',
  'Server Key Exchange': '<strong>TLS Server Key Exchange</strong><br>鍵交換のための追加情報をサーバーが送信します。DHE や ECDHE などの鍵交換方式で使用されます。',
  'Server Hello Done': '<strong>TLS Server Hello Done</strong><br>サーバーがハンドシェイクの初期段階を完了したことを通知します。',
  'Client Key Exchange': '<strong>TLS Client Key Exchange</strong><br>クライアントが鍵交換情報を送信します。この情報から暗号化に使用する共通鍵が生成されます。',
  'Change Cipher Spec': '<strong>TLS Change Cipher Spec</strong><br>以降のメッセージが暗号化されることを通知します。ハンドシェイクの最終段階で送信されます。',
  'Finished': '<strong>TLS Finished</strong><br>TLSハンドシェイクの完了を示します。このメッセージ以降、暗号化された通信が開始されます。',
  'Application Data': '<strong>TLS Application Data</strong><br>暗号化されたアプリケーションデータ（HTTPSの本文など）が送信されています。',
  'Alert': '<strong>TLS Alert</strong><br>TLS通信でエラーや警告が発生したことを通知します。接続の終了や問題の報告に使用されます。',

  // HTTP(S) データ転送
  'HTTP(S) Data Transfer': '<strong>HTTP(S) データ転送</strong><br>この接続でHTTP/HTTPSデータ転送が開始されたことを示します。<br>実際には数百個の暗号化されたパケット（Application Data）が送信されますが、ノイズを避けるため最初の1回のみ表示しています。<br><em>※ Change Cipher Spec後にこの状態が現れれば、HTTP通信が行われています。</em>',

  // DNS
  'DNS Query': '<strong>DNS クエリ（問い合わせ）</strong><br>ドメイン名（例: google.com）からIPアドレスを解決するための問い合わせパケットです。<br>UDP port 53を使用してDNSサーバー（通常 8.8.8.8 や 1.1.1.1）に送信されます。<br><em>※ 最近のブラウザはDNS over HTTPS (DoH)を使用するため、従来のDNSクエリが見えない場合があります。</em>',
  'DNS Response': '<strong>DNS レスポンス（応答）</strong><br>DNSサーバーからの応答パケットです。<br>クエリで要求されたドメイン名に対応するIPアドレス（例: google.com = 142.250.207.46）が含まれます。<br>この情報を使って、以降のHTTPS通信でドメイン名を表示できます。',

  // HTTP
  'HTTP Request': '<strong>HTTP リクエスト</strong><br>暗号化されていないHTTP通信のリクエストです。GET、POST等のメソッドとURLが含まれます。<br><em>※ セキュリティ上、HTTPSの使用が推奨されます。</em>',
  'HTTP Response': '<strong>HTTP レスポンス</strong><br>HTTPサーバーからの応答です。ステータスコード（200 OK、404 Not Found等）とコンテンツが含まれます。',
};

/**
 * 初期化処理
 */
async function init(): Promise<void> {
  console.log('[Renderer] 初期化開始');
  try {
    // パケット受信イベントのリスナーを登録
    console.log('[Renderer] パケット受信リスナーを登録');
    win.api.capture.onPacketCaptured((packet: any) => {
      // デバッグ: domainNameがあるパケットをログ出力
      if (packet.domainName) {
        console.log('[Renderer] ドメイン名付きパケット受信:', packet.domainName, packet);
      }
      addPacket(packet);
    });

    // デバイス一覧を取得してドロップダウンに追加
    await loadDevices();

    // 自分のローカルIPアドレスを取得
    localIPs = await win.api.capture.getLocalIP();
    console.log('[Renderer] ローカルIPアドレス取得:', localIPs);

    console.log('[Renderer] 初期化完了');
  } catch (error) {
    console.error('[Renderer] 初期化エラー:', error);
    alert('初期化に失敗しました: ' + error);
  }
}

/**
 * デバイス一覧を読み込んでドロップダウンに表示
 */
async function loadDevices(): Promise<void> {
  try {
    const devices = await win.api.capture.getDevices();
    console.log('[Renderer] デバイス一覧取得:', devices);

    deviceSelect.innerHTML = '';

    if (devices.length === 0) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'デバイスが見つかりません';
      deviceSelect.appendChild(option);
      startBtn.disabled = true;
      return;
    }

    devices.forEach((device: any) => {
      const option = document.createElement('option');
      option.value = device.name;
      option.textContent = device.displayName || device.name;
      deviceSelect.appendChild(option);
    });

    startBtn.disabled = false;
  } catch (error) {
    console.error('[Renderer] デバイス読み込みエラー:', error);
    deviceSelect.innerHTML = '<option value="">デバイス読み込みエラー</option>';
    startBtn.disabled = true;
  }
}

/**
 * キャプチャを開始（選択されたデバイスを使用）
 */
async function startCapture(): Promise<void> {
  console.log('[Renderer] キャプチャ開始ボタンがクリックされました');

  const selectedDevice = deviceSelect.value;
  if (!selectedDevice) {
    alert('デバイスを選択してください');
    return;
  }

  try {
    console.log('[Renderer] キャプチャ開始をリクエスト中（デバイス:', selectedDevice, ')...');
    const result = await win.api.capture.startCapture(selectedDevice);
    console.log('[Renderer] キャプチャ開始結果:', result);
    updateUIState(true);
  } catch (error) {
    console.error('[Renderer] キャプチャ開始エラー:', error);
    alert('キャプチャの開始に失敗しました。\n管理者権限で実行してください。\n\nエラー: ' + error);
  }
}

/**
 * キャプチャを停止
 */
async function stopCapture(): Promise<void> {
  try {
    await win.api.capture.stopCapture();
    updateUIState(false);
  } catch (error) {
    console.error('キャプチャ停止エラー:', error);
    alert('キャプチャの停止に失敗しました: ' + error);
  }
}

/**
 * パケットリストをクリア
 */
function clearPackets(): void {
  packets = [];
  stats.total = 0;
  stats.tcp = 0;
  stats.udp = 0;
  stats.icmp = 0;
  stats.other = 0;

  updateStatsDisplay();
  renderPackets();
}

/**
 * UIの状態を更新
 */
function updateUIState(isCapturing: boolean): void {
  if (isCapturing) {
    deviceSelect.disabled = true;
    startBtn.disabled = true;
    stopBtn.disabled = false;
    statusEl.textContent = 'キャプチャ中...';
    statusEl.classList.add('capturing');
  } else {
    deviceSelect.disabled = false;
    startBtn.disabled = false;
    stopBtn.disabled = true;
    statusEl.textContent = '停止中';
    statusEl.classList.remove('capturing');
  }
}

/**
 * パケットを追加（全パケット）
 */
function addPacket(packet: any): void {
  // 統計をカウント
  stats.total++;

  switch (packet.protocol.toUpperCase()) {
    case 'TCP':
      stats.tcp++;
      break;
    case 'UDP':
      stats.udp++;
      break;
    case 'ICMP':
      stats.icmp++;
      break;
    default:
      stats.other++;
      break;
  }

  updateStatsDisplay();

  // 全パケットを配列に追加
  packets.push(packet);

  // パケットが多すぎる場合は古いものを削除（最大10000件）
  if (packets.length > 10000) {
    packets.shift();
  }

  // テーブルに行を追加
  addPacketRow(packet);
}

/**
 * 統計表示を更新
 */
function updateStatsDisplay(): void {
  totalPacketsEl.textContent = stats.total.toString();
  tcpCountEl.textContent = stats.tcp.toString();
  udpCountEl.textContent = stats.udp.toString();
  icmpCountEl.textContent = stats.icmp.toString();
  otherCountEl.textContent = stats.other.toString();
}

/**
 * パケット行を追加
 */
function addPacketRow(packet: any): void {
  // 空の状態メッセージを削除
  if (packetTbody.querySelector('.empty-state')) {
    packetTbody.innerHTML = '';
  }

  const row = document.createElement('tr');

  // プロトコルに応じたクラスを設定
  const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;

  // 時刻をフォーマット
  const timestamp = new Date(packet.timestamp);
  const timeStr = timestamp.toLocaleTimeString('ja-JP', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3
  });

  // ドメイン名の表示（あれば）
  const domainDisplay = packet.domainName
    ? `<span style="color: #4ec9b0; font-weight: 500;">${packet.domainName}</span>`
    : '';

  // パケット状態の表示（あれば）
  const stateDisplay = packet.packetState
    ? `<span class="state-link" style="color: #dcdcaa; font-size: 0.85em; cursor: pointer; text-decoration: underline;" data-state="${packet.packetState}">${packet.packetState}</span>`
    : '-';

  // 自分のIPアドレスかどうかを判定
  const isMySourceIP = localIPs.includes(packet.sourceIP);
  const isMyDestIP = localIPs.includes(packet.destIP);

  // 自分のIPの場合、クラスを追加
  const sourceIPClass = isMySourceIP ? 'my-ip' : '';
  const destIPClass = isMyDestIP ? 'my-ip' : '';

  row.innerHTML = `
    <td>${packet.id}</td>
    <td>${timeStr}</td>
    <td class="${protocolClass}">${packet.protocol}</td>
    <td>${stateDisplay}</td>
    <td class="${sourceIPClass}">${packet.sourceIP}</td>
    <td class="${destIPClass}">${packet.destIP}</td>
    <td>${packet.length}</td>
    <td>${domainDisplay ? domainDisplay + '<br>' : ''}${packet.info}</td>
    <td><button class="detail-btn" data-packet='${JSON.stringify(packet)}'>詳細</button></td>
  `;

  // 詳細ボタンのイベントリスナーを追加
  const detailBtn = row.querySelector('.detail-btn');
  if (detailBtn) {
    detailBtn.addEventListener('click', () => {
      showPacketDetail(packet);
    });
  }

  // 状態リンクのイベントリスナーを追加
  const stateLink = row.querySelector('.state-link');
  if (stateLink) {
    stateLink.addEventListener('click', () => {
      const state = stateLink.getAttribute('data-state');
      if (state) {
        showStateExplanation(state);
      }
    });
  }

  packetTbody.appendChild(row);

  // 自動スクロール
  const container = document.querySelector('.packet-table-container');
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

/**
 * パケットを再描画
 */
function renderPackets(): void {
  if (packets.length === 0) {
    packetTbody.innerHTML = `
      <tr>
        <td colspan="8">
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
              <path d="M2 17l10 5 10-5M2 12l10 5 10-5"></path>
            </svg>
            <p>キャプチャを開始してください</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  packetTbody.innerHTML = '';
  packets.forEach(packet => addPacketRow(packet));
}

/**
 * パケット詳細情報を表示
 */
async function showPacketDetail(packet: any): Promise<void> {
  // モーダルを表示
  detailModal.classList.add('active');
  modalBody.innerHTML = '<div class="loading">IPアドレス情報を取得中...</div>';

  try {
    // ipinfo.io APIで宛先IPの詳細情報を取得
    const response = await fetch(`https://ipinfo.io/${packet.destIP}/json`);
    const ipInfo = await response.json();

    // プロトコル情報を解析
    const protocolInfo = analyzeProtocol(packet);

    // ドメイン名の行を作成（あれば）
    const domainRow = packet.domainName ? `
        <div class="detail-row">
          <div class="detail-label">ドメイン名</div>
          <div class="detail-value" style="color: #4ec9b0; font-weight: 600;">${packet.domainName}</div>
        </div>
    ` : '';

    // パケット状態の行を作成（あれば）
    const stateRow = packet.packetState ? `
        <div class="detail-row">
          <div class="detail-label">パケット状態</div>
          <div class="detail-value" style="color: #dcdcaa; font-weight: 600;">${packet.packetState}</div>
        </div>
    ` : '';

    // 詳細情報を表示
    modalBody.innerHTML = `
      <div class="detail-section">
        <h3>基本情報</h3>
        <div class="detail-row">
          <div class="detail-label">パケットNo.</div>
          <div class="detail-value">${packet.id}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">時刻</div>
          <div class="detail-value">${new Date(packet.timestamp).toLocaleString('ja-JP')}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">プロトコル</div>
          <div class="detail-value">${packet.protocol}</div>
        </div>
        ${stateRow}
        ${domainRow}
        <div class="detail-row">
          <div class="detail-label">送信元IP</div>
          <div class="detail-value">${packet.sourceIP}${packet.sourcePort ? ':' + packet.sourcePort : ''}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">宛先IP</div>
          <div class="detail-value">${packet.destIP}${packet.destPort ? ':' + packet.destPort : ''}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">パケット長</div>
          <div class="detail-value">${packet.length} bytes</div>
        </div>
      </div>

      <div class="detail-section">
        <h3>宛先IP詳細情報</h3>
        <div class="detail-row">
          <div class="detail-label">組織</div>
          <div class="detail-value">${ipInfo.org || '不明'}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">国</div>
          <div class="detail-value">${ipInfo.country || '不明'} ${ipInfo.country === 'JP' ? '🇯🇵' : ipInfo.country === 'US' ? '🇺🇸' : ipInfo.country === 'CN' ? '🇨🇳' : ''}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">地域</div>
          <div class="detail-value">${ipInfo.region || '不明'}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">都市</div>
          <div class="detail-value">${ipInfo.city || '不明'}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">ホスト名</div>
          <div class="detail-value">${ipInfo.hostname || '不明'}</div>
        </div>
      </div>

      <div class="detail-section">
        <h3>通信内容の推測</h3>
        <div class="detail-row">
          <div class="detail-label">サービス</div>
          <div class="detail-value">${protocolInfo.service}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">用途</div>
          <div class="detail-value">${protocolInfo.purpose}</div>
        </div>
        <div class="detail-row">
          <div class="detail-label">セキュリティ</div>
          <div class="detail-value">${protocolInfo.security}</div>
        </div>
      </div>
    `;
  } catch (error) {
    modalBody.innerHTML = `
      <div class="detail-section">
        <h3>エラー</h3>
        <div class="detail-row">
          <div class="detail-value" style="color: #e81123;">
            IP情報の取得に失敗しました。<br>
            インターネット接続を確認してください。<br><br>
            エラー: ${error}
          </div>
        </div>
      </div>
    `;
  }
}

/**
 * 状態説明を表示
 */
function showStateExplanation(state: string): void {
  // 状態の説明を取得
  let explanation = stateExplanations[state];

  // マッピングにない場合、個別のフラグを分解して説明を組み立てる
  if (!explanation && state.includes(',')) {
    const flags = state.split(',').map(f => f.trim());
    const foundExplanations = flags
      .map(flag => {
        const exp = stateExplanations[flag];
        return exp ? `<div style="margin-bottom: 1rem;">${exp}</div>` : null;
      })
      .filter(exp => exp !== null);

    if (foundExplanations.length > 0) {
      explanation = foundExplanations.join('');
    }
  }

  // 説明がない場合のデフォルト
  if (!explanation) {
    explanation = `<strong>${state}</strong><br>この状態の詳細な説明はまだ登録されていません。`;
  }

  // モーダルに表示
  stateExplanation.innerHTML = `
    <div style="color: #d4d4d4; line-height: 1.8;">
      ${explanation}
    </div>
  `;

  // モーダルを表示
  stateModal.style.display = 'block';
}

/**
 * プロトコル情報を解析
 */
function analyzeProtocol(packet: any): { service: string; purpose: string; security: string } {
  const port = packet.destPort || 0;
  const protocol = packet.protocol;

  // ポート番号から推測
  if (protocol === 'TCP') {
    switch (port) {
      case 443:
        return {
          service: 'HTTPS（暗号化Web通信）',
          purpose: 'Webサイト閲覧、API通信、クラウドサービス',
          security: '✅ 暗号化されており安全'
        };
      case 80:
        return {
          service: 'HTTP（非暗号化Web通信）',
          purpose: 'Webサイト閲覧',
          security: '⚠️ 暗号化されていません'
        };
      case 143:
        return {
          service: 'IMAP（メール受信）',
          purpose: 'メールクライアントからメールサーバーへの接続',
          security: '❌ 暗号化なし！IMAPS（993）に変更推奨'
        };
      case 993:
        return {
          service: 'IMAPS（暗号化メール受信）',
          purpose: 'メールクライアントからメールサーバーへの安全な接続',
          security: '✅ 暗号化されており安全'
        };
      case 22:
        return {
          service: 'SSH（セキュアシェル）',
          purpose: 'リモートサーバー管理',
          security: '✅ 暗号化されており安全'
        };
      case 3389:
        return {
          service: 'RDP（リモートデスクトップ）',
          purpose: 'Windowsリモートデスクトップ接続',
          security: '⚠️ VPN経由での使用を推奨'
        };
      default:
        return {
          service: `TCP ポート ${port}`,
          purpose: '不明な通信',
          security: 'ポート番号から判断できません'
        };
    }
  } else if (protocol === 'UDP') {
    switch (port) {
      case 443:
        return {
          service: 'QUIC（HTTP/3）',
          purpose: 'Google等の高速Web通信（YouTube, Gmail等）',
          security: '✅ 暗号化されており安全'
        };
      case 53:
        return {
          service: 'DNS（ドメイン名前解決）',
          purpose: 'ドメイン名をIPアドレスに変換',
          security: '⚠️ 通常は暗号化なし（DoH/DoTなら安全）'
        };
      case 5353:
        return {
          service: 'mDNS（ローカルデバイス検出）',
          purpose: 'AirPrint、AirPlay、共有フォルダの検出',
          security: '✅ ローカルネットワーク内のみ'
        };
      case 137:
        return {
          service: 'NetBIOS（Windows共有）',
          purpose: 'Windows共有フォルダ・プリンター検出',
          security: '✅ ローカルネットワーク内のみ'
        };
      default:
        return {
          service: `UDP ポート ${port}`,
          purpose: '不明な通信',
          security: 'ポート番号から判断できません'
        };
    }
  } else if (protocol === 'ICMP') {
    return {
      service: 'ICMP（ネットワーク診断）',
      purpose: 'ping、traceroute等のネットワーク診断ツール',
      security: '✅ 正常なネットワーク管理通信'
    };
  }

  return {
    service: '不明',
    purpose: '不明',
    security: '不明'
  };
}

// イベントリスナーを設定
startBtn.addEventListener('click', startCapture);
stopBtn.addEventListener('click', stopCapture);
clearBtn.addEventListener('click', clearPackets);

// 詳細モーダル
modalCloseBtn.addEventListener('click', () => {
  detailModal.classList.remove('active');
});

// モーダル背景クリックで閉じる
detailModal.addEventListener('click', (e) => {
  if (e.target === detailModal) {
    detailModal.classList.remove('active');
  }
});

// このアプリについてモーダル
aboutBtn.addEventListener('click', () => {
  aboutModal.classList.add('active');
});

aboutModalCloseBtn.addEventListener('click', () => {
  aboutModal.classList.remove('active');
});

// モーダル背景クリックで閉じる
aboutModal.addEventListener('click', (e) => {
  if (e.target === aboutModal) {
    aboutModal.classList.remove('active');
  }
});

// 状態説明モーダル
stateModalCloseBtn.addEventListener('click', () => {
  stateModal.style.display = 'none';
});

// モーダル背景クリックで閉じる
stateModal.addEventListener('click', (e) => {
  if (e.target === stateModal) {
    stateModal.style.display = 'none';
  }
});

// 初期化を実行
init();
