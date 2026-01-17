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
    };
  };
}

// windowをWindowWithAPIとして扱う
const win = window as unknown as WindowWithAPI;

// パケットデータを保存する配列（IP一意のパケットのみ）
let packets: any[] = [];

// 既に表示したIPペアを記録するSet（送信元IP-宛先IPの組み合わせ）
const seenIPPairs = new Set<string>();

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

// 統計要素
const totalPacketsEl = document.getElementById('total-packets') as HTMLSpanElement;
const tcpCountEl = document.getElementById('tcp-count') as HTMLSpanElement;
const udpCountEl = document.getElementById('udp-count') as HTMLSpanElement;
const icmpCountEl = document.getElementById('icmp-count') as HTMLSpanElement;
const otherCountEl = document.getElementById('other-count') as HTMLSpanElement;

/**
 * 初期化処理
 */
async function init(): Promise<void> {
  console.log('[Renderer] 初期化開始');
  try {
    // パケット受信イベントのリスナーを登録
    console.log('[Renderer] パケット受信リスナーを登録');
    win.api.capture.onPacketCaptured((packet: any) => {
      // ログを完全にオフ（本番用）
      addPacket(packet);
    });

    // デバイス一覧を取得してドロップダウンに追加
    await loadDevices();

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
  seenIPPairs.clear(); // IPペアの記録もクリア
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
 * パケットを追加（新規IPペアのみ）
 */
function addPacket(packet: any): void {
  // 統計は全パケットでカウント
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

  // IPペアのキーを生成（送信元IP-宛先IP、ポートは無視）
  const ipPairKey = `${packet.sourceIP}-${packet.destIP}`;

  // 既に表示済みのIPペアならスキップ
  if (seenIPPairs.has(ipPairKey)) {
    return;
  }

  // 新規IPペアとして記録
  seenIPPairs.add(ipPairKey);
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

  row.innerHTML = `
    <td>${packet.id}</td>
    <td>${timeStr}</td>
    <td class="${protocolClass}">${packet.protocol}</td>
    <td>${packet.sourceIP}</td>
    <td>${packet.destIP}</td>
    <td>${packet.length}</td>
    <td>${packet.info}</td>
    <td><button class="detail-btn" data-packet='${JSON.stringify(packet)}'>詳細</button></td>
  `;

  // 詳細ボタンのイベントリスナーを追加
  const detailBtn = row.querySelector('.detail-btn');
  if (detailBtn) {
    detailBtn.addEventListener('click', () => {
      showPacketDetail(packet);
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

// 初期化を実行
init();
