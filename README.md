# PacketFlow

macOSとWindowsのネットワークインターフェースを流れるパケットをリアルタイムでキャプチャし、視覚的に表示するElectronベースのクロスプラットフォームデスクトップアプリケーション。

## 主な機能

- 🔍 **リアルタイムパケットキャプチャ** - 選択したネットワークデバイスからアプリケーション層のパケットを即座にキャプチャ
- 💻 **クロスプラットフォーム対応** - macOSとWindows両方で動作
- 🎛️ **デバイス選択機能** - ドロップダウンから使いやすい表示名でデバイスを選択
- 🔐 **TLS/SSL状態解析** - Client Hello、Server Hello、Certificate等のTLSハンドシェイク状態を可視化
- 🌐 **DNS解析とキャッシュ** - DNSクエリ/レスポンスを解析し、IPアドレスとドメイン名を紐付け
- 🎯 **インテリジェントフィルタリング** - 重要なパケット（TLS、DNS、ハンドシェイク）のみを表示
- 📊 **詳細情報取得** - ipinfo.io APIを使用してIP情報（組織、国、地域、都市）を取得
- 📈 **リアルタイム統計** - TCP/UDP/ICMP/その他のプロトコル別カウント表示
- 🎨 **VSCode風ダークテーマ** - 見やすく洗練されたUI
- ℹ️ **状態説明ポップアップ** - 各パケット状態の詳しい説明を表示

## 技術スタック

- **Electron** v32.3.3 - クロスプラットフォームデスクトップアプリフレームワーク
- **TypeScript** v5.9.3 - 型安全な開発
- **libpcap / Npcap (cap)** v0.2.1 - ネイティブパケットキャプチャライブラリ
  - macOS: libpcap経由でキャプチャ
  - Windows: Npcap経由でキャプチャ
- **ipinfo.io API** - IP地理情報・組織情報取得

## システム要件

### 共通
- Node.js 18.x以上
- **管理者権限** (パケットキャプチャに必要)

### macOS
- macOS 10.15以上
- libpcap (OS標準搭載)

### Windows
- Windows 10/11 (32-bit / 64-bit両方対応)
- **Npcap** v1.70以上 ([https://npcap.com/](https://npcap.com/)からダウンロード・インストール)
  - インストール時に「Install Npcap in WinPcap API-compatible Mode」をチェック

## インストール

```bash
# リポジトリをクローン
git clone git@github.com:eguchi-asial/packet-flow.git
cd packet-flow

# 依存関係をインストール
npm install

# ネイティブモジュールをリビルド（Electron用）
npx electron-rebuild
```

## 使い方

### macOS

**開発モード**:
```bash
# 管理者権限で起動（DevTools自動オープン）
sudo npm run dev
```

**本番モード**:
```bash
# 管理者権限で起動
sudo npm start
```

### Windows

**開発モード**:
```powershell
# 管理者権限でPowerShellまたはコマンドプロンプトを開いて実行
npm run dev
```

**本番モード**:
```powershell
# 管理者権限で実行
npm start
```

**注意**: Windowsでは、コマンドプロンプトまたはPowerShellを「管理者として実行」で開いてから上記コマンドを実行してください。

### ビルドのみ

```bash
npm run build
```

## 機能詳細

### パケットキャプチャ

- **対応プロトコル**: IPv4（TCP, UDP, ICMP, その他）
- **BPFフィルタ**: `tcp portrange 80-8080 or udp port 53`
  - HTTP/HTTPS（ポート80-8080）
  - DNS（ポート53）
  - カーネルレベルで不要なパケットをフィルタリング
- **アプリケーション層フィルタ**: 重要なパケットのみをUIに表示
  - TLS/SSL状態（Client Hello、Server Hello、Certificate等）
  - HTTP(S) Data Transfer（接続ごとに最初の1回のみ）
  - DNS通信（Query、Response）
  - TCPハンドシェイク（SYN、SYN+ACK、FIN、RST）
  - ドメイン名が判明しているパケット（DNSキャッシュ経由）
  - 意味のない単純なACKやPSH+ACKは除外
- **バッファサイズ**: 10MB（高速なパケット処理に対応）

### TLS/SSL解析

PacketFlowは、HTTPS通信のTLSハンドシェイクを詳細に解析します。

**検出できる状態**:
- **Client Hello** - クライアントがTLS接続を開始
- **Server Hello** - サーバーが暗号スイートを選択して応答
- **Certificate** - サーバー証明書の送信
- **Server Key Exchange** - 鍵交換情報の送信
- **Client Key Exchange** - クライアント側の鍵交換
- **Change Cipher Spec** - 暗号化開始の通知
- **Finished** - ハンドシェイク完了
- **HTTP(S) Data Transfer** - HTTP/HTTPSデータ転送開始（接続ごとに最初の1回のみ表示）
- **Alert** - エラーや警告

**SNI（Server Name Indication）抽出**:
- TLS Client HelloからSNIを抽出してドメイン名を取得
- **制限事項**: 大きなClient Helloメッセージ（1500バイト超）はTCPで分割されるため、SNI抽出に失敗します

**Application Dataの扱い**:
- 暗号化されたApplication Dataパケットは通常数百個送信されますが、UIのノイズを避けるため最初の1回のみ「HTTP(S) Data Transfer」として表示
- 2回目以降のApplication Dataパケットは自動的にスキップされます

### DNS解析とキャッシュ

**DNS通信の解析**:
- **DNS Query** - ドメイン名の問い合わせを検出
- **DNS Response** - 応答からドメイン名とIPアドレスを抽出
- **Aレコード解析** - IPv4アドレスを取得してキャッシュに保存

**DNSキャッシュ機能**:
- DNS応答で取得したIP→ドメイン名のマッピングを保存
- 以降のHTTPS通信でSNI抽出に失敗しても、キャッシュからドメイン名を表示
- メモリ効率的なMap構造（約50KB/1000エントリ）

**キャッシュによるドメイン名表示**:
- DNSキャッシュに登録されているIPアドレス（ポート443）との通信は、パケット状態に関わらずドメイン名が表示されます
- 例: ACKパケットでも、宛先IPが `192.28.153.119` でキャッシュに `713-xsc-918.mktoresp.com` が登録されていれば、ドメイン名が表示されます
- これにより、TLS Client Hello以外のパケットでもドメイン名を確認できます

**制限事項**:
- **DNS over HTTPS (DoH)**: 暗号化されたDNS通信は解析できません
- **従来のDNS (UDP port 53)** のみ対応
- 最近のブラウザ（Chrome、Firefox等）はDoHを使用するため、ドメイン名が取得できない場合があります

### 詳細情報の取得

各パケット行の「詳細」ボタンを押下すると、以下の情報を取得・表示します。

**取得する情報**:
- 基本情報（パケット番号、時刻、プロトコル、IP、ポート、長さ）
- IP詳細情報（組織、国、地域、都市、ホスト名）
- 情報取得元: ipinfo.io API（WHOIS、GeoIP、PTRレコードを統合）

**通信内容の推測**:
- サービス識別（ポート番号からHTTPS、DNS、QUIC等を特定）
- 用途の説明（Web閲覧、メール、リモート管理等）
- セキュリティ評価（暗号化の有無を判定）

**解析例**:
- `52.69.186.44:443 Client Hello` → AWS東京リージョンとのHTTPS接続開始
- `8.8.8.8:53 DNS Response` → GoogleパブリックDNSからの応答

### 状態説明ポップアップ

パケット状態列の「詳細」ボタンをクリックすると、状態の詳しい説明がポップアップ表示されます。

**説明が表示される状態**:
- TCP フラグ（SYN、ACK、FIN、RST、PSH、URG、SYN+ACK等）
- TLS/SSL ハンドシェイク（Client Hello、Server Hello、Certificate等）
- DNS 通信（DNS Query、DNS Response）
- HTTP 通信（HTTP Request、HTTP Response）

**説明内容**:
- 状態の意味と役割
- 通信フローにおける位置付け
- セキュリティや性能に関する注意事項

### パケット解析の仕組み

1. **Ethernetヘッダー** - 14バイトをスキップ
2. **IPヘッダー** - バージョン、ヘッダー長、プロトコル番号、送信元・宛先IPを抽出
3. **TCP/UDPヘッダー** - 送信元・宛先ポート番号をビッグエンディアンで読み取り
4. **プロトコル判定** - IPヘッダーのプロトコルフィールド（6=TCP, 17=UDP, 1=ICMP）
5. **アプリケーション層解析**:
   - **ポート443**: TLS状態解析、SNI抽出、DNSキャッシュ参照
   - **ポート53**: DNS解析、キャッシュ保存
   - **ポート80-8080**: HTTP通信

### TCP分割とSNI抽出の制限

**問題**:
現代のTLS通信では、Client Helloメッセージが多くの拡張機能を含むため大きくなり（1500バイト以上）、MTU制限によりTCPセグメントに分割されます。

**影響**:
- LibPCAPは個別のパケットをキャプチャ（TCP再構成なし）
- 分割された最初のセグメントだけではSNI全体を読み取れない
- SNI抽出に失敗する

**対策**:
1. TLSレコード長を検証して分割パケットを検出
2. 分割パケットの場合はSNI抽出をスキップ
3. DNSキャッシュからドメイン名を取得（従来のDNS使用時のみ）

**ログ例**:
```
[PacketCapture:macOS] TLSレコード長: 1783 パケット全体の必要長: 1854 実際のlength: 1468
[PacketCapture:macOS] SNI失敗: パケットが分割されている (TLS Client Helloが複数パケットにまたがっている)
```

## プロジェクト構成

```
PacketFlow/
├── src/
│   ├── main.ts                              # Electronメインプロセス
│   ├── preload.ts                           # プリロードスクリプト（IPC橋渡し）
│   ├── renderer.ts                          # レンダラープロセス（UI制御、状態説明）
│   └── packet-capture/
│       ├── index.ts                         # パケットキャプチャファクトリー
│       ├── types.ts                         # 共通インターフェース
│       ├── cap.d.ts                         # capモジュールの型定義
│       ├── macos/
│       │   └── packet-capture-macos.ts      # macOS実装（libpcap、TLS/DNS解析）
│       └── windows/
│           └── packet-capture-windows.ts    # Windows実装（Npcap、TLS/DNS解析）
├── index.html            # UI（VSCode風ダークテーマ、状態説明モーダル）
├── package.json
├── tsconfig.json
└── README.md
```

### アーキテクチャの特徴

PacketFlowはプラットフォーム別実装を完全に分離した設計を採用しています:

- **ファクトリーパターン**: `createPacketCaptureManager()`が実行時プラットフォームを自動検出
- **共通インターフェース**: `IPacketCaptureManager`で両プラットフォームの動作を統一
- **独立したモジュール**: macOSとWindowsの実装は別ファイルで管理、相互干渉なし
- **デバイス表示名変換**: プラットフォーム固有のデバイス名を人間が読める形式に自動変換
  - macOS: `en0` → `Wi-Fi (192.168.1.10)`
  - Windows: `\Device\NPF_{GUID}` → `Intel(R) Wi-Fi 6 AX201 160MHz (192.168.1.10)`
- **DNSキャッシュ**: Map<string, string>によるメモリ効率的なIP→ドメイン名マッピング
- **インテリジェントフィルタリング**: BPF（カーネル）とアプリケーション層の2段階フィルタ

## セキュリティ

- **contextBridge**: レンダラープロセスとメインプロセス間の安全な通信
- **contextIsolation**: レンダラープロセスの分離
- **nodeIntegration: false**: Node.js APIへの直接アクセスを無効化
- **Content Security Policy**: XSS攻撃からの保護

## トラブルシューティング

### キャプチャが開始できない

**macOS**:
```bash
# 管理者権限で実行されているか確認
sudo npm run dev
```

**Windows**:
1. Npcapがインストールされているか確認（[https://npcap.com/](https://npcap.com/)）
2. コマンドプロンプト/PowerShellを「管理者として実行」で開いているか確認
3. Windowsファイアウォールがブロックしていないか確認

### ネイティブモジュールエラー

```bash
# capモジュールを再ビルド
npx electron-rebuild
```

### デバイスが見つからない

**macOS**:
```bash
# ネットワークインターフェースを確認
ifconfig
```

**Windows**:
```powershell
# ネットワークアダプタを確認
ipconfig /all
```

### Windows: Npcapインストール後も動作しない

1. Npcapインストール時に「Install Npcap in WinPcap API-compatible Mode」がチェックされているか確認
2. Npcapを再インストール（アンインストール後に再度インストール）
3. アプリを完全に終了してから再起動

### ドメイン名が表示されない

**原因**:
1. **DNS over HTTPS (DoH)使用**: 最近のブラウザはDoHを使用するため、従来のDNS（port 53）パケットが見えません
2. **Client Hello分割**: TLSメッセージが大きすぎてTCPセグメントに分割され、SNI抽出に失敗します

**対策**:
- ブラウザのDoHを無効化（Chrome: `chrome://settings/security`、Firefox: `about:preferences#privacy`）
- 従来のDNSを使用するアプリケーションでテスト
- DNSキャッシュが構築されるまで待つ（初回DNS応答後）

**ログ確認**:
```
# DNSキャッシュが機能している場合
[PacketCapture:macOS] DNSキャッシュ保存: example.com = 93.184.216.34
[PacketCapture:macOS] ✅ DNSキャッシュからドメイン名取得: example.com

# TCP分割が発生している場合
[PacketCapture:macOS] SNI失敗: パケットが分割されている
```

## パフォーマンス最適化

### BPFフィルタによる最適化
- カーネルレベルでポート80-8080、53のみキャプチャ
- 不要なパケット（ICMP Echo、ARP等）を早期除外
- CPU使用率とメモリ使用量を大幅削減

### アプリケーション層フィルタリング
- 重要なパケット（TLS、DNS、ハンドシェイク）のみUI表示
- ACK、PSH+ACK、Application Dataは表示しない
- UIの応答性とスクロール性能が向上

### メモリ効率
- DNSキャッシュ: 約50KB/1000エントリ
- TCP再構成なし: セグメントバッファ不要
- パケットIDカウンターのみ保持

## 実装例: Claude.ai新規チャット時の通信

PacketFlowで「新規チャット」ボタンを押した時のキャプチャ例:

```
11:49:19.265  SYN           → 3.209.47.223:443 (AWS米国)
11:49:19.322  SYN           → 34.54.194.141:443 (GCP)
11:49:19.418  SYN,ACK       ← GCP (96ms)
11:49:19.418  Client Hello  → GCP
11:49:19.498  SYN,ACK       ← AWS (233ms、遅延大)
11:49:19.507  Server Hello  ← GCP
11:49:19.507  Change Cipher Spec → GCP (暗号化開始)
```

**解析結果**:
- GCP: API通信（低遅延: 96ms）
- AWS: 静的コンテンツCDN（高遅延: 233ms、米国経由）
- 合計3つのHTTPS接続を並列確立

## ライセンス

ISC

## 作者

Created with ❤️ using Electron and TypeScript

## 貢献

Issue報告やPull Requestを歓迎します！

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
