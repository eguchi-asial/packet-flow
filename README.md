# PacketFlow

macOSとWindowsのネットワークインターフェースを流れるIPv4パケットをリアルタイムでキャプチャし、視覚的に表示するElectronベースのクロスプラットフォームデスクトップアプリケーション。

![PacketFlow Screenshot](https://via.placeholder.com/800x500.png?text=PacketFlow+Screenshot)

## 主な機能

- 🔍 **リアルタイムパケットキャプチャ** - 選択したネットワークデバイスからIPv4パケットを即座にキャプチャ
- 💻 **クロスプラットフォーム対応** - macOSとWindows両方で動作
- 🎛️ **デバイス選択機能** - ドロップダウンから使いやすい表示名でデバイスを選択
- 📊 **一意なIP表示** - 送信元IP-宛先IPペアで重複を排除し、新規通信のみ表示
- 🌍 **詳細情報取得** - ipinfo.io APIを使用してIP情報（組織、国、地域、都市）を取得
- 🔐 **プロトコル解析** - ポート番号からサービスを識別し、セキュリティ評価を実施
- 📈 **リアルタイム統計** - TCP/UDP/ICMP/その他のプロトコル別カウント表示
- 🎨 **VSCode風ダークテーマ** - 見やすく洗練されたUI

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

- **対応プロトコル**: IPv4のみ（TCP, UDP, ICMP, その他）
- **フィルタリング**: BPF（Berkeley Packet Filter）で`ip`フィルタを適用
- **バッファサイズ**: 10MB（高速なパケット処理に対応）

### IP一意化の仕組み

PacketFlowは、**送信元IP-宛先IPの組み合わせ**を一意のキーとして管理し、同じIPペアの通信は初回のみ表示します。

- **判定基準**: 送信元IP + 宛先IP（ポート番号は無視）
- **実装方法**: JavaScriptのSetオブジェクトで既出IPペアを記録
- **統計情報**: 全パケット数をカウント、一覧には新規IPペアのみ追加
- **上限**: 最大10,000件まで保存（古いものから自動削除）

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
- `52.69.186.44:443` → AWS東京リージョンとのHTTPS通信
- `224.0.0.251:5353` → mDNS（AirPrint、AirPlay検出）

### パケット解析の仕組み

1. **Ethernetヘッダー** - 14バイトをスキップ
2. **IPヘッダー** - バージョン、ヘッダー長、プロトコル番号、送信元・宛先IPを抽出
3. **TCP/UDPヘッダー** - 送信元・宛先ポート番号をビッグエンディアンで読み取り
4. **プロトコル判定** - IPヘッダーのプロトコルフィールド（6=TCP, 17=UDP, 1=ICMP）

## プロジェクト構成

```
PacketFlow/
├── src/
│   ├── main.ts                              # Electronメインプロセス
│   ├── preload.ts                           # プリロードスクリプト（IPC橋渡し）
│   ├── renderer.ts                          # レンダラープロセス（UI制御）
│   └── packet-capture/
│       ├── index.ts                         # パケットキャプチャファクトリー
│       ├── types.ts                         # 共通インターフェース
│       ├── cap.d.ts                         # capモジュールの型定義
│       ├── macos/
│       │   └── packet-capture-macos.ts      # macOS実装（libpcap）
│       └── windows/
│           └── packet-capture-windows.ts    # Windows実装（Npcap）
├── index.html            # UI（VSCode風ダークテーマ）
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

## ライセンス

ISC

## 作者

Created with ❤️ using Electron and TypeScript

## 貢献

Issue報告やPull Requestを歓迎します！

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
