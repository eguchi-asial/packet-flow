# PacketFlow

macOSのネットワークインターフェース（en0）を流れるIPv4パケットをリアルタイムでキャプチャし、視覚的に表示するElectronベースのデスクトップアプリケーション。

![PacketFlow Screenshot](https://via.placeholder.com/800x500.png?text=PacketFlow+Screenshot)

## 主な機能

- 🔍 **リアルタイムパケットキャプチャ** - en0デバイスからIPv4パケットを即座にキャプチャ
- 📊 **一意なIP表示** - 送信元IP-宛先IPペアで重複を排除し、新規通信のみ表示
- 🌍 **詳細情報取得** - ipinfo.io APIを使用してIP情報（組織、国、地域、都市）を取得
- 🔐 **プロトコル解析** - ポート番号からサービスを識別し、セキュリティ評価を実施
- 📈 **リアルタイム統計** - TCP/UDP/ICMP/その他のプロトコル別カウント表示
- 🎨 **VSCode風ダークテーマ** - 見やすく洗練されたUI

## 技術スタック

- **Electron** v32.3.3 - クロスプラットフォームデスクトップアプリフレームワーク
- **TypeScript** v5.9.3 - 型安全な開発
- **libpcap (cap)** v0.2.1 - ネイティブパケットキャプチャライブラリ
- **ipinfo.io API** - IP地理情報・組織情報取得

## システム要件

- macOS (en0ネットワークインターフェース使用)
- Node.js 18.x以上
- **管理者権限** (パケットキャプチャに必要)

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

### 開発モード

```bash
# 管理者権限で起動（DevTools自動オープン）
sudo npm run dev
```

### 本番モード

```bash
# 管理者権限で起動
sudo npm start
```

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
│   ├── main.ts           # Electronメインプロセス
│   ├── preload.ts        # プリロードスクリプト（IPC橋渡し）
│   ├── renderer.ts       # レンダラープロセス（UI制御）
│   ├── packet-capture.ts # パケットキャプチャマネージャー
│   └── cap.d.ts          # capモジュールの型定義
├── index.html            # UI（VSCode風ダークテーマ）
├── package.json
├── tsconfig.json
└── README.md
```

## セキュリティ

- **contextBridge**: レンダラープロセスとメインプロセス間の安全な通信
- **contextIsolation**: レンダラープロセスの分離
- **nodeIntegration: false**: Node.js APIへの直接アクセスを無効化
- **Content Security Policy**: XSS攻撃からの保護

## トラブルシューティング

### キャプチャが開始できない

```bash
# 管理者権限で実行されているか確認
sudo npm run dev
```

### ネイティブモジュールエラー

```bash
# capモジュールを再ビルド
npx electron-rebuild
```

### en0デバイスが見つからない

```bash
# ネットワークインターフェースを確認
ifconfig | grep en0
```

## ライセンス

ISC

## 作者

Created with ❤️ using Electron and TypeScript

## 貢献

Issue報告やPull Requestを歓迎します！

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
