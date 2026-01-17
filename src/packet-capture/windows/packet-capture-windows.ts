import * as Cap from 'cap';
import { BrowserWindow } from 'electron';
import { IPacketCaptureManager, PacketInfo } from '../types';

/**
 * Windows専用パケットキャプチャマネージャー
 * Npcap経由でパケットをキャプチャ
 *
 * 前提条件:
 * - Npcapがインストールされていること (https://npcap.com/)
 * - 管理者権限で実行すること
 *
 * Windows固有の特徴:
 * - デバイス名は \Device\NPF_{GUID} 形式
 * - デフォルトデバイスの自動選択が困難（人間には読みにくい名前のため）
 */
export class PacketCaptureWindows implements IPacketCaptureManager {
  private cap: any;
  private device: string | null = null;
  private isCapturing = false;
  private packetCounter = 0;
  private mainWindow: BrowserWindow | null = null;
  private debugLogCounter = 0; // デバッグログ用カウンター

  constructor() {
    try {
      this.cap = new Cap.Cap();
      console.log('[PacketCapture:Windows] Npcap初期化成功');
    } catch (error) {
      console.error('[PacketCapture:Windows] 初期化エラー:', error);
      throw new Error(
        'Npcapの初期化に失敗しました。\n' +
        '\n' +
        'Npcapがインストールされているか確認してください:\n' +
        'https://npcap.com/\n' +
        '\n' +
        'また、管理者権限で実行してください。'
      );
    }
  }

  /**
   * 利用可能なネットワークデバイスを取得
   * Windows版はデバイス名が \Device\NPF_{GUID} 形式で人間には読みにくい
   */
  getDevices(): any[] {
    try {
      const devices = Cap.Cap.deviceList();
      console.log('[PacketCapture:Windows] 検出デバイス数:', devices.length);

      // デバイス情報をログ出力（デバッグ用）
      devices.forEach((device, index) => {
        console.log(`[PacketCapture:Windows] デバイス[${index}]:`, {
          name: device.name,
          description: device.description,
          addresses: device.addresses
        });
      });

      // 各デバイスに表示用の名前を追加
      const devicesWithDisplayName = devices.map(device => ({
        ...device,
        displayName: this.getDeviceDisplayName(device)
      }));

      // アクティブなデバイス（IPv4アドレスを持つもの）を優先的に表示
      return devicesWithDisplayName.sort((a, b) => {
        const aHasIPv4 = a.addresses?.some((addr: any) =>
          addr.addr && !addr.addr.includes(':') && !addr.addr.startsWith('fe80')
        );
        const bHasIPv4 = b.addresses?.some((addr: any) =>
          addr.addr && !addr.addr.includes(':') && !addr.addr.startsWith('fe80')
        );

        // IPv4アドレスを持つデバイスを優先
        if (aHasIPv4 && !bHasIPv4) return -1;
        if (!aHasIPv4 && bHasIPv4) return 1;

        return 0;
      });
    } catch (error) {
      console.error('[PacketCapture:Windows] デバイス取得エラー:', error);
      return [];
    }
  }

  /**
   * Windows用のデバイス表示名を生成
   * \Device\NPF_{GUID} 形式のデバイス名を人間が読みやすい形式に変換
   */
  private getDeviceDisplayName(device: any): string {
    // descriptionがある場合はそれを優先
    if (device.description) {
      return device.description;
    }

    // IPv4アドレスを取得
    const ipv4Address = device.addresses?.find((addr: any) =>
      addr.addr && !addr.addr.includes(':') && !addr.addr.startsWith('fe80')
    );

    if (ipv4Address) {
      return `ネットワークアダプタ (${ipv4Address.addr})`;
    }

    // フォールバック: デバイス名の末尾GUIDを短縮表示
    const guidMatch = device.name.match(/NPF_(.{8})/);
    if (guidMatch) {
      return `ネットワークアダプタ (${guidMatch[1]}...)`;
    }

    return device.name;
  }

  /**
   * メインウィンドウを設定
   */
  setMainWindow(window: BrowserWindow): void {
    this.mainWindow = window;
  }

  /**
   * キャプチャを開始（Windows用実装）
   */
  startCapture(deviceName?: string): boolean {
    console.log('[PacketCapture:Windows] キャプチャ開始リクエスト:', deviceName);

    if (this.isCapturing) {
      console.log('[PacketCapture:Windows] 既にキャプチャ中です');
      return false;
    }

    const devices = this.getDevices();

    if (devices.length === 0) {
      throw new Error(
        '利用可能なネットワークデバイスが見つかりません。\n' +
        '\n' +
        '以下を確認してください:\n' +
        '1. Npcapがインストールされているか\n' +
        '2. 管理者権限で実行しているか\n' +
        '3. ネットワークアダプタが有効になっているか'
      );
    }

    // デバイス選択ロジック（Windows版）
    if (deviceName) {
      // 明示的に指定された場合
      this.device = deviceName;
    } else {
      // デフォルト: 最初のアクティブなデバイスを選択
      // より良い選択: IPv4アドレスを持つ最初のデバイス
      const activeDevice = devices.find(d =>
        d.addresses && d.addresses.some((addr: any) => addr.addr && !addr.addr.startsWith('fe80'))
      );

      if (activeDevice) {
        this.device = activeDevice.name;
        console.log('[PacketCapture:Windows] 自動選択デバイス:', {
          name: activeDevice.name,
          description: activeDevice.description
        });
      } else {
        // フォールバック: 最初のデバイス
        this.device = devices[0].name;
        console.log('[PacketCapture:Windows] フォールバックで最初のデバイスを使用:', this.device);
      }
    }

    console.log('[PacketCapture:Windows] 使用するデバイス:', this.device);

    try {
      // キャプチャフィルター: 全てのIPv4パケット
      const filter = 'ip';
      const bufSize = 10 * 1024 * 1024; // 10MB
      const buffer = Buffer.alloc(65535);

      // リンクタイプを取得
      console.log('[PacketCapture:Windows] capを開いています...');
      const linkType = this.cap.open(this.device, filter, bufSize, buffer);
      console.log('[PacketCapture:Windows] リンクタイプ:', linkType);

      this.isCapturing = true;
      this.packetCounter = 0;
      this.debugLogCounter = 0; // リセット

      // パケット受信イベント
      this.cap.on('packet', (nbytes: number, trunc: boolean) => {
        this.handlePacket(nbytes, buffer, linkType);
      });

      console.log('[PacketCapture:Windows] キャプチャ開始成功');
      return true;
    } catch (error) {
      console.error('[PacketCapture:Windows] キャプチャ開始エラー:', error);
      this.isCapturing = false;
      this.device = null;
      throw new Error(
        `パケットキャプチャの開始に失敗しました。\n\n` +
        `エラー: ${error}\n\n` +
        `対処方法:\n` +
        `1. 管理者権限で実行してください\n` +
        `2. Npcapが正しくインストールされているか確認してください\n` +
        `3. ファイアウォールがブロックしていないか確認してください`
      );
    }
  }

  /**
   * キャプチャを停止
   */
  stopCapture(): void {
    if (this.isCapturing && this.cap) {
      try {
        this.cap.close();
        this.isCapturing = false;
        this.device = null;
        console.log('[PacketCapture:Windows] キャプチャ停止');
      } catch (error) {
        console.error('[PacketCapture:Windows] キャプチャ停止エラー:', error);
      }
    }
  }

  /**
   * キャプチャ中かどうか
   */
  isCaptureActive(): boolean {
    return this.isCapturing;
  }

  /**
   * パケットを処理（Windows版）
   */
  private handlePacket(nbytes: number, buffer: Buffer, linkType: string): void {
    // 最初の10パケットだけ詳細ログを出力
    const shouldLog = this.debugLogCounter < 10;

    if (shouldLog) {
      console.log('[PacketCapture:Windows] パケット受信イベント発火 - バイト数:', nbytes, 'リンクタイプ:', linkType);
      this.debugLogCounter++;
    }

    try {
      const packet = this.parsePacket(buffer, nbytes, linkType, shouldLog);

      if (shouldLog) {
        console.log('[PacketCapture:Windows] 解析結果:', packet);
      }

      if (packet && this.mainWindow) {
        // レンダラープロセスにパケット情報を送信
        if (shouldLog || packet.id % 100 === 1) {
          console.log('[PacketCapture:Windows] パケット送信:', packet.id, packet.protocol);
        }
        this.mainWindow.webContents.send('packet-captured', packet);
      } else {
        if (!packet && shouldLog) {
          console.warn('[PacketCapture:Windows] パケット解析結果がnull');
        }
        if (!this.mainWindow) {
          console.warn('[PacketCapture:Windows] mainWindowが未設定');
        }
      }
    } catch (error) {
      console.error('[PacketCapture:Windows] パケット解析エラー:', error);
    }
  }

  /**
   * パケットを解析（Npcap形式）
   * Windows版もEthernetフレーム形式は同じ
   */
  private parsePacket(buffer: Buffer, length: number, linkType: string, shouldLog: boolean = false): PacketInfo | null {
    try {
      let offset = 0;

      // Ethernetヘッダーをスキップ (14バイト)
      // Windowsでもlibpcap互換のため、Ethernetフレーム形式は同じ
      if (linkType === 'ETHERNET') {
        offset = 14;
      }

      // IPヘッダーを解析
      const ipVersion = (buffer[offset] >> 4) & 0x0f;
      if (shouldLog) {
        console.log('[PacketCapture:Windows] IPバージョン:', ipVersion);
      }
      if (ipVersion !== 4) {
        // IPv6は未対応
        if (shouldLog) {
          console.log('[PacketCapture:Windows] IPv6パケットのためスキップ');
        }
        return null;
      }

      const ipHeaderLength = (buffer[offset] & 0x0f) * 4;
      const protocol = buffer[offset + 9];
      const sourceIP = `${buffer[offset + 12]}.${buffer[offset + 13]}.${buffer[offset + 14]}.${buffer[offset + 15]}`;
      const destIP = `${buffer[offset + 16]}.${buffer[offset + 17]}.${buffer[offset + 18]}.${buffer[offset + 19]}`;

      let protocolName = 'Unknown';
      let sourcePort: number | undefined;
      let destPort: number | undefined;
      let info = '';

      // プロトコル解析
      const tcpUdpOffset = offset + ipHeaderLength;

      if (protocol === 6) {
        // TCP
        protocolName = 'TCP';
        sourcePort = buffer.readUInt16BE(tcpUdpOffset);
        destPort = buffer.readUInt16BE(tcpUdpOffset + 2);
        info = `${sourceIP}:${sourcePort} → ${destIP}:${destPort}`;
      } else if (protocol === 17) {
        // UDP
        protocolName = 'UDP';
        sourcePort = buffer.readUInt16BE(tcpUdpOffset);
        destPort = buffer.readUInt16BE(tcpUdpOffset + 2);
        info = `${sourceIP}:${sourcePort} → ${destIP}:${destPort}`;
      } else if (protocol === 1) {
        // ICMP
        protocolName = 'ICMP';
        info = `${sourceIP} → ${destIP}`;
      } else {
        protocolName = `Protocol ${protocol}`;
        info = `${sourceIP} → ${destIP}`;
      }

      const packetInfo: PacketInfo = {
        id: ++this.packetCounter,
        timestamp: new Date().toISOString(),
        protocol: protocolName,
        sourceIP,
        destIP,
        sourcePort,
        destPort,
        length,
        info,
      };

      return packetInfo;
    } catch (error) {
      console.error('[PacketCapture:Windows] パケット解析エラー:', error);
      return null;
    }
  }
}
