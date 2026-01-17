import * as Cap from 'cap';
import { BrowserWindow } from 'electron';
import { IPacketCaptureManager, PacketInfo } from '../types';

/**
 * macOS専用パケットキャプチャマネージャー
 * libpcap (cap)を使用してen0デバイスからパケットをキャプチャ
 */
export class PacketCaptureMacOS implements IPacketCaptureManager {
  private cap: any;
  private device: string | null = null;
  private isCapturing = false;
  private packetCounter = 0;
  private mainWindow: BrowserWindow | null = null;
  private debugLogCounter = 0; // デバッグログ用カウンター

  constructor() {
    this.cap = new Cap.Cap();
  }

  /**
   * 利用可能なネットワークデバイスを取得
   */
  getDevices(): any[] {
    const devices = Cap.Cap.deviceList();

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

      // 両方ともIPv4を持つ場合、en0を最優先
      if (aHasIPv4 && bHasIPv4) {
        if (a.name === 'en0') return -1;
        if (b.name === 'en0') return 1;
      }

      return 0;
    });
  }

  /**
   * macOS用のデバイス表示名を生成
   */
  private getDeviceDisplayName(device: any): string {
    const name = device.name;

    // IPv4アドレスを取得
    const ipv4Address = device.addresses?.find((addr: any) =>
      addr.addr && !addr.addr.includes(':') && !addr.addr.startsWith('fe80')
    );

    // en0, en1などの一般的なデバイス名の場合
    if (name.match(/^en\d+$/)) {
      const deviceNum = name.substring(2);
      const deviceType = deviceNum === '0' ? 'Wi-Fi' : `Ethernet ${deviceNum}`;
      if (ipv4Address) {
        return `${deviceType} (${ipv4Address.addr})`;
      }
      return deviceType;
    }

    // その他のデバイス（lo0, bridge0など）
    if (device.description) {
      return device.description;
    }

    if (ipv4Address) {
      return `${name} (${ipv4Address.addr})`;
    }

    return name;
  }

  /**
   * メインウィンドウを設定
   */
  setMainWindow(window: BrowserWindow): void {
    this.mainWindow = window;
  }

  /**
   * キャプチャを開始（macOS用実装）
   */
  startCapture(deviceName?: string): boolean {
    console.log('[PacketCapture:macOS] キャプチャ開始リクエスト:', deviceName);

    if (this.isCapturing) {
      console.log('[PacketCapture:macOS] 既にキャプチャ中です');
      return false;
    }

    const devices = this.getDevices();
    console.log('[PacketCapture:macOS] 利用可能なデバイス:', devices);

    if (devices.length === 0) {
      throw new Error('利用可能なネットワークデバイスが見つかりません');
    }

    // デバイス名が指定されていない場合はen0を優先的に使用（macOSのデフォルト）
    this.device = deviceName || 'en0';
    console.log('[PacketCapture:macOS] 使用するデバイス:', this.device);

    try {
      // キャプチャフィルター: 全てのIPパケット
      const filter = 'ip';
      const bufSize = 10 * 1024 * 1024; // 10MB
      const buffer = Buffer.alloc(65535);

      // リンクタイプを取得
      console.log('[PacketCapture:macOS] capを開いています...');
      const linkType = this.cap.open(this.device, filter, bufSize, buffer);
      console.log('[PacketCapture:macOS] リンクタイプ:', linkType);

      this.isCapturing = true;
      this.packetCounter = 0;

      // パケット受信イベント
      this.cap.on('packet', (nbytes: number, trunc: boolean) => {
        this.handlePacket(nbytes, buffer, linkType);
      });

      console.log('[PacketCapture:macOS] キャプチャ開始成功');
      return true;
    } catch (error) {
      console.error('[PacketCapture:macOS] キャプチャ開始エラー:', error);
      throw error;
    }
  }

  /**
   * キャプチャを停止
   */
  stopCapture(): void {
    if (this.isCapturing && this.cap) {
      this.cap.close();
      this.isCapturing = false;
      this.device = null;
      console.log('[PacketCapture:macOS] キャプチャ停止');
    }
  }

  /**
   * キャプチャ中かどうか
   */
  isCaptureActive(): boolean {
    return this.isCapturing;
  }

  /**
   * パケットを処理
   */
  private handlePacket(nbytes: number, buffer: Buffer, linkType: string): void {
    // 最初の10パケットだけ詳細ログを出力
    const shouldLog = this.debugLogCounter < 10;

    if (shouldLog) {
      console.log('[PacketCapture:macOS] パケット受信イベント発火 - バイト数:', nbytes, 'リンクタイプ:', linkType);
      this.debugLogCounter++;
    }

    try {
      const packet = this.parsePacket(buffer, nbytes, linkType, shouldLog);

      if (shouldLog) {
        console.log('[PacketCapture:macOS] 解析結果:', packet);
      }

      if (packet && this.mainWindow) {
        // レンダラープロセスにパケット情報を送信
        if (shouldLog || packet.id % 100 === 1) {
          console.log('[PacketCapture:macOS] パケット送信:', packet.id, packet.protocol);
        }
        this.mainWindow.webContents.send('packet-captured', packet);
      } else {
        if (!packet && shouldLog) {
          console.warn('[PacketCapture:macOS] パケット解析結果がnull');
        }
        if (!this.mainWindow) {
          console.warn('[PacketCapture:macOS] mainWindowが未設定');
        }
      }
    } catch (error) {
      console.error('[PacketCapture:macOS] パケット解析エラー:', error);
    }
  }

  /**
   * パケットを解析（macOS/libpcap形式）
   */
  private parsePacket(buffer: Buffer, length: number, linkType: string, shouldLog: boolean = false): PacketInfo | null {
    try {
      let offset = 0;

      // Ethernetヘッダーをスキップ (14バイト)
      if (linkType === 'ETHERNET') {
        offset = 14;
      }

      // IPヘッダーを解析
      const ipVersion = (buffer[offset] >> 4) & 0x0f;
      if (shouldLog) {
        console.log('[PacketCapture:macOS] IPバージョン:', ipVersion);
      }
      if (ipVersion !== 4) {
        // IPv6は未対応
        if (shouldLog) {
          console.log('[PacketCapture:macOS] IPv6パケットのためスキップ');
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
      console.error('[PacketCapture:macOS] パケット解析エラー:', error);
      return null;
    }
  }
}
