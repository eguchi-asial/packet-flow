import * as Cap from 'cap';
import { BrowserWindow } from 'electron';

/**
 * パケット情報の型定義
 */
export interface PacketInfo {
  id: number;
  timestamp: string;
  protocol: string;
  sourceIP: string;
  destIP: string;
  sourcePort?: number;
  destPort?: number;
  length: number;
  info: string;
}

/**
 * パケットキャプチャマネージャー
 */
export class PacketCaptureManager {
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
    return Cap.Cap.deviceList();
  }

  /**
   * メインウィンドウを設定
   */
  setMainWindow(window: BrowserWindow): void {
    this.mainWindow = window;
  }

  /**
   * キャプチャを開始
   */
  startCapture(deviceName?: string): boolean {
    console.log('[PacketCapture] キャプチャ開始リクエスト:', deviceName);

    if (this.isCapturing) {
      console.log('[PacketCapture] 既にキャプチャ中です');
      return false;
    }

    const devices = this.getDevices();
    console.log('[PacketCapture] 利用可能なデバイス:', devices);

    if (devices.length === 0) {
      throw new Error('利用可能なネットワークデバイスが見つかりません');
    }

    // デバイス名が指定されていない場合は最初のデバイスを使用
    this.device = deviceName || devices[0].name;
    console.log('[PacketCapture] 使用するデバイス:', this.device);

    try {
      // キャプチャフィルター: 全てのIPパケット
      const filter = 'ip';
      const bufSize = 10 * 1024 * 1024; // 10MB
      const buffer = Buffer.alloc(65535);

      // リンクタイプを取得
      console.log('[PacketCapture] capを開いています...');
      const linkType = this.cap.open(this.device, filter, bufSize, buffer);
      console.log('[PacketCapture] リンクタイプ:', linkType);

      this.isCapturing = true;
      this.packetCounter = 0;

      // パケット受信イベント
      this.cap.on('packet', (nbytes: number, trunc: boolean) => {
        this.handlePacket(nbytes, buffer, linkType);
      });

      console.log('[PacketCapture] キャプチャ開始成功');
      return true;
    } catch (error) {
      console.error('[PacketCapture] キャプチャ開始エラー:', error);
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
      console.log('[PacketCapture] パケット受信イベント発火 - バイト数:', nbytes, 'リンクタイプ:', linkType);
      this.debugLogCounter++;
    }

    try {
      const packet = this.parsePacket(buffer, nbytes, linkType, shouldLog);

      if (shouldLog) {
        console.log('[PacketCapture] 解析結果:', packet);
      }

      if (packet && this.mainWindow) {
        // レンダラープロセスにパケット情報を送信
        if (shouldLog || packet.id % 100 === 1) {
          console.log('[PacketCapture] パケット送信:', packet.id, packet.protocol);
        }
        this.mainWindow.webContents.send('packet-captured', packet);
      } else {
        if (!packet && shouldLog) {
          console.warn('[PacketCapture] パケット解析結果がnull');
        }
        if (!this.mainWindow) {
          console.warn('[PacketCapture] mainWindowが未設定');
        }
      }
    } catch (error) {
      console.error('[PacketCapture] パケット解析エラー:', error);
    }
  }

  /**
   * パケットを解析
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
        console.log('[PacketCapture] IPバージョン:', ipVersion);
      }
      if (ipVersion !== 4) {
        // IPv6は未対応
        if (shouldLog) {
          console.log('[PacketCapture] IPv6パケットのためスキップ');
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
      console.error('パケット解析エラー:', error);
      return null;
    }
  }
}
