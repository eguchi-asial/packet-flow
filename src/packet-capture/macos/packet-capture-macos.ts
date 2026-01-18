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

    // デバイス名が指定されていない場合、利用可能なデバイスから選択
    if (deviceName) {
      // 指定されたデバイスが存在するか確認
      const deviceExists = devices.some(d => d.name === deviceName);
      if (!deviceExists) {
        throw new Error(`指定されたデバイス "${deviceName}" が見つかりません`);
      }
      this.device = deviceName;
    } else {
      // デフォルト: リストの最初のデバイス（ソート済みなのでIPv4を持つデバイスが優先される）
      this.device = devices[0].name;
    }
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
          console.log('[PacketCapture:macOS] パケット送信:', packet.id, packet.protocol, packet.domainName ? `ドメイン名: ${packet.domainName}` : '');
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
      let domainName: string | undefined;
      let packetState: string | undefined;

      // プロトコル解析
      const tcpUdpOffset = offset + ipHeaderLength;

      if (protocol === 6) {
        // TCP
        protocolName = 'TCP';
        sourcePort = buffer.readUInt16BE(tcpUdpOffset);
        destPort = buffer.readUInt16BE(tcpUdpOffset + 2);

        // TCPフラグを解析（オフセット+13バイト目）
        const tcpFlags = buffer[tcpUdpOffset + 13];
        const flags: string[] = [];
        if (tcpFlags & 0x02) flags.push('SYN');
        if (tcpFlags & 0x10) flags.push('ACK');
        if (tcpFlags & 0x01) flags.push('FIN');
        if (tcpFlags & 0x04) flags.push('RST');
        if (tcpFlags & 0x08) flags.push('PSH');

        packetState = flags.join(',');

        info = `${sourceIP}:${sourcePort} → ${destIP}:${destPort}`;

        // HTTPS (443) の場合、SNIとTLS状態を解析
        if (destPort === 443 || sourcePort === 443) {
          const tlsState = this.parseTLSState(buffer, tcpUdpOffset, length);
          if (tlsState) {
            packetState = tlsState;
            if (tlsState === 'Client Hello') {
              domainName = this.parseSNI(buffer, tcpUdpOffset, length);
              if (domainName && shouldLog) {
                console.log('[PacketCapture:macOS] SNI検出:', domainName);
              }
            }
          }
        }
      } else if (protocol === 17) {
        // UDP
        protocolName = 'UDP';
        sourcePort = buffer.readUInt16BE(tcpUdpOffset);
        destPort = buffer.readUInt16BE(tcpUdpOffset + 2);
        info = `${sourceIP}:${sourcePort} → ${destIP}:${destPort}`;

        // DNS (53) の場合、ドメイン名を解析
        if (sourcePort === 53 || destPort === 53) {
          packetState = sourcePort === 53 ? 'DNS Response' : 'DNS Query';
          domainName = this.parseDNS(buffer, tcpUdpOffset, sourcePort === 53);
          if (domainName && shouldLog) {
            console.log('[PacketCapture:macOS] DNS検出:', domainName);
          }
        }
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
        domainName,
        packetState,
      };

      return packetInfo;
    } catch (error) {
      console.error('[PacketCapture:macOS] パケット解析エラー:', error);
      return null;
    }
  }

  /**
   * DNSパケットからドメイン名を抽出
   * @param buffer パケットバッファ
   * @param udpOffset UDPヘッダーの開始位置
   * @param isResponse DNSレスポンスかどうか
   */
  private parseDNS(buffer: Buffer, udpOffset: number, isResponse: boolean): string | undefined {
    try {
      // UDPヘッダー: 8バイト
      const dnsOffset = udpOffset + 8;

      // DNSヘッダー: 12バイト
      // Questions数を取得（オフセット+4の2バイト）
      const questionsCount = buffer.readUInt16BE(dnsOffset + 4);

      if (questionsCount === 0) {
        return undefined;
      }

      // Question セクションの開始位置
      const questionOffset = dnsOffset + 12;

      // ドメイン名をデコード
      const domainName = this.decodeDNSName(buffer, questionOffset);
      return domainName || undefined;
    } catch (error) {
      // DNSパース失敗は静かに無視
      return undefined;
    }
  }

  /**
   * DNS形式のドメイン名をデコード
   * 例: 3www3nhk2or2jp0 → www.nhk.or.jp
   */
  private decodeDNSName(buffer: Buffer, offset: number): string | null {
    try {
      const labels: string[] = [];
      let pos = offset;
      let jumped = false;
      let maxJumps = 5; // 無限ループ防止

      while (maxJumps > 0) {
        if (pos >= buffer.length) break;

        const length = buffer[pos];

        // 終端
        if (length === 0) {
          break;
        }

        // 圧縮ポインタ (上位2ビットが11)
        if ((length & 0xc0) === 0xc0) {
          if (!jumped) {
            // ポインタを辿る
            const pointer = ((length & 0x3f) << 8) | buffer[pos + 1];
            pos = pointer;
            jumped = true;
            maxJumps--;
            continue;
          } else {
            break;
          }
        }

        // 通常のラベル
        if (length > 63 || pos + 1 + length > buffer.length) {
          break;
        }

        const label = buffer.toString('utf8', pos + 1, pos + 1 + length);
        labels.push(label);
        pos += 1 + length;

        if (labels.length > 20) {
          break; // 異常に長いドメイン名を防ぐ
        }
      }

      return labels.length > 0 ? labels.join('.') : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * TLSパケットの状態を判定
   * @param buffer パケットバッファ
   * @param tcpOffset TCPヘッダーの開始位置
   * @param length パケット全体の長さ
   */
  private parseTLSState(buffer: Buffer, tcpOffset: number, length: number): string | undefined {
    try {
      // TCPヘッダー長を取得
      const tcpHeaderLength = ((buffer[tcpOffset + 12] >> 4) & 0x0f) * 4;
      const tlsOffset = tcpOffset + tcpHeaderLength;

      // TLSレコード最小サイズチェック
      if (tlsOffset + 6 > length) {
        return undefined;
      }

      // TLSレコードタイプを確認
      const recordType = buffer[tlsOffset];

      // 0x16 = Handshake
      if (recordType === 0x16) {
        const handshakeType = buffer[tlsOffset + 5];

        // Handshakeタイプを判定
        if (handshakeType === 0x01) {
          return 'Client Hello';
        } else if (handshakeType === 0x02) {
          return 'Server Hello';
        } else if (handshakeType === 0x0b) {
          return 'Certificate';
        } else if (handshakeType === 0x10) {
          return 'Client Key Exchange';
        } else if (handshakeType === 0x14) {
          return 'Finished';
        }
      }
      // 0x14 = Change Cipher Spec
      else if (recordType === 0x14) {
        return 'Change Cipher Spec';
      }
      // 0x17 = Application Data
      else if (recordType === 0x17) {
        return 'Application Data';
      }
      // 0x15 = Alert
      else if (recordType === 0x15) {
        return 'Alert';
      }

      return undefined;
    } catch (error) {
      return undefined;
    }
  }

  /**
   * TLS Client HelloからSNI（Server Name Indication）を抽出
   * @param buffer パケットバッファ
   * @param tcpOffset TCPヘッダーの開始位置
   * @param length パケット全体の長さ
   */
  private parseSNI(buffer: Buffer, tcpOffset: number, length: number): string | undefined {
    try {
      // TCPヘッダー長を取得（オフセット+12の上位4ビット * 4）
      const tcpHeaderLength = ((buffer[tcpOffset + 12] >> 4) & 0x0f) * 4;
      const tlsOffset = tcpOffset + tcpHeaderLength;

      // TLSレコード最小サイズチェック
      if (tlsOffset + 5 > length) {
        return undefined;
      }

      // TLSレコードタイプ: 0x16 = Handshake
      if (buffer[tlsOffset] !== 0x16) {
        return undefined;
      }

      // TLSバージョン (TLS 1.0-1.3: 0x0301-0x0303程度)
      const tlsVersion = buffer.readUInt16BE(tlsOffset + 1);
      if (tlsVersion < 0x0301 || tlsVersion > 0x0304) {
        return undefined;
      }

      // Handshakeタイプ: 0x01 = Client Hello
      if (buffer[tlsOffset + 5] !== 0x01) {
        return undefined;
      }

      // Client Helloの解析（簡略版）
      // セッションID長を取得してスキップ
      let pos = tlsOffset + 38; // レコードヘッダー(5) + ハンドシェイクヘッダー(4) + バージョン(2) + ランダム(32)

      if (pos >= length) return undefined;

      const sessionIdLength = buffer[pos];
      pos += 1 + sessionIdLength;

      if (pos + 2 > length) return undefined;

      // Cipher Suites長を取得してスキップ
      const cipherSuitesLength = buffer.readUInt16BE(pos);
      pos += 2 + cipherSuitesLength;

      if (pos + 1 > length) return undefined;

      // Compression Methods長を取得してスキップ
      const compressionMethodsLength = buffer[pos];
      pos += 1 + compressionMethodsLength;

      if (pos + 2 > length) return undefined;

      // Extensions長
      const extensionsLength = buffer.readUInt16BE(pos);
      pos += 2;

      const extensionsEnd = pos + extensionsLength;

      // Extensions を走査
      while (pos + 4 <= extensionsEnd && pos + 4 <= length) {
        const extType = buffer.readUInt16BE(pos);
        const extLength = buffer.readUInt16BE(pos + 2);
        pos += 4;

        // SNI Extension: 0x0000
        if (extType === 0x0000) {
          if (pos + 2 > length) break;

          const serverNameListLength = buffer.readUInt16BE(pos);
          pos += 2;

          if (pos + 3 > length) break;

          const serverNameType = buffer[pos]; // 0x00 = host_name
          const serverNameLength = buffer.readUInt16BE(pos + 1);
          pos += 3;

          if (serverNameType === 0x00 && pos + serverNameLength <= length) {
            const serverName = buffer.toString('utf8', pos, pos + serverNameLength);
            return serverName;
          }

          break;
        }

        pos += extLength;
      }

      return undefined;
    } catch (error) {
      // SNIパース失敗は静かに無視
      return undefined;
    }
  }
}
