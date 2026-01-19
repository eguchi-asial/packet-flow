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
  private dnsCache: Map<string, string> = new Map(); // IP → ドメイン名のマッピング
  private applicationDataSeen: Set<string> = new Set(); // Application Data表示済み接続を追跡

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
      // 明示的に指定された場合、存在確認
      const deviceExists = devices.some(d => d.name === deviceName);
      if (!deviceExists) {
        throw new Error(`指定されたデバイス "${deviceName}" が見つかりません`);
      }
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
      // キャプチャフィルター: アプリケーション層プロトコルのみ (HTTP, HTTPS, DNS等)
      const filter = 'tcp portrange 80-8080 or udp port 53';
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
          console.log('[PacketCapture:Windows] パケット送信:', packet.id, packet.protocol, packet.domainName ? `ドメイン名: ${packet.domainName}` : '');
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
            console.log('[PacketCapture:Windows] TLS状態検出:', tlsState);
            if (tlsState === 'Client Hello') {
              domainName = this.parseSNI(buffer, tcpUdpOffset, length);
              if (domainName) {
                console.log('[PacketCapture:Windows] ✅ SNI ドメイン名抽出成功:', domainName);
              } else {
                console.log('[PacketCapture:Windows] ❌ SNI ドメイン名抽出失敗');
              }
            }

            // Application Dataの場合、接続ごとに最初の1回だけ表示
            if (tlsState === 'Application Data') {
              const connKey = `${sourceIP}:${sourcePort}-${destIP}:${destPort}`;
              if (!this.applicationDataSeen.has(connKey)) {
                this.applicationDataSeen.add(connKey);
                packetState = 'HTTP(S) Data Transfer';
                console.log('[PacketCapture:Windows] ✅ HTTP(S)データ転送開始:', connKey);
              } else {
                // 2回目以降は表示しない
                packetState = undefined;
              }
            }
          }

          // SNIで取得できなかった場合、DNSキャッシュから取得を試みる
          if (!domainName && packetState !== undefined) {
            const cachedDomain = this.dnsCache.get(destPort === 443 ? destIP : sourceIP);
            if (cachedDomain) {
              domainName = cachedDomain;
              console.log('[PacketCapture:Windows] ✅ DNSキャッシュからドメイン名取得:', domainName);
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
          console.log('[PacketCapture:Windows] DNSパケット検出 - sourcePort:', sourcePort, 'destPort:', destPort);
          domainName = this.parseDNS(buffer, tcpUdpOffset, sourcePort === 53);
          if (domainName) {
            console.log('[PacketCapture:Windows] ✅ DNS ドメイン名抽出成功:', domainName);

            // DNS応答の場合、IPアドレスを取得してキャッシュに保存
            if (sourcePort === 53) {
              const resolvedIP = this.extractDNSAnswer(buffer, tcpUdpOffset);
              if (resolvedIP) {
                this.dnsCache.set(resolvedIP, domainName);
                console.log(`[PacketCapture:Windows] DNSキャッシュ保存: ${domainName} = ${resolvedIP}`);
              }
            }
          } else {
            console.log('[PacketCapture:Windows] ❌ DNS ドメイン名抽出失敗');
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

      // 意味のあるパケットのみをUIに表示
      // - TLS/DNSの重要な状態を持つパケット
      // - ドメイン名が取得できたパケット
      // - UDPパケット（DNS等）
      // - 単純なACKやPSH,ACKなどのトランスポート層のみのパケットは除外
      const isSignificantPacket = (
        // TLS関連の重要な状態
        packetState === 'Client Hello' ||
        packetState === 'Server Hello' ||
        packetState === 'Certificate' ||
        packetState === 'Server Key Exchange' ||
        packetState === 'Client Key Exchange' ||
        packetState === 'Change Cipher Spec' ||
        packetState === 'Finished' ||
        packetState === 'Alert' ||
        // HTTP(S)データ転送
        packetState === 'HTTP(S) Data Transfer' ||
        // DNS関連
        packetState === 'DNS Query' ||
        packetState === 'DNS Response' ||
        // ドメイン名が取得できた
        domainName !== undefined ||
        // UDPプロトコル（DNS等）
        protocolName === 'UDP' ||
        // TCPハンドシェイク
        packetState === 'SYN' ||
        packetState === 'SYN,ACK' ||
        packetState === 'FIN' ||
        packetState === 'FIN,ACK' ||
        packetState === 'RST'
      );

      if (!isSignificantPacket) {
        // 重要でないパケット（ACK、PSH,ACK等）はログのみ
        console.log(`[PacketCapture:Windows] スキップ（表示価値なし）: ${protocolName} ${packetState || 'no-state'}`);
        return null;
      }

      return packetInfo;
    } catch (error) {
      console.error('[PacketCapture:Windows] パケット解析エラー:', error);
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
   * DNS応答からIPアドレス（A レコード）を抽出
   * @param buffer パケットバッファ
   * @param udpOffset UDPヘッダーの開始位置
   * @returns 解決されたIPアドレス
   */
  private extractDNSAnswer(buffer: Buffer, udpOffset: number): string | undefined {
    try {
      const dnsOffset = udpOffset + 8; // UDPヘッダー: 8バイト

      // DNSヘッダーを解析
      const questionsCount = buffer.readUInt16BE(dnsOffset + 4);
      const answersCount = buffer.readUInt16BE(dnsOffset + 6);

      if (answersCount === 0) {
        return undefined; // 回答がない
      }

      // Questionセクションをスキップ
      let pos = dnsOffset + 12;
      for (let i = 0; i < questionsCount; i++) {
        // ドメイン名をスキップ
        while (pos < buffer.length) {
          const len = buffer[pos];
          if (len === 0) {
            pos++; // 終端
            break;
          }
          if ((len & 0xc0) === 0xc0) {
            pos += 2; // 圧縮ポインタ
            break;
          }
          pos += 1 + len;
        }
        pos += 4; // Type (2) + Class (2)
      }

      // Answerセクションを解析
      for (let i = 0; i < answersCount; i++) {
        // ドメイン名をスキップ
        while (pos < buffer.length) {
          const len = buffer[pos];
          if (len === 0) {
            pos++;
            break;
          }
          if ((len & 0xc0) === 0xc0) {
            pos += 2; // 圧縮ポインタ
            break;
          }
          pos += 1 + len;
        }

        if (pos + 10 > buffer.length) break;

        const type = buffer.readUInt16BE(pos);     // Type
        const dataLength = buffer.readUInt16BE(pos + 8); // Data Length
        pos += 10; // Type (2) + Class (2) + TTL (4) + Length (2)

        // Type 1 = A レコード (IPv4)
        if (type === 1 && dataLength === 4) {
          const ip = `${buffer[pos]}.${buffer[pos + 1]}.${buffer[pos + 2]}.${buffer[pos + 3]}`;
          return ip;
        }

        pos += dataLength; // 次のAnswerへ
      }

      return undefined;
    } catch (error) {
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

      console.log('[PacketCapture:Windows] SNI解析開始 - tcpOffset:', tcpOffset, 'tcpHeaderLength:', tcpHeaderLength, 'tlsOffset:', tlsOffset, 'length:', length);

      // TLSレコード最小サイズチェック
      if (tlsOffset + 9 > length) {
        console.log('[PacketCapture:Windows] SNI失敗: TLSレコード最小サイズ不足');
        return undefined;
      }

      // TLSレコードタイプ: 0x16 = Handshake
      const recordType = buffer[tlsOffset];
      console.log('[PacketCapture:Windows] TLSレコードタイプ:', '0x' + recordType.toString(16));
      if (recordType !== 0x16) {
        console.log('[PacketCapture:Windows] SNI失敗: Handshakeではない');
        return undefined;
      }

      // TLSレコード長を取得（3-4バイト目）
      const tlsRecordLength = buffer.readUInt16BE(tlsOffset + 3);
      const totalTlsLength = tlsOffset + 5 + tlsRecordLength;
      console.log('[PacketCapture:Windows] TLSレコード長:', tlsRecordLength, 'パケット全体の必要長:', totalTlsLength, '実際のlength:', length);

      // パケットが分割されている場合はスキップ
      if (totalTlsLength > length) {
        console.log('[PacketCapture:Windows] SNI失敗: パケットが分割されている (TLS Client Helloが複数パケットにまたがっている)');
        return undefined;
      }

      // TLSバージョン (TLS 1.0-1.3: 0x0301-0x0304)
      const tlsVersion = buffer.readUInt16BE(tlsOffset + 1);
      console.log('[PacketCapture:Windows] TLSバージョン:', '0x' + tlsVersion.toString(16));
      if (tlsVersion < 0x0301 || tlsVersion > 0x0304) {
        console.log('[PacketCapture:Windows] SNI失敗: TLSバージョンが範囲外');
        return undefined;
      }

      // Handshakeタイプ: 0x01 = Client Hello
      const handshakeType = buffer[tlsOffset + 5];
      console.log('[PacketCapture:Windows] Handshakeタイプ:', '0x' + handshakeType.toString(16));
      if (handshakeType !== 0x01) {
        console.log('[PacketCapture:Windows] SNI失敗: Client Helloではない');
        return undefined;
      }

      // Client Helloの解析（簡略版）
      // セッションID長を取得してスキップ
      let pos = tlsOffset + 38; // レコードヘッダー(5) + ハンドシェイクヘッダー(4) + バージョン(2) + ランダム(32)

      console.log('[PacketCapture:Windows] Client Hello解析開始 - 初期pos:', pos);

      if (pos >= length) {
        console.log('[PacketCapture:Windows] SNI失敗: バッファ長不足(初期pos)');
        return undefined;
      }

      const sessionIdLength = buffer[pos];
      console.log('[PacketCapture:Windows] SessionID長:', sessionIdLength);
      pos += 1 + sessionIdLength;

      if (pos + 2 > length) {
        console.log('[PacketCapture:Windows] SNI失敗: バッファ長不足(CipherSuites前)');
        return undefined;
      }

      // Cipher Suites長を取得してスキップ
      const cipherSuitesLength = buffer.readUInt16BE(pos);
      console.log('[PacketCapture:Windows] CipherSuites長:', cipherSuitesLength);
      pos += 2 + cipherSuitesLength;

      if (pos + 1 > length) {
        console.log('[PacketCapture:Windows] SNI失敗: バッファ長不足(CompressionMethods前)');
        return undefined;
      }

      // Compression Methods長を取得してスキップ
      const compressionMethodsLength = buffer[pos];
      console.log('[PacketCapture:Windows] CompressionMethods長:', compressionMethodsLength);
      pos += 1 + compressionMethodsLength;

      if (pos + 2 > length) {
        console.log('[PacketCapture:Windows] SNI失敗: バッファ長不足(Extensions前)');
        return undefined;
      }

      // Extensions長
      const extensionsLength = buffer.readUInt16BE(pos);
      console.log('[PacketCapture:Windows] Extensions長:', extensionsLength);
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
