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
  domainName?: string; // DNS/SNIから取得したドメイン名
  packetState?: string; // TCP/TLS状態（SYN, ACK, Client Hello等）
}

/**
 * パケットキャプチャマネージャーの共通インターフェース
 * プラットフォーム固有の実装はこのインターフェースを実装する
 */
export interface IPacketCaptureManager {
  /**
   * 利用可能なネットワークデバイスを取得
   */
  getDevices(): any[];

  /**
   * メインウィンドウを設定
   */
  setMainWindow(window: BrowserWindow): void;

  /**
   * キャプチャを開始
   * @param deviceName デバイス名（省略時はデフォルトデバイスを使用）
   * @returns 成功したらtrue
   */
  startCapture(deviceName?: string): boolean;

  /**
   * キャプチャを停止
   */
  stopCapture(): void;

  /**
   * キャプチャ中かどうか
   */
  isCaptureActive(): boolean;
}
