import { BrowserWindow } from 'electron';
import { IPacketCaptureManager } from '../types';

/**
 * Windows専用パケットキャプチャマネージャー（未実装）
 *
 * Windows対応時にはNpcapのインストールが必要
 * デバイス名は \Device\NPF_{GUID} 形式になる
 *
 * 実装時の参考:
 * - Npcap: https://npcap.com/
 * - capモジュールのWindows対応確認が必要
 * - デバイス選択UIが必要（デバイス名が人間には読みにくいため）
 */
export class PacketCaptureWindows implements IPacketCaptureManager {
  constructor() {
    console.log('[PacketCapture:Windows] Windows版は未実装です');
  }

  /**
   * 利用可能なネットワークデバイスを取得
   */
  getDevices(): any[] {
    console.warn('[PacketCapture:Windows] Windows版は未実装です');
    return [];
  }

  /**
   * メインウィンドウを設定
   */
  setMainWindow(window: BrowserWindow): void {
    // Windows実装時に使用
  }

  /**
   * キャプチャを開始（未実装）
   */
  startCapture(deviceName?: string): boolean {
    throw new Error(
      'Windows版は現在未対応です。\n' +
      '\n' +
      '対応するには以下が必要です:\n' +
      '1. Npcapのインストール (https://npcap.com/)\n' +
      '2. capモジュールのWindows互換性確認\n' +
      '3. デバイス選択UIの実装\n' +
      '\n' +
      '現在はmacOS専用アプリとして動作します。'
    );
  }

  /**
   * キャプチャを停止（未実装）
   */
  stopCapture(): void {
    // Windows実装時に使用
  }

  /**
   * キャプチャ中かどうか
   */
  isCaptureActive(): boolean {
    return false;
  }
}
