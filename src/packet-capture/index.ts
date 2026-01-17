import { IPacketCaptureManager } from './types';

/**
 * プラットフォーム別のパケットキャプチャマネージャーを生成するファクトリー関数
 *
 * 現在の対応状況:
 * - macOS: 完全対応（libpcap経由でパケットをキャプチャ）
 * - Windows: 完全対応（Npcap経由でパケットをキャプチャ）
 * - Linux: 未対応
 *
 * @returns プラットフォームに応じたパケットキャプチャマネージャー
 * @throws 対応していないプラットフォームの場合はエラー
 */
export function createPacketCaptureManager(): IPacketCaptureManager {
  const platform = process.platform;

  console.log(`[PacketCapture] プラットフォーム検出: ${platform}`);

  if (platform === 'darwin') {
    // macOS
    const { PacketCaptureMacOS } = require('./macos/packet-capture-macos');
    console.log('[PacketCapture] macOS用モジュールをロード');
    return new PacketCaptureMacOS();
  } else if (platform === 'win32') {
    // Windows
    const { PacketCaptureWindows } = require('./windows/packet-capture-windows');
    console.log('[PacketCapture] Windows用モジュールをロード');
    return new PacketCaptureWindows();
  } else {
    throw new Error(
      `未対応のプラットフォームです: ${platform}\n` +
      '\n' +
      '対応プラットフォーム:\n' +
      '- macOS (darwin) ✅\n' +
      '- Windows (win32) ✅\n' +
      '- Linux ❌ 未対応'
    );
  }
}

// 型定義を再エクスポート
export { IPacketCaptureManager, PacketInfo } from './types';
