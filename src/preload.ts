import { contextBridge } from 'electron';

/**
 * プリロードスクリプト
 * レンダラープロセスとメインプロセス間の安全な通信を提供
 */

// contextBridgeを使用して、レンダラープロセスにAPIを安全に公開
contextBridge.exposeInMainWorld('api', {
  // Node.jsとElectronのバージョン情報を公開
  version: process.versions,
});
