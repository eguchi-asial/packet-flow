import { contextBridge, ipcRenderer } from 'electron';

/**
 * プリロードスクリプト
 * レンダラープロセスとメインプロセス間の安全な通信を提供
 */

// contextBridgeを使用して、レンダラープロセスにAPIを安全に公開
contextBridge.exposeInMainWorld('api', {
  // Node.jsとElectronのバージョン情報を公開
  version: process.versions,

  // パケットキャプチャAPI
  capture: {
    // 利用可能なネットワークデバイスを取得
    getDevices: () => ipcRenderer.invoke('get-devices'),

    // キャプチャを開始
    startCapture: (deviceName?: string) => ipcRenderer.invoke('start-capture', deviceName),

    // キャプチャを停止
    stopCapture: () => ipcRenderer.invoke('stop-capture'),

    // キャプチャ状態を取得
    isCapturing: () => ipcRenderer.invoke('is-capturing'),

    // パケット受信イベントのリスナーを登録
    onPacketCaptured: (callback: (packet: any) => void) => {
      ipcRenderer.on('packet-captured', (_event, packet) => callback(packet));
    },
  },
});
