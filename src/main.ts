import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import { PacketCaptureManager } from './packet-capture';

// パケットキャプチャマネージャーのインスタンス
let captureManager: PacketCaptureManager;

/**
 * メインウィンドウを作成する
 */
function createWindow(): void {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      // セキュリティのため、プリロードスクリプトを使用
      preload: path.join(__dirname, 'preload.js'),
      // nodeIntegrationを無効化してセキュリティを強化
      nodeIntegration: false,
      // contextIsolationを有効化してレンダラープロセスを分離
      contextIsolation: true,
    },
  });

  // HTMLファイルを読み込む
  mainWindow.loadFile(path.join(__dirname, '../index.html'));

  // 開発環境の場合はDevToolsを自動で開く
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }

  // パケットキャプチャマネージャーを初期化
  captureManager = new PacketCaptureManager();
  captureManager.setMainWindow(mainWindow);
}

/**
 * IPCハンドラーをセットアップ
 */
function setupIpcHandlers(): void {
  // 利用可能なデバイス一覧を取得
  ipcMain.handle('get-devices', () => {
    try {
      return captureManager.getDevices();
    } catch (error) {
      console.error('デバイス取得エラー:', error);
      return [];
    }
  });

  // キャプチャを開始
  ipcMain.handle('start-capture', (_event, deviceName?: string) => {
    try {
      return captureManager.startCapture(deviceName);
    } catch (error) {
      console.error('キャプチャ開始エラー:', error);
      throw error;
    }
  });

  // キャプチャを停止
  ipcMain.handle('stop-capture', () => {
    try {
      captureManager.stopCapture();
      return true;
    } catch (error) {
      console.error('キャプチャ停止エラー:', error);
      throw error;
    }
  });

  // キャプチャ状態を取得
  ipcMain.handle('is-capturing', () => {
    return captureManager.isCaptureActive();
  });
}

// アプリケーションの準備が完了したら実行
app.whenReady().then(() => {
  createWindow();
  setupIpcHandlers();

  // macOS: Dockアイコンがクリックされた時、ウィンドウが無ければ新規作成
  // (macOSでは全ウィンドウを閉じてもアプリは終了しないため)
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// 全てのウィンドウが閉じられた時の処理
app.on('window-all-closed', () => {
  // キャプチャを停止
  if (captureManager) {
    captureManager.stopCapture();
  }

  // macOS以外: 全ウィンドウが閉じられたらアプリを終了
  // macOSではCmd+Qで明示的に終了するまでアプリを終了しない
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
