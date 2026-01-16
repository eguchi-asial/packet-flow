import { app, BrowserWindow } from 'electron';
import * as path from 'path';

/**
 * メインウィンドウを作成する
 */
function createWindow(): void {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
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
}

// アプリケーションの準備が完了したら実行
app.whenReady().then(() => {
  createWindow();

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
  // macOS以外: 全ウィンドウが閉じられたらアプリを終了
  // macOSではCmd+Qで明示的に終了するまでアプリを終了しない
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
