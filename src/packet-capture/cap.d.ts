/**
 * capモジュール（libpcapのNode.jsバインディング）の型定義
 * macOS/Linuxではlibpcap、WindowsではWinPcap/Npcapを使用
 */
declare module 'cap' {
  /**
   * パケットキャプチャクラス
   */
  export class Cap {
    /**
     * コンストラクタ
     */
    constructor();

    /**
     * 利用可能なネットワークデバイス一覧を取得（静的メソッド）
     * @returns デバイス情報の配列
     */
    static deviceList(): Array<{
      name: string;           // デバイス名（例: en0, eth0, \Device\NPF_{GUID}）
      description?: string;   // デバイスの説明
      addresses: any[];       // IPアドレス情報
    }>;

    /**
     * パケットキャプチャを開始
     * @param device デバイス名
     * @param filter BPF（Berkeley Packet Filter）フィルタ文字列
     * @param bufSize バッファサイズ（バイト）
     * @param buffer データ受信用バッファ
     * @returns リンクタイプ（例: "ETHERNET"）
     */
    open(device: string, filter: string, bufSize: number, buffer: Buffer): string;

    /**
     * パケット受信イベントのリスナーを登録
     * @param event イベント名（"packet"）
     * @param listener コールバック関数
     */
    on(event: 'packet', listener: (nbytes: number, trunc: boolean) => void): this;

    /**
     * キャプチャを停止
     */
    close(): void;
  }
}
