/**
 * cap モジュールの型定義
 */
declare module 'cap' {
  export class Cap {
    constructor();
    static deviceList(): Array<{ name: string; description?: string; addresses: any[] }>;
    open(device: string, filter: string, bufSize: number, buffer: Buffer): string;
    close(): void;
    on(event: 'packet', listener: (nbytes: number, trunc: boolean) => void): this;
    setMinBytes(size: number): void;
  }

  export const decoders: any;
}
