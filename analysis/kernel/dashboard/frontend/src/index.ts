import { Reachability } from './controllers/reachability';
import { Heap } from './controllers/heap';

import "./index.css";

export class Index {

  private constructor(
    private reachabilityPromise: Promise<Reachability>,
    private heapPromise: Promise<Heap>
  ) { }

  async onLocationChange(locationHash: string) {
    switch (true) {
      case !!locationHash.match(/^#!heap/):
        await (await this.heapPromise).onLocationChange(locationHash);
        (document.querySelector('.struct-explorer') as HTMLDivElement).focus();
        break;
      case !!locationHash.match(/^#\w+[/]/):
        await (await this.reachabilityPromise).onLocationChange(locationHash);
        break;
      default:
        console.error(404);
        return;
    }
  }

  static async init() {
    let index: Index = new Index(
      Promise.resolve().then(() => Reachability.init(index)),
      Promise.resolve().then(() => Heap.init(index))
    );
    document.onreadystatechange = onhashchange = async () => {
      document.documentElement.style.cursor = 'progress';
      await index.onLocationChange(location.hash);
      document.documentElement.style.cursor = '';
    };
    return index;
  }
}

Index.init();