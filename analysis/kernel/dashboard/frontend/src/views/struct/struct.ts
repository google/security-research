import { View } from "../view";
import { Heap } from "../../controllers/heap";
import { STRUCT_RESULTS } from "../../types";
import { interpolateHtml } from "../html";

import structListHtml from "./struct-list.html";
import structEntryHtml from "./struct-entry.html";
import structAllocHtml from "./struct-alloc.html";

import "./struct.css";

export class Struct {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'struct-root-node';

    static async getRootNode(): Promise<HTMLDivElement> {
        return Struct.ROOT_NODE = await View.getRootNode(Struct.ROOT_NODE, Struct.ROOT_NODE_CLASS_NAME);
    }
    constructor(private heap: Heap) { }

    displayStructs(parentNode: HTMLDivElement, structResults: STRUCT_RESULTS[], kmalloc: string, struct: string, offset:  number) {
        let structListFragment = interpolateHtml(structListHtml, new Map());
        let structList = structListFragment.querySelector('.struct-list') as HTMLDivElement;
        structResults.reduce((map, result) => {
            if (!map.has(result.struct_name)) {
                map.set(result.struct_name, new Set<STRUCT_RESULTS>);
            }
            if (result.kmalloc_bucket_name) {
                map.get(result.struct_name)!.add(result);
            }
            return map;
        }, new Map<string, Set<STRUCT_RESULTS>>).forEach((allocs, struct_name) => {
            let structEntryFragment = interpolateHtml(structEntryHtml, new Map([
                [`//*[@class="struct-entry-container"]/@aria-rowspan`, `${allocs.size + 1}`],
                [`//*[@class="struct-name"]/a/@href`, `#!heap/${kmalloc}/${struct_name}`],
                [`//*[@class="struct-name"]/a/text()`, struct_name],
                [`//*[@class="struct-alloc-num"]/text()`, `${allocs.size}`]
            ]));
            let structEntry = structEntryFragment.querySelector('.struct-entry');
            let structAlloc = structEntryFragment.querySelector('.struct-alloc');
            structList.appendChild(structEntryFragment);
            allocs.forEach(alloc => {
                const kmalloc = `kmalloc-${
                    alloc.kmalloc_cgroup_name?"cg-":""
                }${
                    alloc.kmalloc_bucket_name
                }${
                    alloc.kmalloc_dyn?"-dyn":""
                }`;
                let structAllocFragment = interpolateHtml(structAllocHtml, new Map([
                    [`//*[@class="struct-alloc-cache"]/a/@href`, `#!heap/${kmalloc}/${struct}`],
                    [`//*[@class="struct-alloc-cache"]/a/text()`, kmalloc],
                    [`//*[@class="struct-alloc-call"]/text()`, `${alloc.call_value}`],
                    [`//*[@class="struct-alloc-link"]/a/@href`, `#${alloc.call_uri}:${alloc.function_start_line}:${alloc.function_end_line}`],
                    [`//*[@class="struct-alloc-link"]/a/text()`, `${alloc.call_uri}#${alloc.call_startLine}`],
                    [`//*[@class="struct-alloc-link"]/a/@title`, `${alloc.function}`],
                    [`//*[@class="struct-alloc-syscalls-num"]/text()`, `${alloc.syscalls_num}`]
                ]));
                structAlloc!.appendChild(structAllocFragment);
            });
        });;
        parentNode.replaceChildren(structListFragment);
    }
}