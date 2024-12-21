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
                [`//a[@class="struct-name"]/@href`, `#!heap/${kmalloc}/${struct_name}`],
                [`//a[@class="struct-name"]/text()`, struct_name],
                [`//span[@class="struct-alloc-num"]/text()`, String(allocs.size)]
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
                    [`//a[@class="struct-alloc-cache"]/@href`, `#!heap/${kmalloc}/${struct}`],
                    [`//a[@class="struct-alloc-cache"]/text()`, kmalloc],
                    [`//div[@class="struct-alloc-call"]/text()`, `${alloc.call_value}`],
                    [`//a[@class="struct-alloc-link"]/@href`, `#${alloc.call_uri}:${alloc.function_start_line}:${alloc.function_end_line}`],
                    [`//a[@class="struct-alloc-link"]/text()`, `${alloc.call_uri}#${alloc.call_startLine}`],
                    [`//a[@class="struct-alloc-link"]/@title`, `${alloc.function}`],
                    [`//span[@class="struct-alloc-syscalls-num"]/text()`, `${alloc.syscalls_num}`]
                ]));
                structAlloc!.appendChild(structAllocFragment);
            });
        });;
        parentNode.replaceChildren(structListFragment);
    }
}