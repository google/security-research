import { View } from "../view";
import { Heap } from "../../controllers/heap";
import { interpolateHtml } from "../html";

import accessListHtml from "./access-list.html";
import accessFieldHtml from "./access-field.html";
import accessCallHtml from "./access-call.html";

import { ACCESS_RESULTS } from "../../types";

export class Access {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'access-root-node';

    static async getRootNode(): Promise<HTMLDivElement> {
        return Access.ROOT_NODE = await View.getRootNode(Access.ROOT_NODE, Access.ROOT_NODE_CLASS_NAME);
    }
    constructor(private reachability: Heap) { }

    static generateAccessList() {
        return interpolateHtml(accessListHtml, new Map())!;
    }

    static generateAccessField(entry: ACCESS_RESULTS, size: number, kmalloc: string) {
        return interpolateHtml(accessFieldHtml, new Map([
            [`//*[@class="access-field-struct-name"]/text()`, `${entry.struct_name}`],
            [`//*[@class="access-field-struct-name"]/@href`, `#!heap/${kmalloc}/${entry.struct_name}`],
            [`//*[@class="access-field-full-name"]/text()`, `${entry.full_field_name}`],
            [`//*[@class="access-field-type"]/text()`, `${entry.type}`],
            [`//*[@class="access-field-bit-range-link"]/@href`, `#!heap/${kmalloc}/${entry.struct_name}/${entry.bits_offset}..${entry.bits_end}`],
            [`//*[@class="access-field-bits-offset"]/text()`, `${entry.bits_offset}`],
            [`//*[@class="access-field-bits-end"]/text()`, `${entry.bits_end}`],
            [`//*[@class="access-field-calls-size"]/text()`, `${size}`]
        ]))!;
    }

    static generateAccessCall(entry: ACCESS_RESULTS) {
        return interpolateHtml(accessCallHtml, new Map([
            [`//*[@class="access-call-type"]/text()`, entry.field_access_type],
            [`//*[@class="access-call-link"]/@href`, `#${entry.function_file_path}:${entry.function_start_line}:${entry.function_end_line}`],
            [`//*[@class="access-call-link"]/text()`, `${entry.function_file_path}#${entry.field_access_start_line}`],
            [`//*[@class="access-call-syscalls-num"]/text()`, entry.syscalls_num]
        ]))!;
    }

    displayAccess(parentNode: HTMLDivElement, results: ACCESS_RESULTS[], kmalloc: string, offset: number) {
        let accessListFragment = Access.generateAccessList();
        let accessList = accessListFragment.querySelector('.access-list')!;
        parentNode.replaceChildren(accessListFragment);

        results.reduce((map, result) => {
            let key = JSON.stringify((({
                struct_name, full_field_name, bits_offset, bits_end, type
            }) => ({
                struct_name, full_field_name, bits_offset, bits_end, type
            }))(result));
            if (!map.has(key)) {
                map.set(key, new Set<ACCESS_RESULTS>);
            }
            map.get(key)!.add(result);
            return map;
        }, new Map<string, Set<ACCESS_RESULTS>>).forEach((accesses, key) => {
            let accessFieldFragment = Access.generateAccessField(
                accesses.entries().next().value[0], accesses.size, kmalloc);
            let accessCalls = accessFieldFragment.querySelector('.access-calls')!;
            accessList.appendChild(accessFieldFragment);
            accesses.forEach(access => {
                let accessCallFragment = Access.generateAccessCall(access);
                accessCalls.appendChild(accessCallFragment);
            });
        });
    }
}