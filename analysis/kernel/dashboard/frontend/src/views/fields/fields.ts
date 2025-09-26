import { View } from "../view";
import { Heap } from "../../controllers/heap";
import { FIELDS_RESULTS } from "../../types";
import ThreeView, { ThreeViewItem } from "../three/three";


export class Fields {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'fields-root-node';

    static async getRootNode(): Promise<HTMLDivElement> {
        Fields.ROOT_NODE = await View.getRootNode(Fields.ROOT_NODE, Fields.ROOT_NODE_CLASS_NAME);
        Fields.ROOT_NODE.role = "tree";
        return Fields.ROOT_NODE;
    }
    constructor(private heap: Heap) { }

    displayStructs(parentNode: HTMLDivElement, fieldResults: FIELDS_RESULTS[], struct: string, kmalloc: string, kmalloc_cache_name: string|undefined, kmalloc_cgroup_name: string|undefined, bits_offset: string, bits_end: string) {
        let root = { name: '', children: [] } as ThreeViewItem<FIELDS_RESULTS>;
        let fullName = false;

        fieldResults.forEach(field => {
            let pathParts = `${struct}.${field.name}`.split(/[.]|[/][*]|[*][/]/);
            let leaf = root;

            pathParts.forEach((part, index) => {
                if (part == "") {
                    part = `union`;
                }
                let nextLeaf = leaf.children?.find(e => e.name == part);
                if (!nextLeaf) {
                    nextLeaf = {
                        expanded: true,
                        selected: bits_offset == field.bits_offset && bits_end == field.bits_end,
                        get name() {
                            if (fullName) {
                                return `[${this.data!.bits_offset}..${this.data!.bits_end}] ${part} (${this.data!.type})`;
                            }
                            return part;
                        },
                        label: part,
                        children: [],
                        data: {
                            bits_offset: field.bits_offset,
                            bits_end: field.bits_end,
                            name: field.name,
                            parent_type: '?',
                            type: part == 'union' ? '...' : 'struct'
                        }
                    };
                    leaf.children?.push(nextLeaf);
                } else if (parseInt(nextLeaf.data!.bits_end) < parseInt(field.bits_end)) {
                    nextLeaf.data!.bits_end = field.bits_end;
                    nextLeaf.selected = bits_offset == nextLeaf.data!.bits_offset && bits_end == field.bits_end;
                }
                if (index == pathParts.length - 1) {
                    nextLeaf.data!.type = field.type;
                    nextLeaf.data!.parent_type = field.parent_type;
                } else if (index == pathParts.length - 2) {
                    nextLeaf.data!.type = field.parent_type;
                }
                leaf = nextLeaf;
            });
        });
        fullName = true;
        parentNode.replaceChildren();
        const treeview = new ThreeView<FIELDS_RESULTS>(root.children, parentNode);
        treeview.on('select', e => {
            let field = e.data.data!;
            history.pushState(null, '', `#!heap/${kmalloc}/${struct}/${field.bits_offset}..${field.bits_end}`);
            this.heap.displayAccess(
                Number(field.bits_offset),
                Number(field.bits_end),
                struct,
                kmalloc,
                kmalloc_cache_name,
                kmalloc_cgroup_name,
                0);
        });
        let sel = treeview.getSelected();
        switch(sel?.length) {
            case undefined:
            case 0:
                treeview.focus(treeview.getFirst());
                break;
            case 1:
                break;
            default:
                treeview.select(sel![0]);
        }
    }
}