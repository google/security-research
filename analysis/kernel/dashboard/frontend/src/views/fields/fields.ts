import { View } from "../view";
import { Heap } from "../../controllers/heap";
import { FIELDS_RESULTS } from "../../types";
import TreeView, { TreeViewItem } from "js-treeview";


export class Fields {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'fields-root-node';

    static async getRootNode(): Promise<HTMLDivElement> {
        return Fields.ROOT_NODE = await View.getRootNode(Fields.ROOT_NODE, Fields.ROOT_NODE_CLASS_NAME);
    }
    constructor(private heap: Heap) { }

    displayStructs(parentNode: HTMLDivElement, fieldResults: FIELDS_RESULTS[], struct: string, kmalloc: string) {
        let root = { name: '', children: [] } as TreeViewItem<FIELDS_RESULTS>;
        let fullName = false;

        fieldResults.forEach(field => {
            let pathParts = `${struct}.${field.name}`.split(/[.]|[/][*]|[*][/]/);
            let leaf = root;

            pathParts.forEach((part, index) => {
                if (part == "") {
                    part = `union`;
                }
                let nextLeaf: TreeViewItem<FIELDS_RESULTS> = leaf.children.find(e => e.name == part);
                if (!nextLeaf) {
                    nextLeaf = {
                        expanded: true,
                        get name() {
                            if (fullName) {
                                return `[${this.data!.bits_offset}..${this.data!.bits_end}] ${part} (${this.data!.type})`;
                            }
                            return part;
                        },
                        children: [],
                        data: {
                            bits_offset: field.bits_offset,
                            bits_end: field.bits_end,
                            name: field.name,
                            parent_type: '?',
                            type: part == 'union' ? '...' : 'struct'
                        }
                    };
                    leaf.children.push(nextLeaf);
                } else if (parseInt(nextLeaf.data!.bits_end) < parseInt(field.bits_end)) {
                    nextLeaf.data!.bits_end = field.bits_end
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
        const treeview = new TreeView<FIELDS_RESULTS>(root.children, parentNode);
        treeview.on('select', e => {
            let field = e.data.data!;
            location.hash = `!heap/${kmalloc}/${struct}/${field.bits_offset}..${field.bits_end}`;
        });
    }
}