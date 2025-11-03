import { View } from "../view";
import { Reachability } from "../../controllers/reachability";

import { interpolateHtml } from "../html";
import dialogSyzkallerHtml from "./dialog-syzkaller.html";
import dialogSyzkallerProgramHtml from "./dialog-syzkaller-program.html";
import dialogConditionsHtml from "./dialog-conditions.html";
import dialogConditionsDecriptionHtml from "./dialog-conditions-description.html";
import dialogEdgeSelectionHtml from "./dialog-edge-selection.html";
import dialogEdgeSelectionDescriptionHtml from "./dialog-edge-selection-description.html";

import "./dialog.css";
import { ALL_EDGES_LOCATIONS, CONDITION_LOCATIONS } from "../../types";

export class Dialog {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'dialog-root-node';

    static async getRootNode(): Promise<HTMLDivElement> {
        return Dialog.ROOT_NODE = await View.getRootNode(Dialog.ROOT_NODE, Dialog.ROOT_NODE_CLASS_NAME);
    }
    constructor(private reachability: Reachability) { }

    static generateSyzkallerDialog() {
        return interpolateHtml(dialogSyzkallerHtml, new Map());
    }

    static generateConditionsDialog() {
        return interpolateHtml(dialogConditionsHtml, new Map());
    }

    static generateSyzkallerDialogProgram(code: string) {
        return interpolateHtml(dialogSyzkallerProgramHtml, new Map([
            [`//code/text()`, code]
        ]));
    }

    static generateConditionDecription(condition: string, file_path: string, start_line: string, end_line: string) {
        return interpolateHtml(dialogConditionsDecriptionHtml, new Map([
            [`//a/text()`, condition],
            [`//a/@href`, `#${file_path}:${start_line}:${end_line}`]
        ]));
    }

    static generateEdgeSelectionDialog() {
        return interpolateHtml(dialogEdgeSelectionHtml, new Map());
    }

    static generateEdgeSelectionDescription(type: string, identifier: string) {
        return interpolateHtml(dialogEdgeSelectionDescriptionHtml, new Map([
            [`//button/text()`, `${type}: ${identifier}`]
        ]));
    }

    displaySyzkallerPrograms(parentNode: HTMLDivElement, programs: { prog_code: string }[]) {
        let dialogFragment = Dialog.generateSyzkallerDialog();
        let syzkallerPrograms = dialogFragment.querySelector('.syzkaller-programs') as HTMLDivElement;
        let dialog = dialogFragment.querySelector('dialog');
        for (let program of programs) {
            syzkallerPrograms.appendChild(Dialog.generateSyzkallerDialogProgram(program.prog_code));
        }
        parentNode.replaceChildren(dialogFragment);
        dialog!.showModal()
    }

    displayConditions(parentNode: HTMLDivElement, conditions: CONDITION_LOCATIONS[]) {
        let dialogFragment = Dialog.generateConditionsDialog();
        let syscallConditions = dialogFragment.querySelector('.syscall-conditions') as HTMLDivElement;
        let dialog = dialogFragment.querySelector('dialog');
        for (let condition of conditions) {
            syscallConditions.appendChild(Dialog.generateConditionDecription(
                `${condition.condition_type}(${
                    condition.condition_type.match(/capable/)?
                        this.bitMaskToNames(condition.condition_argument):
                        condition.condition_argument
                })`,
                condition.function_call_file_path,
                condition.function_call_start_line,
                condition.function_call_end_line
            ));
        }
        parentNode.replaceChildren(dialogFragment);
        dialog!.showModal();
    }

    displayEdgeSelection(parentNode: HTMLDivElement, edges: ALL_EDGES_LOCATIONS[], functionName: string, node: Node, childEdges: HTMLElement) {
        let dialogFragment = Dialog.generateEdgeSelectionDialog();
        let edgeSelection = dialogFragment.querySelector('.edge-selection') as HTMLUListElement;
        let dialog = dialogFragment.querySelector('dialog');
        for (let edge of edges) {
            let edgeNode;
            if (edge.identifier == functionName || edge.identifier == 'call to ' + functionName) {
                edgeNode = Dialog.generateEdgeSelectionDescription(
                    edge.edge_type,
                    edge.identifier
                );
                edgeNode.querySelector('button')!.onclick = () => {
                    console.log('yikes');
                    this.reachability.showFileLine(childEdges, edge.file_path, Number(edge.start_line), Number(edge.end_line), edge.identifier, node);
                };
                edgeSelection.appendChild(edgeNode);
            } else {
                console.log('refused to link', edge.identifier, 'and', functionName);
            }
        }
        parentNode.replaceChildren(dialogFragment);
        dialog!.showModal();
    }

    bitMaskToNames(capability: string) {
        if (!capability.match(/^\d+$/)) return capability;
        const BIT_TO_CAP = new Map([
            [0, 'CAP_CHOWN'],
            [1, 'CAP_DAC_OVERRIDE'],
            [2, 'CAP_DAC_READ_SEARCH'],
            [3, 'CAP_FOWNER'],
            [4, 'CAP_FSETID'],
            [5, 'CAP_KILL'],
            [6, 'CAP_SETGID'],
            [7, 'CAP_SETUID'],
            [8, 'CAP_SETPCAP'],
            [9, 'CAP_LINUX_IMMUTABLE'],
            [10, 'CAP_NET_BIND_SERVICE'],
            [11, 'CAP_NET_BROADCAST'],
            [12, 'CAP_NET_ADMIN'],
            [13, 'CAP_NET_RAW'],
            [14, 'CAP_IPC_LOCK'],
            [15, 'CAP_IPC_OWNER'],
            [16, 'CAP_SYS_MODULE'],
            [17, 'CAP_SYS_RAWIO'],
            [18, 'CAP_SYS_CHROOT'],
            [19, 'CAP_SYS_PTRACE'],
            [20, 'CAP_SYS_PACCT'],
            [21, 'CAP_SYS_ADMIN'],
            [22, 'CAP_SYS_BOOT'],
            [23, 'CAP_SYS_NICE'],
            [24, 'CAP_SYS_RESOURCE'],
            [25, 'CAP_SYS_TIME'],
            [26, 'CAP_SYS_TTY_CONFIG'],
            [27, 'CAP_MKNOD'],
            [28, 'CAP_LEASE'],
            [29, 'CAP_AUDIT_WRITE'],
            [30, 'CAP_AUDIT_CONTROL'],
            [31, 'CAP_SETFCAP'],
            [32, 'CAP_MAC_OVERRIDE'],
            [33, 'CAP_MAC_ADMIN'],
            [34, 'CAP_SYSLOG'],
            [35, 'CAP_WAKE_ALARM'],
            [36, 'CAP_BLOCK_SUSPEND'],
            [37, 'CAP_AUDIT_READ'],
            [38, 'CAP_PERFMON'],
            [39, 'CAP_BPF'],
            [40, 'CAP_CHECKPOINT_RESTORE'],
        ]);
        return BIT_TO_CAP.get(Number(capability)) || "unknown";
    }
}