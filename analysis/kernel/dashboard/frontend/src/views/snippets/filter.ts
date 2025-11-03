import { Reachability } from "../../controllers/reachability";
import { CONDITION_LOCATIONS, SYSCALL_NAMES, SYZKALL_NAMES } from "../../types";
import { interpolateHtml } from "../html";

import codeFilterTableHtml from "./code-filter-table.html";
import codeFilterSyscallHtml from "./code-filter-syscall.html";

export class Filter {
    private static changeAbortControllers = new WeakMap<HTMLDivElement, AbortController>();

    private static uidCounter = 0;

    static generateCodeFilterSyscall(syscall: string, coverage: string, conditions: string): any {
        let uid = `uid-${Filter.uidCounter++}`;
        return interpolateHtml(codeFilterSyscallHtml, new Map([
            [`//div[@data-filtered-syscall]/@data-filtered-syscall`, syscall],
            [`//div[@data-filtered-coverage]/@data-filtered-coverage`, `any ${coverage}`],
            [`//div[@data-filtered-conditions]/@data-filtered-conditions`, `any ${conditions}`],
            [`//div[@class="code-filter-syscall-checkbox"]/input/@id`, uid],
            [`//div[@class="code-filter-syscall-checkbox"]/input/@value`, syscall],
            [`//label[@class="code-filter-syscall-name"]/@for`, uid],
            [`//label[@class="code-filter-syscall-name"]/text()`, syscall],
            [`//div[@class="code-filter-syscall-coverage"]/text()`, coverage],
            [`//div[@class="code-filter-syscall-conditions"]/text()`, conditions],
        ]));
    }

    static generateCodeFilterTable() {
        let uid = `uid-${Filter.uidCounter++}`;
        return interpolateHtml(codeFilterTableHtml, new Map([
            [`//input/@id`, uid],
            [`//label/@for`, uid]
        ]));
    }

    constructor(private reachability: Reachability) { }

    async displaySyscalls(
        syscalls: SYSCALL_NAMES[], syskallsPromise: Promise<SYZKALL_NAMES[]>, conditionsPromise: Promise<CONDITION_LOCATIONS[]>,
        codeFilter: HTMLDivElement
    ) {
        let syzkalls = await syskallsPromise;
        let codeBody = codeFilter.closest('.code-body') as HTMLDivElement;
        let outerCodeBody = codeBody.closest('.code-body.filter-syscall[data-filter-syscall]') as HTMLDivElement | null;
        let defaultSelectedSyscallsFromParent = null;
        if (outerCodeBody) {
            defaultSelectedSyscallsFromParent = new Set(outerCodeBody.dataset.filterSyscall?.split(' '));
        }
        let defaultUnselectedSyscallsFromChildren = new Set<string>();
        codeBody.querySelectorAll('.code-body .code-filter-syscall-checkbox-input:not(:checked)').forEach(
            input => defaultUnselectedSyscallsFromChildren.add((input as HTMLInputElement).value));
        let syscallMap = new Map();

        const updateCheckboxes = () => {
            codeBody.dataset.filterSyscall = [...syscallMap.entries()].filter(v =>
                v[1].checked && (v[1] as any).checkVisibility()
            ).map(v => v[0]).join(' ');
        };

        const changeHandler = (e: Event) => {
            let eventElement = e.target as HTMLInputElement;
            let checkboxElement = syscallMap.get(eventElement.value);
            if (checkboxElement) {
                checkboxElement.checked = eventElement.checked;
            }
            updateCheckboxes();
        };

        if (codeFilter.children.length) {
            this.clearSyscallFilter(codeBody, codeFilter);
        } else {
            this.applySyscallFilter(
                syscalls, syzkalls, await conditionsPromise,
                codeBody, codeFilter,
                syscallMap,
                updateCheckboxes, changeHandler,
                defaultSelectedSyscallsFromParent, defaultUnselectedSyscallsFromChildren
            );
        }
    }

    private clearSyscallFilter(codeBody: HTMLDivElement, codeFilter: HTMLDivElement) {
        codeBody.classList.remove('filter-syscall');
        codeFilter.replaceChildren();
        Filter.changeAbortControllers.get(codeBody)?.abort();
    }

    private applySyscallFilter(
        syscalls: SYSCALL_NAMES[],
        syzkalls: SYZKALL_NAMES[],
        conditions: CONDITION_LOCATIONS[],
        codeBody: HTMLDivElement,
        codeFilter: HTMLDivElement,
        syscallMap: Map<string, HTMLInputElement>,
        updateCheckboxes: () => void,
        changeHandler: (e: Event) => void,
        defaultSelectedSyscallsFromParent: Set<string> | null,
        defaultUnselectedSyscallsFromChildren: Set<string>
    ) {
        codeBody.classList.add('filter-syscall');
        let codeFilterTableFragment = Filter.generateCodeFilterTable();
        let codeFilterTable = codeFilterTableFragment.querySelector('.code-filter-table') as HTMLDivElement;
        codeFilter.replaceChildren(codeFilterTableFragment);

        codeFilterTable.querySelectorAll('select').forEach(select =>
            select.addEventListener('change', (e: Event) => {
                codeFilterTable.setAttribute(`data-filter-${select.name}`, `${select.value}`);
                updateCheckboxes();
            })
        );

        codeFilterTable.querySelector('.code-filter-header input')?.addEventListener('change', (e) => {
            let master = e.target as HTMLInputElement;
            codeFilterTable.querySelectorAll('.code-filter-syscall-checkbox-input').forEach(elem => {
                const input = elem as HTMLInputElement;
                if ((elem as any).checkVisibility()) {
                    input.checked = master.checked;
                }
            });
            updateCheckboxes();
        });

        for (let syscall of syscalls) {
            const hasCoverage = syzkalls.some(s => s.syscall == syscall.syscall);
            const syzPrograms = syzkalls.filter(s => s.syscall == syscall.syscall).map(s => s.prog_id);
            const filteredConditions = conditions.filter(s => s.syscall == syscall.syscall);
            let conditionSummarySet = new Set<string>;
            filteredConditions.forEach((entry) => {
                conditionSummarySet.add(entry.condition_type[0]);
            });
            let conditionSummary = [...conditionSummarySet];

            let syscallFragment = Filter.generateCodeFilterSyscall(
                syscall.syscall,
                hasCoverage ? 'yes' : 'no',
                conditionSummary.join(' '),
            );
            let syscallCheckbox = syscallFragment.querySelector('input') as HTMLInputElement;
            let syzkallerLink = syscallFragment.querySelector('.code-filter-syscall-coverage') as HTMLDivElement;
            let conditionLink = syscallFragment.querySelector('.code-filter-syscall-conditions') as HTMLDivElement;
            syscallMap.set(syscall.syscall, syscallCheckbox);
            codeFilterTable.appendChild(syscallFragment);

            if (defaultSelectedSyscallsFromParent) {
                syscallCheckbox.checked = defaultSelectedSyscallsFromParent.has(syscall.syscall);
            }
            syscallCheckbox.checked = syscallCheckbox.checked && !defaultUnselectedSyscallsFromChildren.has(syscall.syscall);

            if (hasCoverage) {
                syzkallerLink.classList.add('code-filter-syscall-coverage-link');
                syzkallerLink.addEventListener('click', e => {
                    this.reachability.displaySyzkallerPrograms(syzPrograms);
                });
            }

            if (conditionSummary.length) {
                conditionLink.classList.add('code-filter-syscall-condition-link');
                conditionLink.addEventListener('click', e => {
                    this.reachability.displayConditions(filteredConditions);
                });
            }
        }

        updateCheckboxes();
        let abortController = new AbortController;
        Filter.changeAbortControllers.set(codeBody, abortController);
        codeBody.addEventListener('change', changeHandler, {
            signal: abortController.signal
        });
    }
}