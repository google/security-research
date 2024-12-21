import { View } from "../view";
import { Reachability } from "../../controllers/reachability";
import { COVERAGE_PROGRAMS, CHILD_EDGE_LOCATIONS, PARENT_EDGE_LOCATIONS, SYSCALL_NAMES, SYZKALL_NAMES, CONDITION_LOCATIONS } from '../../types';

import Prism from "../prism";

import "./snippets.css";
import codeSnippetHtml from "./code-snippet.html";
import codeFileHtml from "./code-file.html";
import { interpolateHtml } from "../html";

import TreeView, { TreeViewItem } from 'js-treeview';
import '../treeview.css';
import { Filter } from "./filter";

export class Snippets {
    private static ROOT_NODE: HTMLDivElement | null = null;
    private static ROOT_NODE_CLASS_NAME: string = 'snippets-root-node';

    static async getRootNode(): Promise<HTMLElement> {
        return Snippets.ROOT_NODE = await View.getRootNode(Snippets.ROOT_NODE, Snippets.ROOT_NODE_CLASS_NAME);
    }

    static generateCodeBody(startLine: string, endLine: string, linesOfCode: string[], title: string = "") {
        return interpolateHtml(
            codeSnippetHtml,
            new Map([
                [`//div[@class="code-body"]/@data-start-line`, startLine],
                [`//div[@class="code-body"]/@data-end-line`, endLine],
                [`//div[@class="code-metadata"]/div[@class="code-title"]/text()`, title],
                [`//div[@class="code-snippet"]/pre/@data-start`, startLine],
                [`//div[@class="code-snippet"]/pre/@data-line-offset`, startLine],
                [`//div[@class="code-snippet"]/pre/code/text()`, linesOfCode.join('')]
            ])
        )!;
    }

    static generateCodeFile(filePath: string) {
        return interpolateHtml(codeFileHtml, new Map([
            [`//div[@class="code-file"]/@data-file-path`, filePath],
            [`//div[@class="code-file-path"]/text()`, filePath]
        ]));
    }

    private filter: Filter = new Filter(this.reachability);
    constructor(private reachability: Reachability) { }

    displayLoading(message: string) {
        console.log("Loading", message, this.reachability);
    }

    createSyscallFilters(syscalls: string[]) {
        let style = document.createElement('style');
        document.documentElement.appendChild(style);
        syscalls.forEach(s => {
            style.sheet?.insertRule(
                `.filter-syscall[data-filter-syscall~=${JSON.stringify(s)}] .filtered-syscall[data-filtered-syscall~=${JSON.stringify(s)}] {
                    --filtered-syscall-highlight: var(--filtered-syscall-highlight-hit);
                    --filtered-syscall-color: var(--filtered-syscall-color-hit);
                    --filtered-syscall-outline: var(--filtered-syscall-outline-hit);
                    --filtered-syscall-opacity: var(--filtered-syscall-opacity-hit);
                    --filtered-syscall-appearance: var(--filtered-syscall-appearance-hit);
                    --filtered-syscall-display: var(--filtered-syscall-display-hit);
                }`);
        });
    }

    async displaySnippet(
        parentNode: HTMLElement, filePath: string, linesOfCode: string[],
        startLine = "", title = "",
        childEdgesPromise: Promise<CHILD_EDGE_LOCATIONS[]> | null = null,
        parentEdgesPromise: Promise<PARENT_EDGE_LOCATIONS[]> | null = null,
        coveragePromise: Promise<COVERAGE_PROGRAMS[]> | null = null,
        syscallsPromise: Promise<SYSCALL_NAMES[]> | null = null,
        syzkallsPromise: Promise<SYZKALL_NAMES[]> | null = null,
        conditionsPromise: Promise<CONDITION_LOCATIONS[]> | null = null
    ) {
        let fileNode = parentNode.querySelector(`& > .code-file[data-file-path="${filePath}"]`) as HTMLElement;
        let endLine = String(Number(startLine) + linesOfCode.length - 1);

        if (!fileNode) {
            fileNode = this.createNewFileNode(filePath, parentNode);
        }

        let fileCodeSnippets = fileNode.querySelector('& > .code-snippets')!;

        let surroundings = this.getSurroundingSnippets(
            startLine, [...fileCodeSnippets.querySelectorAll('& > .code-body')]);

        if (surroundings.existingElement) {
            return this.selectExistingElement(surroundings.existingElement);
        }

        let codyBodyFragment = Snippets.generateCodeBody(startLine, endLine, linesOfCode, title);
        let parentFiles = codyBodyFragment.querySelector('.parent-files') as HTMLDivElement;
        let parentBrowser = codyBodyFragment.querySelector('.parent-browser') as HTMLDivElement;
        let codeSnippet = codyBodyFragment.querySelector('.code-snippet pre') as HTMLPreElement;
        let codeMetadata = codyBodyFragment.querySelector('.code-metadata') as HTMLDivElement;
        let codeFilter = codyBodyFragment.querySelector('.code-filter') as HTMLDivElement;

        if (coveragePromise) {
            let coverage = await coveragePromise;
            codeSnippet.dataset.line = [... new Set(coverage.map(c => c.code_line_no))].join(',');
        }

        fileCodeSnippets.insertBefore(
            codyBodyFragment, surroundings.nextInSequence);

        Prism.highlightElement(codeSnippet.querySelector('code')!);

        this.focusElement(codeSnippet);

        if (childEdgesPromise) {
            this.displayChildEdges(childEdgesPromise, fileNode, codeSnippet, filePath, startLine);
        }

        if (parentEdgesPromise) {
            this.displayParentEdges(parentEdgesPromise, parentFiles, parentBrowser);
        }

        if (syscallsPromise && syzkallsPromise && conditionsPromise) {
            this.displaySyscalls(syscallsPromise, syzkallsPromise, conditionsPromise, codeMetadata, codeFilter);
        }

        return codeSnippet;
    }

    addLabel(container: HTMLDivElement, className: string, value: string) {
        let labelNode = container.appendChild(document.createElement('div'));
        labelNode.className = 'label ' + className;
        labelNode.appendChild(document.createTextNode(value));
        return labelNode;
    }

    createNewFileNode(filePath: string, parentNode: Element) {
        let newFileFragment = Snippets.generateCodeFile(filePath);
        let fileNode = newFileFragment.querySelector('.code-file') as HTMLElement;
        fileNode.addEventListener('change', (e) => {
            this.focusElement(e.target as Element);
            this.reachability.updateViews();
        });
        parentNode.appendChild(newFileFragment);
        return fileNode;
    }

    selectExistingElement(existingElement: HTMLDivElement) {
        const snippetCssPath = '> .code-metadata :checked';
            const fileCssPath = '> .code-snippets > .code-file-path-container :checked';
            let collapsedSnippet, collapsedFile;
            do {
                collapsedSnippet = existingElement.closest(`.code-body:has(${snippetCssPath})`);
                collapsedFile = existingElement.closest(`.code-file:has(${fileCssPath})`);
                console.log(collapsedSnippet, collapsedFile);
                if (collapsedSnippet) {
                    (collapsedSnippet.querySelector(`& ${snippetCssPath}`) as HTMLInputElement).checked = false;
                }
                if (collapsedFile) {
                    (collapsedFile.querySelector(`& ${fileCssPath}`) as HTMLInputElement).checked = false;
                }
            } while(collapsedSnippet || collapsedFile);
            let codeSnippet = existingElement.querySelector('& > .code-snippet > pre')!;
            this.focusElement(codeSnippet);
            return codeSnippet;
    }

    async displayChildEdges(childEdgesPromise: Promise<CHILD_EDGE_LOCATIONS[]>, fileNode: HTMLElement, codeSnippet: HTMLPreElement, filePath: string, startLine: string) {
        let childEdges = await childEdgesPromise;
        this.decorateChildEdges(
            fileNode!.querySelector('& > .child-files')!,
            codeSnippet,
            childEdges,
            filePath,
            startLine
        );
        this.reachability.updateViews();
    }

    async displayParentEdges(parentEdgesPromise: Promise<PARENT_EDGE_LOCATIONS[]>, parentFiles: HTMLElement, parentBrowser: HTMLDivElement) {
        let parentEdges = await parentEdgesPromise;
        this.showParentEdges(
            parentFiles,
            parentBrowser,
            parentEdges
        );
        parentBrowser.dataset.loadingFinished = "true";
        this.reachability.updateViews();
    }

    async displaySyscalls(
        syscallsPromise: Promise<SYSCALL_NAMES[]>, syskallsPromise: Promise<SYZKALL_NAMES[]>, conditionsPromise: Promise<CONDITION_LOCATIONS[]>,
        codeMetadata: HTMLDivElement, codeFilter: HTMLDivElement
    ) {
        let syscalls = await syscallsPromise;
        let syscallsLabel = this.addLabel(
            codeMetadata,
            syscalls.length ? 'label-syscalls' : '',
            `syscalls:${syscalls.length}`
        );
        if (syscalls.length) {
            syscallsLabel.addEventListener('click', async () => {
                await this.filter.displaySyscalls(syscalls, syskallsPromise, conditionsPromise, codeFilter);
                this.reachability.updateViews();
            });
        }
    }

    focusElement(codeSnippet: Element) {
        codeSnippet.scrollIntoView({
            behavior: "smooth",
            block: "nearest",
            inline: "nearest"
        });
    }


    getSurroundingSnippets(targetLine: string, codeSnippets: Element[]) {
        let nextInSequence = null;
        let lastInSequence = null;
        let existingElement = null;
        for (let elem of codeSnippets) {
            let htmlNode = elem as HTMLDivElement;
            if (
                htmlNode.dataset.startLine && Number(htmlNode.dataset.startLine) <= Number(targetLine) &&
                htmlNode.dataset.endLine && Number(htmlNode.dataset.endLine) >= Number(targetLine)
            ) {
                existingElement = htmlNode;
                break;
            }
            if (htmlNode.dataset.startLine && Number(htmlNode.dataset.startLine) >= Number(targetLine)) {
                nextInSequence = htmlNode;
                break;
            }
            lastInSequence = htmlNode;
        }
        return { existingElement, lastInSequence, nextInSequence };
    }

    decorateChildEdges(childFiles: HTMLElement, snippet: HTMLPreElement, edges: CHILD_EDGE_LOCATIONS[], filePath: string, startLine: string) {
        [...snippet.querySelectorAll('.token.function')].forEach(node => {
            let functionName = node.textContent;
            let matchingEdges = edges.filter(edge => edge.source_message == "call to " + functionName);
            if (matchingEdges.length == 1) {
                const edge = matchingEdges[0];
                node.classList.add('navigation-edge');
                node.addEventListener('click', async () => {
                    this.reachability.showFileLine(
                        childFiles!,
                        edge!.target_uri,
                        Number(edge!.target_startLine),
                        Number(edge!.target_function_end_line),
                        functionName!,
                        node
                    );
                });
            } else {
                node.classList.add('navigation-missing-edge');
                node.addEventListener('click', async () => {
                    const range = document.createRange();
                    range.setStartBefore(snippet);
                    range.setEndBefore(node);
                    const lineOffset = range.cloneContents().textContent!.split(/\n/).length - 1;
                    const lineNumber = Number(startLine) + lineOffset;
                    this.reachability.displayEdgeSelection(functionName!, filePath, lineNumber, node, childFiles!);
                });
            }
        });
        [...snippet.querySelectorAll('.token.class-name')].forEach(node => {
            let structName = node.textContent;
            node.classList.add('navigation-struct');
            node.addEventListener('click', async () => {
                location.hash = `#!heap/*/${structName}`;
            });
        });
    }

    showParentEdges(parentFiles: HTMLElement, parentBrowser: Element, edges: PARENT_EDGE_LOCATIONS[]) {
        type parentEdgeData = {edge?: PARENT_EDGE_LOCATIONS, syscalls: string[]};
        let root = {name: '', children: []} as TreeViewItem<parentEdgeData>;
        let expanded = edges.length < 30;
        edges.forEach(edge => {
            if (!edge.source_function_names) return;
            let pathParts = [...edge.source_uri.split('/'), edge.source_function_names];
            let leaf = root;
            pathParts.forEach(part => {
                let nextLeaf = leaf.children.find(e => e.name == part);
                if (!nextLeaf) {
                    nextLeaf = {
                        expanded: expanded,
                        name: part.replace(/,/g, '\n'),
                        children: [],
                        data: {syscalls: []}
                    };
                    leaf.children.push(nextLeaf);
                }
                leaf = nextLeaf;
                leaf.data = {syscalls: [...new Set(leaf.data?.syscalls), ...edge.syscalls.split(' ')]};
            });
            leaf.data = {edge, syscalls: [...edge.syscalls.split(' ')]};
        });
        const treeview = new TreeView<parentEdgeData>(root.children, parentBrowser);
        treeview.on('expand', () => this.reachability.updateViews());
        treeview.on('collapse', () => this.reachability.updateViews());
        treeview.on('select', event => {
            const edge = event.data.data!.edge;
            if (!edge) return;
            this.reachability.showFileLine(
                parentFiles,
                edge.source_uri,
                Number(edge.source_function_start_line),
                Number(edge.source_function_end_line),
                event.data.name,
                null
            );
        });
        parentBrowser.querySelectorAll('.tree-leaf-content').forEach(node => {
            let nodeDiv = node as HTMLDivElement;
            let nodeJson = JSON.parse(nodeDiv.dataset.item || '{}');
            nodeDiv.dataset.filteredSyscall = nodeJson.data.syscalls.join(' ');
            nodeDiv.classList.add('filtered-syscall');
        });
    }
}
