import { Code } from '../models/code';
import { Paths } from '../models/paths';
import { Syzkaller } from '../models/syzkaller';

import { Snippets } from '../views/snippets/snippets';
import { Navigation } from '../views/navigation/navigation';
import { Index } from '..';
import { Dialog } from '../views/dialog/dialog';
import { CHILD_EDGE_LOCATIONS, CONDITION_LOCATIONS } from '../types';

export class Reachability {
    private snippets = new Snippets(this);
    private navigation = new Navigation(this);
    private dialog = new Dialog(this);

    private syscalls = new Set<string>;

    private constructor(
        private index: Index,
        private codePromise: Promise<Code>,
        private pathsPromise: Promise<Paths>,
        private syzkallerPromise: Promise<Syzkaller>
    ) {}

    async onLocationChange(locationHash: string) {
        let identifier = locationHash.slice(1);
        let [$file_path, $start_line, $end_line] = identifier.split(':');
        await Promise.all([
            this.snippets.displayLoading(identifier),
            this.navigation.initNavigation(),
            this.loadAllSyscalls(),
            this.showFileLine(
                await Snippets.getRootNode(),
                $file_path,
                Number($start_line),
                Number($end_line),
                identifier
            )
        ]);
    }

    static async init(index: Index) {
        const reachability: Reachability = new Reachability(
            index,
            Promise.resolve().then(() => Code.init(reachability.snippets)),
            Promise.resolve().then(() => Paths.init()),
            Promise.resolve().then(() => Syzkaller.init())
        );
        return reachability;
    }

    async showFileLine(
        parentNode : HTMLElement,
        $file_path: string, $start_line: number, $end_line: number,
        title: string = "",
        arrowSource: Node | null = null
    ) {
        let promise = this.showFileLineInternal(parentNode, $file_path, $start_line, $end_line, title, arrowSource);
        if (parentNode.style) {
            parentNode.style.cursor = 'progress';
            await promise;
            parentNode.style.cursor = '';
        }
        return promise;
    }

    private async showFileLineInternal(
        parentNode : HTMLElement,
        $file_path: string, $start_line: number, $end_line: number,
        title: string,
        arrowSource: Node | null
    ) {
        const code = await this.codePromise;
        const paths = await this.pathsPromise;
        const syzkaller = await this.syzkallerPromise;

        // end_line = 0 means it is the same as start_line
        $end_line = $end_line || $start_line;
        const coverage = syzkaller.getCoverageByFileLine($file_path, $start_line, $end_line);
        const childEdges = paths.getChildEdgesByFileLine($file_path, $start_line, $end_line);
        const parentEdges = paths.getParentEdgesByFileLine($file_path, $start_line, $end_line);
        const syzkalls = syzkaller.getSyscallsByFileLine($file_path, $start_line, $end_line);
        const syscalls = paths.getSyscallsByFileLine($file_path, $start_line, $end_line);
        const conditions = paths.getConditionsByFileLine($file_path, $start_line, $end_line);
        const linesOfCode = await code.getSourceByFileLine($file_path, $start_line, $end_line);
        if (linesOfCode.length == 0) {
            console.log('No code found for', $file_path, $start_line, $end_line);
            return;
        }

        let snippet = await this.snippets.displaySnippet(
            parentNode,
            $file_path,
            linesOfCode.map(loc => loc.data),
            linesOfCode[0].line_no,
            title,
            childEdges,
            parentEdges,
            coverage,
            syscalls,
            syzkalls,
            conditions
        );

        if (arrowSource) {
            this.navigation.addLine(arrowSource, snippet);
        }

        this.updateViews();

        console.log(await Promise.all([
            'loc', linesOfCode, 'cov', coverage,
            'chi', childEdges, 'par', parentEdges,
            'sys', syscalls, 'syz', syzkalls
        ]));
    }

    async displaySyzkallerPrograms(programs: string[]) {
        let syzkaller = await this.syzkallerPromise;
        this.dialog.displaySyzkallerPrograms(
            await Dialog.getRootNode(),
            await syzkaller.getProgramById(programs)
        );
    }

    async displayConditions(conditions: CONDITION_LOCATIONS[]) {
        this.dialog.displayConditions(
            await Dialog.getRootNode(),
            conditions
        );
    }

    async displayEdgeSelection(
        functionName: string, filePath: string, lineNumber: number,
        node: Node, childEdges: HTMLElement
    ) {
        const paths = await this.pathsPromise;
        const allEdges = await paths.getAllEdgesFromFileLine(filePath, lineNumber);
        this.dialog.displayEdgeSelection(
            await Dialog.getRootNode(),
            allEdges, functionName,
            node, childEdges
        );
    }

    async loadAllSyscalls() {
        let syzkaller = await this.syzkallerPromise;
        let paths = await this.pathsPromise;
        [
            ...(await syzkaller.getAllSyscalls()),
            ...(await paths.getAllSyscalls())
        ].forEach(row => this.syscalls.add(row.syscall));
        let syscalls = this.syscalls.values();
        this.snippets.createSyscallFilters([...syscalls]);
    }

    updateViews() {
        this.navigation.updateLinesPositions();
    }
}
