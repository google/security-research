import { Db } from './db';

import Syzkaller_getCoverageByFileLine from '../../db/sql/syzkaller-6.1.111.db/query-Syzkaller_getCoverageByFileLine.sql';
import Syzkaller_getSyscallsByFileLine from '../../db/sql/syzkaller-6.1.111.db/query-Syzkaller_getSyscallsByFileLine.sql';
import Syzkaller_getAllSyscalls from '../../db/sql/syzkaller-6.1.111.db/query-Syzkaller_getAllSyscalls.sql';
import Syzkaller_getProgramById from '../../db/sql/syzkaller-6.1.111.db/query-Syzkaller_getProgramById.sql';
export class Syzkaller {
    private static DB_PATH: string = '../db/syzkaller-6.1.111.db';

    private constructor(
        private db: Db
    ) {}

    static async init() {
        return new Syzkaller(
            await Db.init(Syzkaller.DB_PATH));
    }

    async getCoverageByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Syzkaller_getCoverageByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            file_path: Db.getColumn(row, 'file_path'),
            code_line_no: Db.getColumn(row, 'code_line_no'),
            prog_id: Db.getColumn(row, 'prog_id'),
        }));
    }

    async getSyscallsByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Syzkaller_getSyscallsByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            syscall: Db.getColumn(row, 'syscall'),
            prog_id: Db.getColumn(row, 'prog_id'),
        }));
    }

    async getAllSyscalls() {
        let rows = await this.db.exec(Syzkaller_getAllSyscalls, {});
        return rows.map(row => ({
            syscall: Db.getColumn(row, 'syscall')
        }));
    }

    async getProgramById($prog_ids: string[]) {
        let rows = await this.db.exec(Syzkaller_getProgramById, {$prog_ids: JSON.stringify($prog_ids)});
        return rows.map(row => ({
            prog_code: Db.getColumn(row, 'prog_code')
        }));
    }
}
