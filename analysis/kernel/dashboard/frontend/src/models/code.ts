import { Db } from './db';
import { Snippets } from '../views/snippets/snippets';

import Code_getSourceByFileLineSql from '../../db/sql/git_blame-6.1.111.db/query-Code_getSourceByFileLine.sql';

export class Code {
    private static DB_PATH: string = '../db/git_blame-6.1.111.db';

    private constructor(
        private snippets: Snippets,
        private db: Db
    ) {}

    static async init(snippets: Snippets) {
        return new Code(
            snippets,
            await Db.init(Code.DB_PATH));
    }

    async getSourceByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Code_getSourceByFileLineSql, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            file_path: Db.getColumn(row, 'file_path'),
            line_no: Db.getColumn(row, 'line_no'),
            data: Db.getColumn(row, 'data'),
        }));
    }
}