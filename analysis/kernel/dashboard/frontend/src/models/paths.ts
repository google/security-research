import { Db } from './db';
import { CHILD_EDGE_LOCATIONS } from '../types';

import Paths_getChildEdgesByFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getChildEdgesByFileLine.sql';
import Paths_getParentEdgesByFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getParentEdgesByFileLine.sql';
import Paths_getSyscallsByFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getSyscallsByFileLine.sql';
import Paths_getSyscallParentEdgesByFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getSyscallParentEdgesByFileLine.sql';
import Paths_getAllSyscalls from '../../db/sql/codeql_data-6.1.db/query-Paths_getAllSyscalls.sql';
import Paths_getConditionsByFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getConditionsByFileLine.sql';
import Paths_getAllEdgesFromFileLine from '../../db/sql/codeql_data-6.1.db/query-Paths_getAllEdgesFromFileLine.sql';
export class Paths {
    private static DB_PATH: string = '../db/codeql_data-6.1.db';

    private constructor(
        private db: Db
    ) {}

    static async init() {
        return new Paths(
            await Db.init(Paths.DB_PATH));
    }

    async getChildEdgesByFileLine($file_path: string, $start_line: number, $end_line: number): Promise<CHILD_EDGE_LOCATIONS[]> {
        let rows = await this.db.exec(Paths_getChildEdgesByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            source_message: Db.getColumn(row, 'source_message'),
            target_startLine: Db.getColumn(row, 'target_startLine'),
            target_uri: Db.getColumn(row, 'target_uri'),
            target_function_end_line: Db.getColumn(row, 'target_function_end_line')
        }));
    }

    async getParentEdgesByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Paths_getParentEdgesByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            source_uri: Db.getColumn(row, 'source_uri'),
            source_function_start_line: Db.getColumn(row, 'source_function_start_line'),
            source_function_end_line: Db.getColumn(row, 'source_function_end_line'),
            source_function_names: Db.getColumn(row, 'source_function_names'),
            syscalls: Db.getColumn(row, 'syscalls'),
        }));
    }

    async getSyscallsByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Paths_getSyscallsByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            syscall: Db.getColumn(row, 'syscall')
        }));
    }

    async getConditionsByFileLine($file_path: string, $start_line: number, $end_line: number) {
        let rows = await this.db.exec(Paths_getConditionsByFileLine, {
            $file_path, $start_line, $end_line
        });
        return rows.map(row => ({
            syscall: Db.getColumn(row, 'syscall'),
            condition_type: Db.getColumn(row, 'condition_type'),
            condition_argument: Db.getColumn(row, 'condition_argument'),
            function_call_file_path: Db.getColumn(row, 'function_call_file_path'),
            function_call_start_line: Db.getColumn(row, 'function_call_start_line'),
            function_call_end_line: Db.getColumn(row, 'function_call_end_line')
        }));
    }

    async getAllSyscalls() {
        let rows = await this.db.exec(Paths_getAllSyscalls, {});
        return rows.map(row => ({
            syscall: Db.getColumn(row, 'syscall')
        }));
    }

    async getSyscallParentEdgesByFileLine($syscall: string, $file_path: string, $start_line: number, $end_line: number, $depth = 3, $limit = 1000, $offset = 0) {
        let rows = await this.db.exec(Paths_getSyscallParentEdgesByFileLine, {
            $syscall, $file_path, $end_line, $depth, $limit, $offset
        });
        return rows.map(row => ({
            caller_uri: Db.getColumn(row, 'caller_uri'),
            caller_endLine: Db.getColumn(row, 'caller_endLine'),
            callee_uri: Db.getColumn(row, 'callee_uri'),
            callee_endLine: Db.getColumn(row, 'callee_endLine')
        }));
    }

    async getAllEdgesFromFileLine($file_path: string, $start_line: number) {
        let rows = await this.db.exec(Paths_getAllEdgesFromFileLine, {
            $file_path, $start_line
        });
        return rows.map(row => ({
            edge_type: Db.getColumn(row, 'edge_type'),
            identifier: Db.getColumn(row, 'identifier'),
            file_path: Db.getColumn(row, 'file_path'),
            start_line: Db.getColumn(row, 'start_line'),
            end_line: Db.getColumn(row, 'end_line')
        }));
    }
}
