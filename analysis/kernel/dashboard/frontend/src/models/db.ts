import { createSQLiteHTTPPool, SQLiteHTTPPool } from 'sqlite-wasm-http';

export class Db {
    static getColumn(row: ({ row: string, columnNames: string[] }), columnName: string) {
        return row.row[row.columnNames.indexOf(columnName)];
    }

    private constructor(private pool: SQLiteHTTPPool) { }

    static async init(dbPath: string) {
        const pool = await createSQLiteHTTPPool({});
        pool.open(dbPath);
        return new Db(pool);
    }

    async exec(query: string, params: Record<string, any>) {
        console.debug(query, params);
        const result = this.pool.exec(query, params);
        console.debug(await result);
        return result;
    }
}