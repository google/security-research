import { Db } from './db';

import Btf_getStructsByStructName from '../../db/sql/btf-kernelctf-6_1_111.db/query-Btf_getStructsByStructName.sql';
import Btf_getStructsByAllocation from '../../db/sql/btf-kernelctf-6_1_111.db/query-Btf_getStructsByAllocation.sql';
import Btf_getFieldsByStructName from '../../db/sql/btf-kernelctf-6_1_111.db/query-Btf_getFieldsByStructName.sql';
import Btf_getAccessByCache from '../../db/sql/btf-kernelctf-6_1_111.db/query-Btf_getAccessByCache.sql';
import Btf_getAccessByStruct from '../../db/sql/btf-kernelctf-6_1_111.db/query-Btf_getAccessByStruct.sql';

import { ACCESS_RESULTS, STRUCT_RESULTS } from '../types';

export class Btf {
  private static DB_PATH: string = '../db/btf-kernelctf-6_1_111.db';

  private constructor(
    private db: Db
  ) { }

  static async init() {
    return new Btf(
      await Db.init(Btf.DB_PATH));
  }

  async getStructsByStructName($struct_name: string): Promise<STRUCT_RESULTS[]> {
    let rows = await this.db.exec(Btf_getStructsByStructName, {
      $struct_name
    });
    return rows.map(row => ({
        struct_name: Db.getColumn(row, 'struct_name'),
        struct_size: Db.getColumn(row, 'struct_size'),
        allocSizeMax: Db.getColumn(row, 'allocSizeMax'),
        allocSizeMin: Db.getColumn(row, 'allocSizeMin'),
        allocSize: Db.getColumn(row, 'allocSize'),
        call_startLine: Db.getColumn(row, 'call_startLine'),
        call_uri: Db.getColumn(row, 'call_uri'),
        call_value: Db.getColumn(row, 'call_value'),
        depth: Db.getColumn(row, 'depth'),
        flagsMax: Db.getColumn(row, 'flagsMax'),
        flagsMin: Db.getColumn(row, 'flagsMin'),
        flags: Db.getColumn(row, 'flags'),
        function: Db.getColumn(row, 'function'),
        function_start_line: Db.getColumn(row, 'function_start_line'),
        function_end_line: Db.getColumn(row, 'function_end_line'),
        syscalls_num: Db.getColumn(row, 'syscalls_num'),
        kmalloc_bucket_name: Db.getColumn(row, 'kmalloc_bucket_name'),
        kmalloc_cgroup_name: Db.getColumn(row, 'kmalloc_cgroup_name'),
        kmalloc_dyn: Db.getColumn(row, 'kmalloc_dyn')
    }));
  }

  async getStructsByAllocation(
    $kmalloc_bucket_name: string,
    $kmalloc_cgroup_name: string|null,
    $offset = 0,
    $limit = 100
  ): Promise<STRUCT_RESULTS[]> {
    let rows = await this.db.exec(Btf_getStructsByAllocation, {
      $kmalloc_bucket_name, $kmalloc_cgroup_name,
      $limit, $offset
    });
    return rows.map(row => ({
      struct_name: Db.getColumn(row, 'struct_name'),
      struct_size: Db.getColumn(row, 'struct_size'),
      allocSizeMax: Db.getColumn(row, 'allocSizeMax'),
      allocSizeMin: Db.getColumn(row, 'allocSizeMin'),
      allocSize: Db.getColumn(row, 'allocSize'),
      call_startLine: Db.getColumn(row, 'call_startLine'),
      call_uri: Db.getColumn(row, 'call_uri'),
      call_value: Db.getColumn(row, 'call_value'),
      depth: Db.getColumn(row, 'depth'),
      flagsMax: Db.getColumn(row, 'flagsMax'),
      flagsMin: Db.getColumn(row, 'flagsMin'),
      flags: Db.getColumn(row, 'flags'),
      function: Db.getColumn(row, 'function'),
      function_start_line: Db.getColumn(row, 'function_start_line'),
      function_end_line: Db.getColumn(row, 'function_end_line'),
      syscalls_num: Db.getColumn(row, 'syscalls_num'),
      kmalloc_bucket_name: Db.getColumn(row, 'kmalloc_bucket_name'),
      kmalloc_cgroup_name: Db.getColumn(row, 'kmalloc_cgroup_name'),
      kmalloc_dyn: Db.getColumn(row, 'kmalloc_dyn')
    }));
  }

  async getFieldsByStructName($struct_name: string) {
    let rows = await this.db.exec(Btf_getFieldsByStructName, {
      $struct_name
    });
    return rows.map(row => ({
        bits_offset: Db.getColumn(row, 'bits_offset'),
        bits_end: Db.getColumn(row, 'bits_end'),
        type: Db.getColumn(row, 'type'),
        parent_type: Db.getColumn(row, 'parent_type'),
        name: Db.getColumn(row, 'name')
    }));
  }

  async getAccessByCache(
    $kmalloc_bucket_name: string,
    $kmalloc_cgroup_name: string|null,
    $overlap_start: number,
    $overlap_end: number,
    $offset = 0,
    $limit = 100
  ): Promise<ACCESS_RESULTS[]> {
    let rows = await this.db.exec(Btf_getAccessByCache, {
      $kmalloc_bucket_name, $kmalloc_cgroup_name, $overlap_start, $overlap_end,
      $limit, $offset
    });
    return rows.map(row => ({
        struct_name: Db.getColumn(row, 'struct_name'),
        type: Db.getColumn(row, 'type'),
        full_field_name: Db.getColumn(row, 'full_field_name'),
        bits_offset: Db.getColumn(row, 'bits_offset'),
        bits_end: Db.getColumn(row, 'bits_end'),
        field_access_type: Db.getColumn(row, 'field_access_type'),
        field_access_start_line: Db.getColumn(row, 'field_access_start_line'),
        function_file_path: Db.getColumn(row, 'function_file_path'),
        function_start_line: Db.getColumn(row, 'function_start_line'),
        function_end_line: Db.getColumn(row, 'function_end_line'),
        syscalls_num: Db.getColumn(row, 'syscalls_num')
    }));
  }


  async getAccessByStruct($struct_name: string, $overlap_start: number, $overlap_end: number, $offset: number, $limit = 100): Promise<ACCESS_RESULTS[]> {
    let rows = await this.db.exec(Btf_getAccessByStruct, {
      $struct_name, $overlap_start, $overlap_end,
      $limit, $offset
    });
    return rows.map(row => ({
        struct_name: Db.getColumn(row, 'struct_name'),
        type: Db.getColumn(row, 'type'),
        full_field_name: Db.getColumn(row, 'full_field_name'),
        bits_offset: Db.getColumn(row, 'bits_offset'),
        bits_end: Db.getColumn(row, 'bits_end'),
        field_access_type: Db.getColumn(row, 'field_access_type'),
        field_access_start_line: Db.getColumn(row, 'field_access_start_line'),
        function_file_path: Db.getColumn(row, 'function_file_path'),
        function_start_line: Db.getColumn(row, 'function_start_line'),
        function_end_line: Db.getColumn(row, 'function_end_line'),
        syscalls_num: Db.getColumn(row, 'syscalls_num')
    }));
  }
}
