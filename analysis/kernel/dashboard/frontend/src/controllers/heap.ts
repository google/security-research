import { Index } from '..';
import { Btf } from '../models/btf';
import { STRUCT_RESULTS } from '../types';
import { Access } from '../views/access/access';
import { Fields } from '../views/fields/fields';
import { Struct } from '../views/struct/struct';

export class Heap {
    private struct: Struct = new Struct(this);
    private fields: Fields = new Fields(this);
    private access: Access = new Access(this);

    private kmalloc_cache_name?: string;
    private kmalloc_cgroup_name?: string;
    private kmalloc_dyn?: string;

    private constructor(
        private index: Index,
        private btfPromise: Promise<Btf>
    ) {}

    async onLocationChange(locationHash: string) {
        let [match, kmalloc, cg, size, dyn, kmalloc_offset, struct, bits_offset, bits_end, access_offset] = [...locationHash.match(
            /#!heap[/](kmalloc-(?:(cg)-)?(\w+)(-dyn)?(?:,(\d+))?|[*])(?:[/](\w+))?(?:[/](\d+)[.][.](\d+)(?:,(\d+))?)?/
        ) || []];
        console.log([match, kmalloc, cg, size, dyn, struct]);
        if (!match) return;

        const btf = await this.btfPromise;
        let results: Promise<STRUCT_RESULTS[]>;

        if (kmalloc != "*") {
            this.kmalloc_cache_name = size;
            this.kmalloc_cgroup_name = cg;
            this.kmalloc_dyn = dyn;
            results = btf.getStructsByAllocation(size, cg, Number(kmalloc_offset || 0));
        } else {
            results = btf.getStructsByStructName(struct);
        }

        this.struct.displayStructs(
            await Struct.getRootNode(),
            await results,
            kmalloc,
            struct,
            Number(kmalloc_offset || 0)
        );

        if (!struct) {
            struct = (await results)[0].struct_name;
        }

        this.fields.displayStructs(
            await Fields.getRootNode(),
            await btf.getFieldsByStructName(struct),
            struct,
            kmalloc
        );

        if (bits_offset && bits_end) {
            this.displayAccess(
                Number(bits_offset),
                Number(bits_end),
                struct,
                kmalloc,
                this.kmalloc_cache_name,
                this.kmalloc_cgroup_name,
                Number(access_offset || 0));
        }
    }

    static async init(index: Index) {
        const heap: Heap = new Heap(
            index,
            Promise.resolve().then(() => Btf.init())
        );
        return heap;
    }

    async displayAccess(bits_offset:number, bits_end:number, struct: string, kmalloc: string, kmalloc_cache_name?: string|undefined, kmalloc_cgroup_name?: string, offset = 0) {
        const btf = await this.btfPromise;
        let access;
        if (kmalloc_cache_name) {
            access = await btf.getAccessByCache(
                kmalloc_cache_name,
                kmalloc_cgroup_name || null,
                bits_offset, bits_end,
                offset
            );
        } else {
            access = await btf.getAccessByStruct(
                struct,
                bits_offset, bits_end,
                offset
            );
        }
        this.access.displayAccess(await Access.getRootNode(), access, kmalloc, offset);
    }
}
