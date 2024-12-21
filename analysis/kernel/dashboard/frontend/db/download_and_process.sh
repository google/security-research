#!/bin/bash

LOGS_DIR=$(mktemp -d)
GCS_BUCKET=https://storage.googleapis.com/kernelctf-dash
INIT="
.bail on
.stats on
.eqp full
.mode line
.progress 5000000
.parameter init
"

RESIZE_DB="
PRAGMA main.journal_mode = delete;
PRAGMA main.page_size = 1024;
PRAGMA main.auto_vacuum = 1;
VACUUM;
"

declare -A SQL=(
    ["git_blame-6.1.111.db"]='
.parameter set $file_path "net/socket"
.parameter set $start_line 2770
.parameter set $end_line 2776
'
    ["codeql_data-6.1.db"]='
.parameter set $file_path "mm/slab_common.c"
.parameter set $start_line 969
.parameter set $end_line 989
.parameter set $syscall accept
.parameter set $depth 1
.parameter set $limit 10
.parameter set $offset 0
'
    ["syzkaller-6.1.111.db"]='
.parameter set $file_path "net/socket"
.parameter set $start_line 2770
.parameter set $end_line 2776'
    ["btf-kernelctf-6_1_111.db"]='
.parameter set $struct_name "pipe_buffer"
.parameter set $kmalloc_bucket_name "128"
.parameter set $kmalloc_cgroup_name NULL
.parameter set $overlap_end 128
.parameter set $overlap_end 64
.parameter set $limit 100
.parameter set $offset 0
'
)


function process_db() {
    set -evx
    DB="$1";
    COST="$2";
    SQL="${SQL[$DB]}";
    wget -nc "$GCS_BUCKET/$DB" || true;
    if [[
        "$DB" == "syzkaller-6.1.111.db" &&
        "$(sqlite3 $DB 'select count(*) from sqlite_master where type="table" and name="syzk_sys"')" != "1"
    ]]; then
        (
            echo prog_id,syscall;
            sqlite3 -json "$DB" 'select * from syzk_prog;' | jq -r '.[] | {id: (.prog_id | tostring), syscalls: ([.prog_code | match("((?:\\w+ = )?(?<syscall>[^$(]+)(?:[$]\\w+)?.+)\n?"; "g") | .captures[1].string] | unique | .[])} | map(.) | @csv'
        ) > syzkaller_syscalls.csv
        sqlite3 -csv "$DB" ".import syzkaller_syscalls.csv syzk_sys"
        rm syzkaller_syscalls.csv
    fi
    if [[
        "$DB" == "btf-kernelctf-6_1_111.db"
    ]]; then
        wget -nc "$GCS_BUCKET/allocs.db" || true;
        wget -nc "$GCS_BUCKET/codeql_data-6.1.db" || true;
    fi
    ionice -c 2 -n 0 sqlite3 -init <(echo "$INIT") -echo $DB  ".read ./sql/$DB/prolog.sql";
    for query in ./sql/$DB/query-*.sql; do
        tmp=$(mktemp)
        sqlite3 -init <(
            echo "$INIT";
            echo "$SQL";
        ) -echo $DB ".read $query" | tee $tmp;
        (echo -n $query:; grep 'Read.. system calls' $tmp | awk '{print $4}') >> $COST
        rm $tmp
    done
    ionice -c 2 -n 0 sqlite3 -init <(echo "$INIT") -echo $DB "PRAGMA optimize;";
    if [[
        "$(sqlite3 $DB 'PRAGMA page_size')" != "1024" ||
        "$(sqlite3 $DB 'PRAGMA journal_mode')" != "delete" ||
        "$(sqlite3 $DB 'PRAGMA auto_vacuum')" != "1"
    ]]; then
        ionice -c 2 -n 0 sqlite3 -echo $DB "$RESIZE_DB"
    fi
}

declare -A PID2DB
for db in "${!SQL[@]}"; do
    touch $LOGS_DIR/$db.{log,err,cost,fin}
    (process_db "$db" "$LOGS_DIR/$db.cost" 1>>$LOGS_DIR/$db.log 2>>$LOGS_DIR/$db.err) &
    pid=$!
    PID2DB[$pid]=$db
    echo RUNNING > $LOGS_DIR/$db.run
done

tail -f -n +0 $LOGS_DIR/* &
TAIL_PROC=$!

FAIL=""
for pid in "${!PID2DB[@]}"; do
    wait $pid
    ERR=$?
    if [ $ERR -ne 0 ]; then
        FAIL="$FAIL ${PID2DB[$pid]}"
    fi
    echo "________FINISHED:$ERR" > $LOGS_DIR/${PID2DB[$pid]}.run
    grep -v FINISHED $LOGS_DIR/*.run > $LOGS_DIR/${PID2DB[$pid]}.fin
done

kill $TAIL_PROC
echo
echo

if [ "$FAIL" != "" ]; then
    echo "ERROR (logs: $LOGS_DIR)"
    echo "Processing failed for $FAIL."
    for db in $FAIL; do
        echo "About to print $db STDOUT and STDERR from $LOGS_DIR"
        cat $LOGS_DIR/$db.run
        echo "Press enter to continue"
        read
        echo "STDOUT $db"
        cat $LOGS_DIR/$db.log
        echo "STDERR $db"
        cat $LOGS_DIR/$db.err
    done
    echo "Press enter to continue (will delete logs on $LOGS_DIR)"
    read
else
    echo "All processing completed successfully."
    echo
    echo Query costs:
    cat $LOGS_DIR/*.cost
fi

rm -rf $LOGS_DIR
