### RetBleed Mitigations Performance Evaluation

We share our experiement setup so that the reported performance data can be
reproduced reliably.

#### Benchmark and Host Setup

We used the
[Redis memtier benchmark](https://github.com/RedisLabs/memtier_benchmark).

The host kernel is Linux 6.12: commit adc218676eef25575469234709c2d87185ca223a.

We use three configurations for the mitigation enablement. All other kernel
command line options are the default:

```
A: retbleed=off
B: retbleed=auto
C: retbleed=ibpb
```

Machine configuration:

```
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12 64-Core Processor
```

Redis configuration:

```
./redis-server --bind ::1 --protected-mode yes --port 6379 \
  --server_cpulist 0-3,128-131  --maxmemory-policy allkeys-lru \
  --io-threads-do-reads no --maxmemory 4096mb &> server.log &

taskset -c 8-15,136-142 ./memtier_benchmark --server ::1 --port 6379  \
  --protocol redis --clients 8 --threads 4 --ratio 1:9 --data-size 1024 \
  --pipeline 1 --key-minimum 1 --key-maximum 10000000 --key-pattern R:R \
  --run-count 1 --test-time 800 --print-percentile 50,90,95,99,99.9 \
  --random-data &> benchmark.log &
```

#### Results

We execute the benchmark 10 times on each host configuration.

| Configuration | Runs | MEAN | MEDIAN | STDDEV | Overhead |
| :------------ | :--- | :----------- | :------------- | :----------- | :------- |
| retbleed=off (A) | 10 | 38619.000 | 38649.500 | 99.936 | 0 |
| retbleed=auto (B) | 10 | 86271.600 | 86296.500 | 270.602 | 5.59% |
| retbleed=ibpb (C) | 10 | 91385.800 | 91393.500 | 119.416 | 57.74% |
