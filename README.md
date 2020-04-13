# casbin-flamegraph


## Steps

1. Install cargo-flamegraph
```
sudo apt install -y linux-tools-common linux-tools-generic
cargo install flamegraph
```

2. Build release
```
cargo build --release
```

3. check what are the available bench functions
```
./target/release/casbin-flamegraph

./casbin-flamgraph 
        b_benchmark_raw
        b_benchmark_basic_model
        b_benmark_cached_basic_model
        b_benchmark_rbac_model
        b_benchmark_cached_rbac_model
        b_benchmark_rbac_model_small
        b_benchmark_cached_rbac_model_small
        b_benchmark_rbac_model_medium
        b_benchmark_cached_rbac_model_medium
        b_benchmark_rbac_model_large
        b_benchmark_rbac_with_resource_roles
        b_benchmark_cached_rbac_with_resource_roles
        b_benchmark_rbac_model_with_domains
        b_benchmark_cached_rbac_model_with_domains
        b_benchmark_abac_model
        b_benchmark_cached_abac_model
        b_benchmark_key_match
        b_benchmark_cached_key_match
        b_benchmark_rbac_with_deny
        b_benchmark_cached_rbac_with_deny
        b_benchmark_priority_model
        b_benchmark_cached_priority_model
```

4. generate graph for specific bench function
```
flamegraph -o my_flamegraph.svg target/release/casbin-flamgraph b_benchmark_rbac_model_small
```
