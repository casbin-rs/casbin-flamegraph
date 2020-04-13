use casbin::prelude::*;
use std::{collections::HashMap, time::Instant};

fn raw_enforce(r: [&str; 3]) -> bool {
    let policies = [["alice", "data1", "read"], ["bob", "data2", "write"]];
    for policy in &policies {
        if policy == &r {
            return true;
        }
    }
    return false;
}

fn await_future<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    #[cfg(feature = "runtime-async-std")]
    {
        async_std::task::block_on(future)
    }

    #[cfg(feature = "runtime-tokio")]
    {
        tokio::runtime::Runtime::new().unwrap().block_on(future)
    }
}

fn b_benchmark_raw() {
    raw_enforce(["alice", "data1", "read"]);
}

fn b_benchmark_basic_model() {
    let mut e = await_future(Enforcer::new(
        "examples/basic_model.conf",
        "examples/basic_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benmark_cached_basic_model() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/basic_model.conf",
        "examples/basic_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_rbac_model() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_model.conf",
        "examples/rbac_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data2", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_model() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_model.conf",
        "examples/rbac_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data2", "read"])).unwrap();
}

fn b_benchmark_rbac_model_small() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_model.conf",
        None as Option<&'static str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    await_future(
        e.add_policies(
            (0..100_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 1000 users.
    await_future(
        e.add_grouping_policies(
            (0..1000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user501", "data9", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_model_small() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    await_future(
        e.add_policies(
            (0..100_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 1000 users.
    await_future(
        e.add_grouping_policies(
            (0..1000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user501", "data9", "read"])).unwrap();
}

fn b_benchmark_rbac_model_medium() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    await_future(
        e.add_policies(
            (0..1000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 10000 users.
    await_future(
        e.add_grouping_policies(
            (0..10000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user5001", "data15", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_model_medium() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    await_future(
        e.add_policies(
            (0..1000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 10000 users.
    await_future(
        e.add_grouping_policies(
            (0..10000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user5001", "data150", "read"])).unwrap();
}

fn b_benchmark_rbac_model_large() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    await_future(
        e.add_policies(
            (0..10000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 100000 users.
    await_future(
        e.add_grouping_policies(
            (0..100000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user50001", "data1500", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_model_large() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    await_future(
        e.add_policies(
            (0..10000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 100000 users.
    await_future(
        e.add_grouping_policies(
            (0..100000_u64)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    await_future(e.enforce(&["user50001", "data1500", "read"])).unwrap();
}

fn b_benchmark_rbac_with_resource_roles() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_with_resource_roles_model.conf",
        "examples/rbac_with_resource_roles_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_with_resource_roles() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_resource_roles_model.conf",
        "examples/rbac_with_resource_roles_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_rbac_model_with_domains() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "domain1", "data1", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_model_with_domains() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "domain1", "data1", "read"])).unwrap();
}

fn b_benchmark_abac_model() {
    let mut e = await_future(Enforcer::new(
        "examples/abac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    await_future(e.enforce(&["alice", r#"{"Owner": "alice"}"#, "read"])).unwrap();
}

fn b_benchmark_cached_abac_model() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/abac_model.conf",
        None as Option<&str>,
    ))
    .unwrap();

    await_future(e.enforce(&["alice", r#"{"Owner": "alice"}"#, "read"])).unwrap();
}

fn b_benchmark_key_match() {
    let mut e = await_future(Enforcer::new(
        "examples/keymatch_model.conf",
        "examples/keymatch_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "/alice_data/resource1", "GET"])).unwrap();
}

fn b_benchmark_cached_key_match() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/keymatch_model.conf",
        "examples/keymatch_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "/alice_data/resource1", "GET"])).unwrap();
}

fn b_benchmark_rbac_with_deny() {
    let mut e = await_future(Enforcer::new(
        "examples/rbac_with_deny_model.conf",
        "examples/rbac_with_deny_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_cached_rbac_with_deny() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_deny_model.conf",
        "examples/rbac_with_deny_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_priority_model() {
    let mut e = await_future(Enforcer::new(
        "examples/priority_model.conf",
        "examples/priority_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn b_benchmark_cached_priority_model() {
    let mut e = await_future(CachedEnforcer::new(
        "examples/priority_model.conf",
        "examples/priority_policy.csv",
    ))
    .unwrap();

    await_future(e.enforce(&["alice", "data1", "read"])).unwrap();
}

fn main() -> Result<()> {
    let mut hash_map: HashMap<&str, fn()> = HashMap::new();
    hash_map.insert("b_benchmark_raw", b_benchmark_raw);
    hash_map.insert("b_benchmark_basic_model", b_benchmark_basic_model);
    hash_map.insert("b_benmark_cached_basic_model", b_benmark_cached_basic_model);
    hash_map.insert("b_benchmark_rbac_model", b_benchmark_rbac_model);
    hash_map.insert(
        "b_benchmark_cached_rbac_model",
        b_benchmark_cached_rbac_model,
    );
    hash_map.insert("b_benchmark_rbac_model_small", b_benchmark_rbac_model_small);
    hash_map.insert(
        "b_benchmark_cached_rbac_model_small",
        b_benchmark_cached_rbac_model_small,
    );
    hash_map.insert(
        "b_benchmark_rbac_model_medium",
        b_benchmark_rbac_model_medium,
    );
    hash_map.insert(
        "b_benchmark_cached_rbac_model_medium",
        b_benchmark_cached_rbac_model_medium,
    );
    hash_map.insert("b_benchmark_rbac_model_large", b_benchmark_rbac_model_large);
    hash_map.insert(
        "b_benchmark_cached_rbac_model_large",
        b_benchmark_cached_rbac_model_large,
    );
    hash_map.insert(
        "b_benchmark_rbac_with_resource_roles",
        b_benchmark_rbac_with_resource_roles,
    );
    hash_map.insert(
        "b_benchmark_cached_rbac_with_resource_roles",
        b_benchmark_cached_rbac_with_resource_roles,
    );
    hash_map.insert(
        "b_benchmark_rbac_model_with_domains",
        b_benchmark_rbac_model_with_domains,
    );
    hash_map.insert(
        "b_benchmark_cached_rbac_model_with_domains",
        b_benchmark_cached_rbac_model_with_domains,
    );
    hash_map.insert("b_benchmark_abac_model", b_benchmark_abac_model);
    hash_map.insert(
        "b_benchmark_cached_abac_model",
        b_benchmark_cached_abac_model,
    );
    hash_map.insert("b_benchmark_key_match", b_benchmark_key_match);
    hash_map.insert("b_benchmark_cached_key_match", b_benchmark_cached_key_match);
    hash_map.insert("b_benchmark_rbac_with_deny", b_benchmark_rbac_with_deny);
    hash_map.insert(
        "b_benchmark_cached_rbac_with_deny",
        b_benchmark_cached_rbac_with_deny,
    );
    hash_map.insert("b_benchmark_priority_model", b_benchmark_priority_model);
    hash_map.insert(
        "b_benchmark_cached_priority_model",
        b_benchmark_cached_priority_model,
    );

    if let Some(b) = std::env::args().skip(1).next() {
        if let Some(f) = hash_map.get(b.as_str()) {
            let now = Instant::now();
            f();
            println!("took {} nano secs to finish", now.elapsed().as_nanos());
            return Ok(());
        }
    }

    println!(
        r#"./casbin-flamgraph 
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
        b_benchmark_cached_priority_model"#
    );

    Ok(())
}
