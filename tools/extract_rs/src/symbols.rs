//! Symbol resolution tables and ashmem file_operations scanning.

use std::collections::{BTreeMap, BTreeSet};

use crate::btf::Btf;
use crate::kallsyms::unique;

pub const SYMBOLS: &[(&str, &str)] = &[
    ("off_init_task", "init_task"),
    ("off_init_cred", "init_cred"),
    ("off_root_task_group", "root_task_group"),
    ("off_selinux_enforcing", "selinux_state"),
    ("off_selinux_blob_sizes", "selinux_blob_sizes"),
    ("off_security_hook_heads", "security_hook_heads"),
    ("off_slide_nfulnl_logger", "nfulnl_logger"),
    ("off_slide_boot_id", "sysctl_bootid"),
    // Vivo vr.ko anti-root neutralization: sys_exit enforcement probe target.
    // Present on all GKI kernels; neutralization only runs when vr.ko is
    // detected in /proc/modules at runtime, so non-vivo devices are unaffected.
    ("off_vr_sys_exit_tp", "__tracepoint_sys_exit"),
];

/// GKI kernels drop some data symbols; unresolved optionals emit 0 and the
/// runtime falls back to target.h defaults.
pub const OPTIONAL_SYMBOLS: &[&str] = &[
    "off_security_hook_heads",
    // __tracepoint_sys_exit may be absent on stripped/custom kernels;
    // 0 disables vr.ko neutralization safely.
    "off_vr_sys_exit_tp",
];

/// struct name -> (offset macro, BTF field)
pub const STRUCT_FIELDS: &[(&str, &[(&str, &str)])] = &[
    (
        "task_struct",
        &[
            ("task_prio", "prio"),
            ("task_normal_prio", "normal_prio"),
            ("task_sched_task_group", "sched_task_group"),
            ("task_pi_lock", "pi_lock"),
            ("task_pi_waiters", "pi_waiters"),
            ("task_pi_top_task", "pi_top_task"),
            ("task_pi_blocked_on", "pi_blocked_on"),
            ("task_pid", "pid"),
            ("task_tgid", "tgid"),
            ("task_atomic_flags", "atomic_flags"),
            ("task_real_cred", "real_cred"),
            ("task_cred", "cred"),
            ("task_comm", "comm"),
            ("task_tasks", "tasks"),
            ("task_seccomp", "seccomp"),
        ],
    ),
    (
        "rt_mutex_waiter",
        &[
            // 6.6+ names the rb_nodes tree/pi_tree; 6.1 calls them
            // tree_entry/pi_tree_entry (both are plain members, same layout).
            ("waiter_tree", "tree"),
            ("waiter_pi_tree", "pi_tree"),
            ("waiter_task", "task"),
            ("waiter_lock", "lock"),
            ("waiter_wake_state", "wake_state"),
            ("waiter_ww_ctx", "ww_ctx"),
            ("waiter_tree", "tree_entry"),
            ("waiter_pi_tree", "pi_tree_entry"),
        ],
    ),
    (
        "cred",
        &[
            ("cred_uid", "uid"),
            ("cred_securebits", "securebits"),
            ("cred_caps", "cap_inheritable"),
            ("cred_security", "security"),
        ],
    ),
    (
        "seccomp",
        &[
            ("seccomp_mode", "mode"),
            ("seccomp_filter_count", "filter_count"),
            ("seccomp_filter", "filter"),
        ],
    ),
];

pub type ResolvedSymbols = BTreeMap<String, Option<u64>>;

pub fn resolve_symbols(symbols: &BTreeMap<String, BTreeSet<u64>>, base: u64) -> ResolvedSymbols {
    let mut result: ResolvedSymbols = BTreeMap::new();
    for (name, symbol) in SYMBOLS {
        result.insert((*name).to_string(), unique(symbols, symbol));
    }
    result.insert(
        "off_slide_loggers_0_1".to_string(),
        unique(symbols, "loggers").map(|value| value + 0x10),
    );
    result
        .iter_mut()
        .for_each(|(_, value)| *value = value.and_then(|v| v.checked_sub(base)));
    result
}

/// Layout selector for a release, or None when that kernel has no measured
/// geometry. Only 6.1, 6.6 and 6.12 are verified; callers treat None as
/// "use STRUCT_OFFSETS_6_6 as a testing starting point", and the extractor
/// warns so nobody mistakes a fallback table for a verified one.
pub fn kernel_struct_macro(release: Option<&str>) -> Option<&'static str> {
    let release = release?;
    let mut parts = release.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    match (major, minor) {
        // 6.1 android14 builds use the flat compact-waiter layout.
        (6, 1) => Some("STRUCT_OFFSETS_6_1"),
        (6, 6) => Some("STRUCT_OFFSETS_6_6"),
        (6, 12) => Some("STRUCT_OFFSETS_6_12"),
        _ => None,
    }
}

pub type ResolvedStructs = BTreeMap<String, Option<u32>>;

pub fn resolve_structs(btf: Option<&Btf>) -> ResolvedStructs {
    let mut result: ResolvedStructs = BTreeMap::new();
    let Some(btf) = btf else {
        for (_, fields) in STRUCT_FIELDS {
            for (macro_name, _) in *fields {
                result.insert((*macro_name).to_string(), None);
            }
        }
        result.insert("struct_page_size".to_string(), None);
        result.insert("struct_page_compound_head".to_string(), None);
        result.insert("struct_page_type".to_string(), None);
        result.insert("struct_slab_cache".to_string(), None);
        result.insert("struct_mm_struct".to_string(), None);
        return result;
    };
    for (struct_name, fields) in STRUCT_FIELDS {
        if btf.named_struct(struct_name).is_none() {
            for (macro_name, _) in *fields {
                result.insert((*macro_name).to_string(), None);
            }
            continue;
        }
        for (macro_name, field_name) in *fields {
            let value = btf.field(struct_name, field_name);
            // Alias entries (e.g. tree/tree_entry) resolve on one kernel
            // naming only; never clobber a resolved value with a miss.
            match result.get(*macro_name).copied().flatten() {
                Some(old) if value.is_none() => {
                    result.insert((*macro_name).to_string(), Some(old));
                }
                _ => {
                    result.insert((*macro_name).to_string(), value);
                }
            }
        }
    }
    result.insert("struct_page_size".to_string(), btf.size("page"));
    result.insert(
        "struct_page_compound_head".to_string(),
        btf.field("page", "compound_head"),
    );
    result.insert(
        "struct_page_type".to_string(),
        btf.field("page", "page_type"),
    );
    result.insert(
        "struct_slab_cache".to_string(),
        btf.field("slab", "slab_cache"),
    );
    result.insert("struct_mm_struct".to_string(), btf.size("mm_struct"));
    result
}

pub type ResolvedStructs2 = BTreeMap<String, Option<u32>>;

pub fn optional_symbols() -> BTreeSet<&'static str> {
    OPTIONAL_SYMBOLS.iter().copied().collect()
}

pub fn task_keys_list() -> &'static [&'static str] {
    &[
        "task_prio",
        "task_normal_prio",
        "task_sched_task_group",
        "task_pi_lock",
        "task_pi_waiters",
        "task_pi_top_task",
        "task_pi_blocked_on",
        "task_pid",
        "task_tgid",
        "task_atomic_flags",
        "task_real_cred",
        "task_cred",
        "task_comm",
        "task_tasks",
        "task_seccomp",
    ]
}

pub fn struct_fields_reference()
-> &'static [(&'static str, &'static [(&'static str, &'static str)])] {
    STRUCT_FIELDS
}

#[cfg(test)]
mod tests {
    use super::{pselect_waiter_shift_for, render_c};
    use std::collections::BTreeMap;

    #[test]
    fn render_c_carries_the_layout_selector_and_6_1_scalars() {
        let symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let out = render_c(
            Some("6.1.118-android14-11-gca0ef6d17716-ab13624819"),
            "x",
            &symbols,
            &structs,
            None,
            1,
        );
        assert!(out.contains("STRUCT_OFFSETS_6_1"));
        assert!(out.contains(".compact_waiter=1"));
        assert!(out.contains(".mm_struct_sz=0x400"));

        let out66 = render_c(
            Some("6.6.92-android15-8"),
            "x",
            &symbols,
            &structs,
            None,
            -2,
        );
        assert!(out66.contains("STRUCT_OFFSETS_6_6"));
        assert!(!out66.contains("compact_waiter"));
    }

    #[test]
    fn pselect_waiter_shift_matches_the_committed_tables() {
        assert_eq!(
            pselect_waiter_shift_for(Some("6.1.118-android14-11-gca0ef6d17716-ab13624819")),
            1
        );
        assert_eq!(pselect_waiter_shift_for(Some("6.6.92-android15-8")), -2);
        assert_eq!(pselect_waiter_shift_for(Some("6.12.30-android16-0")), 0);
        assert_eq!(pselect_waiter_shift_for(None), -2);
    }
}