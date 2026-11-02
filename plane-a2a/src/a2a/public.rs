// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEPLOYMENT'S PUBLIC BASE, READ ONE WAY: the absolute URLs this plane publishes (its

/// One reading of `public_url`: parse it, replace the path wholesale, drop query and fragment.

pub fn absolute(public_url: &str, path: &str) -> Option<String> {
    let mut u = url::Url::parse(public_url).ok()?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return None;
    }
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

#[cfg(test)]
#[path = "tests/public_tests.rs"]
mod public_tests;
