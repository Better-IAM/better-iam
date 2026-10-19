//! One process wall clock (`Date.now()` under the conformance server's clock): the override reaches core, auth and the
//! server alike. A binary of its own, since the clock is process-wide.

use std::sync::Arc;

#[test]
fn one_wall_clock_moves_core_auth_and_server_time() {
    better_iam_server::utils::set_wall_clock(Some(Arc::new(|| 1_234_567.0)));
    let (core, server) = (
        better_iam_core::js::now_ms(),
        better_iam_server::utils::date_now(),
    );
    better_iam_server::utils::set_wall_clock(None);
    assert_eq!((core, server), (1_234_567.0, 1_234_567.0));
    assert!(better_iam_core::js::now_ms() > 1_600_000_000_000.0);
    assert!(better_iam_core::js::system_now_ms() > 1_600_000_000_000.0);
}
