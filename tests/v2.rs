use ratelimitly::ApiKey;
#[test]
fn v2_annual_cap() {
    let key: ApiKey =
        "rl-cookie1qgqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8scfwu4f"
            .parse()
            .expect("v2 annual cap");
    assert_eq!(key.key_id(), 1);
}

#[test]
fn additive_wide_resources_preserve_narrow_ids_and_bounds() {
    use ratelimitly::{Resource, WideResource, WindowCap};
    use std::time::Duration;
    let narrow = Resource::new("checkout", Duration::from_millis(60_000), 100).unwrap();
    let wide = WideResource::new("checkout", Duration::from_millis(60_000), 100).unwrap();
    assert_eq!(narrow.id(), wide.id());
    for days in [90u64, 182, 365] {
        let window = Duration::from_millis(days * 86_400_000);
        assert_eq!(
            WideResource::new("checkout", window, 100).unwrap().window(),
            window
        );
        assert!(Resource::new("checkout", window, 100).is_err());
    }
    assert!(WideResource::new("checkout", Duration::from_millis(31_536_000_001), 100).is_err());
    assert!(WideResource::new("checkout", Duration::from_nanos(1_000_001), 100).is_err());
    let key: ApiKey =
        "rl-cookie1qgqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8scfwu4f"
            .parse()
            .unwrap();
    assert_eq!(key.format_version(), 2);
    assert_eq!(key.window_cap(), WindowCap::Finite(31_536_000_000));
}
