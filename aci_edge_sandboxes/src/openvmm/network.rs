//! Translation of the contract's network posture into OpenVMM options.
//!
//! OpenVMM's portable profile enforces an egress default plus IPv4 and IPv6 allow and deny rules
//! that match a network of one family and, optionally, one protocol (TCP, UDP, or ICMP) and, for
//! TCP or UDP, one port or an inclusive range of ports; deny rules take precedence. Contract rules
//! are expanded into that form exactly: exceptions are subtracted from their networks, a rule
//! without destinations matches `0.0.0.0/0` and `::/0`, and `any` protocol with a port or a port
//! range becomes a TCP and a UDP rule. Rules that cannot be expressed exactly are rejected.

use crate::cidr::Cidr;
use crate::error::{Error, Result};
use crate::model::{Access, NetworkPolicy, NetworkRule, Protocol};

/// Largest number of allow rules, and of deny rules, that OpenVMM accepts.
const MAX_RULES: usize = 256;

/// Returns the OpenVMM options that enforce `policy`.
///
/// Without a network section, or when egress is denied without allow rules and ingress is
/// denied, no network device is attached. Otherwise the portable profile applies the egress
/// posture and the ingress default with host loopback denied; other postures are rejected before
/// provisioning by the backend's capabilities.
pub(crate) fn network_arguments(
    policy: Option<&NetworkPolicy>,
    guest_network: &str,
) -> Result<Vec<String>> {
    let Some(policy) = policy else {
        return Ok(Vec::new());
    };
    let egress = &policy.egress;
    if egress.default == Access::Deny
        && egress.allow.is_empty()
        && policy.ingress.default == Access::Deny
    {
        return Ok(Vec::new());
    }
    let mut arguments: Vec<String> = [
        "--net",
        guest_network,
        "--network-profile",
        "portable",
        "--network-egress",
        egress.default.as_str(),
        "--network-ingress",
        policy.ingress.default.as_str(),
        "--host-loopback",
        "deny",
    ]
    .map(str::to_owned)
    .to_vec();
    for (rules, option, field) in [
        (
            &egress.allow,
            "--network-egress-allow",
            "network.egress.allow",
        ),
        (&egress.deny, "--network-egress-deny", "network.egress.deny"),
    ] {
        let mut expanded = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            expand_rule(rule, &format!("{field}[{index}]"), &mut expanded)?;
        }
        expanded.sort_unstable();
        expanded.dedup();
        if expanded.len() > MAX_RULES {
            return Err(Error::policy_validation(format!(
                "{field} expands to {} OpenVMM rules; the openvmm backend accepts at most \
                 {MAX_RULES}",
                expanded.len()
            )));
        }
        for rule in expanded {
            arguments.push(option.to_owned());
            arguments.push(rule);
        }
    }
    Ok(arguments)
}

/// Appends the OpenVMM rules equivalent to `rule`.
fn expand_rule(rule: &NetworkRule, field: &str, output: &mut Vec<String>) -> Result<()> {
    let unsupported = |message: String| Err(Error::policy_validation(format!("{field}{message}")));
    let mut networks = Vec::new();
    if rule.to.is_empty() {
        networks.extend([Cidr::everything(false), Cidr::everything(true)]);
    }
    for (index, peer) in rule.to.iter().enumerate() {
        let Ok(network) = Cidr::parse(&peer.cidr) else {
            return unsupported(format!(".to[{index}]: the destination is not a network"));
        };
        let mut excluded = Vec::new();
        for value in &peer.except {
            match Cidr::parse(value) {
                Ok(exclusion) if network.contains(exclusion) => excluded.push(exclusion),
                _ => {
                    return unsupported(format!(
                        ".to[{index}].except: an exception is not a network within the destination"
                    ));
                }
            }
        }
        let Some(remainder) = network.subtract(&excluded, MAX_RULES - networks.len()) else {
            return unsupported(format!(
                " covers more than {MAX_RULES} networks after removing its exceptions"
            ));
        };
        networks.extend(remainder);
    }

    let mut selectors = Vec::new();
    if rule.ports.is_empty() {
        selectors.push(Selector::Everything);
    }
    for (index, port) in rule.ports.iter().enumerate() {
        let protocols: &[&'static str] = match port.protocol {
            Protocol::Tcp => &["tcp"],
            Protocol::Udp => &["udp"],
            Protocol::Icmp => &["icmp"],
            Protocol::Any => &["tcp", "udp"],
        };
        let Some(start) = port.port else {
            if port.end_port.is_some() {
                return unsupported(format!(".ports[{index}].endPort requires port"));
            }
            if port.protocol == Protocol::Any {
                selectors.push(Selector::Everything);
            } else {
                selectors.extend(protocols.iter().copied().map(Selector::Protocol));
            }
            continue;
        };
        if port.protocol == Protocol::Icmp {
            return unsupported(format!(".ports[{index}]: ICMP has no ports"));
        }
        let end = port.end_port.unwrap_or(start);
        if end < start {
            return unsupported(format!(".ports[{index}].endPort must not be below port"));
        }
        selectors.extend(
            protocols
                .iter()
                .map(|&protocol| Selector::Ports(protocol, start, end)),
        );
    }

    for network in &networks {
        for selector in &selectors {
            output.push(match *selector {
                Selector::Everything => network.to_string(),
                Selector::Protocol(protocol) => format!("{network}:{protocol}"),
                Selector::Ports(protocol, start, end) if start == end => {
                    format!("{network}:{protocol}:{start}")
                }
                Selector::Ports(protocol, start, end) => {
                    format!("{network}:{protocol}:{start}-{end}")
                }
            });
            if output.len() > MAX_RULES * 4 {
                return unsupported(format!(" expands to more than {MAX_RULES} OpenVMM rules"));
            }
        }
    }
    Ok(())
}

/// The traffic that one OpenVMM rule selects at its destination network.
#[derive(Clone, Copy)]
enum Selector {
    /// Every protocol and port.
    Everything,
    /// Every port of TCP or UDP, or every ICMP message.
    Protocol(&'static str),
    /// The TCP or UDP ports from the first through the last, both included.
    Ports(&'static str, u16, u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;
    use crate::model::{EgressPolicy, NetworkPeer, NetworkPort};

    fn policy(egress: EgressPolicy) -> NetworkPolicy {
        NetworkPolicy {
            egress,
            ..NetworkPolicy::deny_all()
        }
    }

    fn rules(arguments: &[String], option: &str) -> Vec<String> {
        arguments
            .windows(2)
            .filter(|pair| pair[0] == option)
            .map(|pair| pair[1].clone())
            .collect()
    }

    #[test]
    fn default_postures_map_to_portable_profile_options() {
        assert!(network_arguments(None, "10.0.0.2/24").unwrap().is_empty());
        assert!(
            network_arguments(Some(&NetworkPolicy::deny_all()), "10.0.0.2/24")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            network_arguments(Some(&NetworkPolicy::egress(Access::Allow)), "10.0.0.2/24").unwrap(),
            [
                "--net",
                "10.0.0.2/24",
                "--network-profile",
                "portable",
                "--network-egress",
                "allow",
                "--network-ingress",
                "deny",
                "--host-loopback",
                "deny",
            ]
        );
        // Deny rules under a deny default change nothing, so no device is attached.
        let denied = policy(EgressPolicy::new(Access::Deny).with_deny(NetworkRule::to("1.2.3.4")));
        assert!(
            network_arguments(Some(&denied), "10.0.0.2/24")
                .unwrap()
                .is_empty()
        );

        // Ingress needs the device even when egress is denied.
        let mut ingress = NetworkPolicy::deny_all();
        ingress.ingress.default = Access::Allow;
        assert_eq!(
            network_arguments(Some(&ingress), "10.0.0.2/24").unwrap(),
            [
                "--net",
                "10.0.0.2/24",
                "--network-profile",
                "portable",
                "--network-egress",
                "deny",
                "--network-ingress",
                "allow",
                "--host-loopback",
                "deny",
            ]
        );
    }

    #[test]
    fn rules_expand_exactly() {
        let egress = EgressPolicy::new(Access::Deny)
            .with_allow(NetworkRule {
                to: vec![NetworkPeer {
                    cidr: "10.0.0.0/30".to_owned(),
                    except: vec!["10.0.0.1".to_owned()],
                }],
                ports: vec![NetworkPort {
                    protocol: Protocol::Tcp,
                    port: Some(80),
                    end_port: Some(81),
                }],
            })
            .with_allow(NetworkRule::to("192.0.2.7").on_port(Protocol::Any, 53))
            .with_allow(NetworkRule::to("198.51.100.0/24"));
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();
        assert_eq!(
            rules(&arguments, "--network-egress-allow"),
            [
                "10.0.0.0/32:tcp:80-81",
                "10.0.0.2/31:tcp:80-81",
                "192.0.2.7/32:tcp:53",
                "192.0.2.7/32:udp:53",
                "198.51.100.0/24",
            ]
        );
        assert!(has_pair(&arguments, "--network-egress", "deny"));

        let egress = EgressPolicy::new(Access::Allow).with_deny(NetworkRule {
            to: Vec::new(),
            ports: vec![NetworkPort {
                protocol: Protocol::Udp,
                port: Some(53),
                end_port: None,
            }],
        });
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();
        // A rule without destinations matches both address families.
        assert_eq!(
            rules(&arguments, "--network-egress-deny"),
            ["0.0.0.0/0:udp:53", "::/0:udp:53"]
        );
    }

    #[test]
    fn ipv6_rules_expand_exactly() {
        let egress = EgressPolicy::new(Access::Deny)
            .with_allow(NetworkRule::to("2001:db8:1::/64").on_port(Protocol::Tcp, 443))
            .with_allow(NetworkRule {
                to: vec![NetworkPeer {
                    cidr: "2001:db8:2::/126".to_owned(),
                    except: vec!["2001:db8:2::1".to_owned()],
                }],
                ports: vec![NetworkPort {
                    protocol: Protocol::Any,
                    port: Some(53),
                    end_port: None,
                }],
            })
            .with_allow(NetworkRule::to("192.0.2.0/24").on_protocol(Protocol::Icmp))
            .with_allow(NetworkRule::to("::/0").on_protocol(Protocol::Icmp))
            .with_deny(NetworkRule::to("2001:db8:1::123"));
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();
        assert_eq!(
            rules(&arguments, "--network-egress-allow"),
            [
                "192.0.2.0/24:icmp",
                "2001:db8:1::/64:tcp:443",
                "2001:db8:2::/128:tcp:53",
                "2001:db8:2::/128:udp:53",
                "2001:db8:2::2/127:tcp:53",
                "2001:db8:2::2/127:udp:53",
                "::/0:icmp",
            ]
        );
        assert_eq!(
            rules(&arguments, "--network-egress-deny"),
            ["2001:db8:1::123/128"]
        );
    }

    #[test]
    fn exclusions_remain_local_to_their_rules() {
        let excluding = |cidr: &str, excluded: &str| NetworkRule {
            to: vec![NetworkPeer {
                cidr: cidr.to_owned(),
                except: vec![excluded.to_owned()],
            }],
            ports: Vec::new(),
        };
        let egress = EgressPolicy::new(Access::Deny)
            .with_allow(excluding("192.0.2.0/24", "192.0.2.128/25"))
            .with_allow(NetworkRule::to("192.0.2.200"))
            .with_deny(excluding("198.51.100.0/24", "198.51.100.128/25"));
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();

        assert_eq!(
            rules(&arguments, "--network-egress-allow"),
            ["192.0.2.0/25", "192.0.2.200/32"]
        );
        assert_eq!(
            rules(&arguments, "--network-egress-deny"),
            ["198.51.100.0/25"]
        );
    }

    fn has_pair(arguments: &[String], name: &str, value: &str) -> bool {
        arguments
            .windows(2)
            .any(|pair| pair[0] == name && pair[1] == value)
    }

    #[test]
    fn protocols_without_ports_expand_to_protocol_rules() {
        let egress = EgressPolicy::new(Access::Deny)
            .with_allow(NetworkRule::to("192.0.2.7").on_protocol(Protocol::Tcp))
            .with_allow(NetworkRule::to("192.0.2.7").on_protocol(Protocol::Udp))
            .with_allow(NetworkRule::to("192.0.2.7").on_protocol(Protocol::Icmp))
            .with_allow(NetworkRule::to("198.51.100.0/24").on_protocol(Protocol::Any))
            .with_allow(NetworkRule::to("203.0.113.9").on_port(Protocol::Any, 443))
            .with_deny(
                NetworkRule::to("192.0.2.7")
                    .on_protocol(Protocol::Icmp)
                    .on_port(Protocol::Tcp, 22),
            );
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();
        assert_eq!(
            rules(&arguments, "--network-egress-allow"),
            [
                "192.0.2.7/32:icmp",
                "192.0.2.7/32:tcp",
                "192.0.2.7/32:udp",
                "198.51.100.0/24",
                "203.0.113.9/32:tcp:443",
                "203.0.113.9/32:udp:443",
            ]
        );
        assert_eq!(
            rules(&arguments, "--network-egress-deny"),
            ["192.0.2.7/32:icmp", "192.0.2.7/32:tcp:22"]
        );
    }

    #[test]
    fn port_ranges_expand_to_one_rule_per_network_and_protocol() {
        let egress = EgressPolicy::new(Access::Deny)
            .with_allow(NetworkRule::to("192.0.2.7").on_port_range(Protocol::Tcp, 8000, 8010))
            .with_allow(NetworkRule::to("192.0.2.7").on_port_range(Protocol::Udp, 5000, 5010))
            .with_allow(NetworkRule::to("198.51.100.0/24").on_port_range(Protocol::Any, 1, 65535))
            // A range of one port is that port's rule.
            .with_allow(NetworkRule::to("203.0.113.9").on_port_range(Protocol::Tcp, 443, 443))
            .with_deny(NetworkRule::to("192.0.2.7").on_port(Protocol::Tcp, 8005));
        let arguments = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap();
        assert_eq!(
            rules(&arguments, "--network-egress-allow"),
            [
                "192.0.2.7/32:tcp:8000-8010",
                "192.0.2.7/32:udp:5000-5010",
                "198.51.100.0/24:tcp:1-65535",
                "198.51.100.0/24:udp:1-65535",
                "203.0.113.9/32:tcp:443",
            ]
        );
        assert_eq!(
            rules(&arguments, "--network-egress-deny"),
            ["192.0.2.7/32:tcp:8005"]
        );
    }

    #[test]
    fn inexpressible_rules_are_rejected() {
        let port = |protocol, port, end_port| NetworkRule {
            to: vec![NetworkPeer::new("10.0.0.0/8")],
            ports: vec![NetworkPort {
                protocol,
                port,
                end_port,
            }],
        };
        for rule in [
            port(Protocol::Icmp, Some(8), None),
            // Structural validation rejects these first, unless the backend is called directly.
            port(Protocol::Tcp, Some(90), Some(80)),
            port(Protocol::Udp, None, Some(80)),
            NetworkRule {
                to: (0..300)
                    .map(|index| NetworkPeer::new(format!("10.0.{}.0/24", index % 256)))
                    .collect(),
                ports: vec![NetworkPort {
                    protocol: Protocol::Tcp,
                    port: Some(1),
                    end_port: Some(2),
                }],
            },
            // 129 separate ranges of both TCP and UDP need 258 OpenVMM rules.
            NetworkRule {
                to: vec![NetworkPeer::new("10.0.0.0/8")],
                ports: (0..129)
                    .map(|index| NetworkPort {
                        protocol: Protocol::Any,
                        port: Some(3 * index + 1),
                        end_port: Some(3 * index + 2),
                    })
                    .collect(),
            },
        ] {
            let egress = EgressPolicy::new(Access::Deny).with_allow(rule.clone());
            assert_eq!(
                network_arguments(Some(&policy(egress)), "10.0.0.2/24")
                    .unwrap_err()
                    .code(),
                ErrorCode::PolicyValidation,
                "{rule:?}"
            );
        }
    }

    #[test]
    fn exceptions_that_split_a_network_too_finely_are_rejected() {
        // Without a limit, these exceptions would split the address space into 512 * 23 networks.
        let peer = NetworkPeer {
            cidr: "0.0.0.0/0".to_owned(),
            except: (0..512u32)
                .map(|index| std::net::Ipv4Addr::from(index << 23).to_string())
                .collect(),
        };
        let rule = NetworkRule {
            to: vec![peer],
            ports: Vec::new(),
        };
        let egress = EgressPolicy::new(Access::Deny).with_allow(rule);
        let error = network_arguments(Some(&policy(egress)), "10.0.0.2/24").unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyValidation);
        assert!(
            error.message().contains("covers more than 256 networks"),
            "{error}"
        );
    }
}
