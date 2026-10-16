use crate::guest::sys::Errno;
use crate::protocol::{
    self, APP_CANCEL, APP_EXEC, APP_FEATURES, APP_MAPS, APP_PING, APP_READY, APP_STOP, APP_STOPPED,
    GuestFeatures, INVALID_REQUEST, MAPPINGS_INCOMPLETE, OUTER_DATA, OUTER_RESET,
    UNSUPPORTED_OPERATION,
};

use super::diagnostics;
use super::mappings::{HostMappings, MappingError};
use super::seam::System;
use super::session::{Record, Session};
use super::{AgentConfig, exec, tty};

/// Terminal outcome of the long-lived dispatch loop.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The host requested and acknowledged an orderly stop.
    Stopped,
}

/// Serves control requests until STOP or a fatal session error.
pub(crate) fn run(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    mappings: &mut HostMappings,
) -> Result<Outcome, Errno> {
    session.send_attach()?;
    loop {
        let record = session.read_record().inspect_err(|error| {
            diagnostics::error(system, "outer-read", *error as i32);
        })?;
        match record.header.record_type {
            OUTER_RESET => session.acknowledge_reset(&record).inspect_err(|error| {
                diagnostics::error(system, "reset-ack", *error as i32);
            })?,
            // As in the C agent, a DATA record that fails also reports the `data` stage, after any
            // more specific stage. Its status is the error that ends the session, which
            // `control-session` reports too: `EPROTO` where C's `errno` was incidental, as after
            // a validation failure.
            OUTER_DATA => match handle_data(system, session, config, mappings, &record) {
                Ok(Some(outcome)) => return Ok(outcome),
                Ok(None) => {}
                Err(error) => {
                    diagnostics::error(system, "data", error as i32);
                    return Err(error);
                }
            },
            record_type => {
                diagnostics::error(system, "outer-type", i32::from(record_type));
                return Err(Errno::EPROTO);
            }
        }
    }
}

/// Validates one DATA record and serves its application request, returning the outcome that
/// ends the session, if any.
fn handle_data(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    mappings: &mut HostMappings,
    record: &Record,
) -> Result<Option<Outcome>, Errno> {
    let request = match session.validate_data(record) {
        Ok(request) => request,
        Err(failure) => {
            diagnostics::error(system, failure.kind.stage(), failure.status);
            return Err(failure.into_error());
        }
    };
    match request.kind {
        APP_PING => {
            if request.payload.is_empty() {
                session
                    .send_app(APP_READY, request.request_id, 0, &[])
                    .inspect_err(|error| {
                        diagnostics::error(system, "ping-ready", *error as i32);
                    })?;
            } else {
                diagnostics::error(system, "ping-payload", request.payload.len() as i32);
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?;
            }
        }
        APP_EXEC => {
            if mappings.applied != mappings.expected {
                session.send_error(
                    request.request_id,
                    Errno::EAGAIN as i32,
                    MAPPINGS_INCOMPLETE,
                )?;
                return Ok(None);
            }
            let execution = match protocol::decode_guest_exec_payload(request.payload) {
                Ok(execution) => execution,
                Err(_) => {
                    session.send_error(
                        request.request_id,
                        Errno::EINVAL as i32,
                        INVALID_REQUEST,
                    )?;
                    return Ok(None);
                }
            };
            exec::run(system, session, config, request.request_id, &execution)?;
        }
        APP_CANCEL => {
            // The targeted workload has already reported its outcome.
        }
        APP_FEATURES => {
            if request.payload.is_empty() {
                let features = if config.direct {
                    GuestFeatures::DIRECT_AGENT
                } else {
                    GuestFeatures::SANDBOX_AGENT
                };
                session.send_app(APP_READY, request.request_id, 0, &features.encode())?;
            } else {
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?;
            }
        }
        APP_MAPS => match super::mappings::apply_request(system, mappings, request.payload) {
            Ok(()) => session.send_app(APP_READY, request.request_id, 0, &[])?,
            Err(MappingError::Invalid) => {
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?
            }
            Err(MappingError::Mount { status, entry }) => {
                diagnostics::mapping_error(system, status, entry);
                session.send_error(request.request_id, status, protocol::MAPPING_FAILED)?;
            }
        },
        APP_STOP => {
            if !request.payload.is_empty() {
                return Err(Errno::EPROTO);
            }
            session.send_app(APP_STOPPED, request.request_id, 0, &[])?;
            tty::drain(system, session.descriptor());
            return Ok(Some(Outcome::Stopped));
        }
        _ => session.send_error(
            request.request_id,
            Errno::ENOTSUP as i32,
            std::str::from_utf8(UNSUPPORTED_OPERATION).expect("the category is ASCII"),
        )?,
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    use crate::protocol::{
        APP_ERROR, OUTER_ACK, OUTER_CREDIT, OUTER_GUEST_ATTACH, OUTER_HEADER_LEN,
        OUTER_RECEIVE_WINDOW, OuterHeader, decode_ack_payload, decode_app, decode_credit_payload,
        decode_outer_header, encode_app, encode_outer,
    };

    use super::super::seam::{Paths, TestSystem};
    use super::*;
    use crate::guest::sys::FileDescriptor;

    const INSTANCE: [u8; 16] = [7; 16];

    struct Response {
        kind: u8,
        request_id: u64,
        status: i32,
        payload: Vec<u8>,
    }

    struct Harness {
        host: UnixStream,
        thread: thread::JoinHandle<(Result<Outcome, Errno>, TestSystem)>,
        host_sequence: u64,
        guest_sequence: u64,
    }

    impl Harness {
        fn new(direct: bool) -> Self {
            let (host, guest) = UnixStream::pair().unwrap();
            let descriptor = FileDescriptor::from_owned(guest.into());
            let thread = thread::spawn(move || {
                let mut system = TestSystem::new(Paths::default());
                let config = AgentConfig {
                    rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
                    hostname: c"test".to_owned(),
                    uid: c"1000".to_owned(),
                    gid: c"1000".to_owned(),
                    user: c"workload".to_owned(),
                    home: c"/home/workload".to_owned(),
                    direct,
                };
                let mut session = Session::new(descriptor);
                let mut mappings = HostMappings::default();
                let outcome = run(&mut system, &mut session, &config, &mut mappings);
                (outcome, system)
            });
            let mut harness = Self {
                host,
                thread,
                host_sequence: 8,
                guest_sequence: 1,
            };
            let (header, payload) = harness.read_outer();
            assert_eq!(header.record_type, OUTER_GUEST_ATTACH);
            assert!(payload.is_empty());
            harness
                .host
                .write_all(&encode_outer(OUTER_RESET, &INSTANCE, 1, 7, &[]).unwrap())
                .unwrap();
            let (header, payload) = harness.read_outer();
            assert_eq!((header.record_type, header.sequence), (OUTER_ACK, 0));
            assert_eq!(decode_ack_payload(&payload).unwrap(), OUTER_RECEIVE_WINDOW);
            harness
        }

        fn request(&mut self, kind: u8, payload: &[u8]) -> Response {
            let frame = encode_app(kind, 42, 0, payload);
            self.host
                .write_all(
                    &encode_outer(OUTER_DATA, &INSTANCE, 1, self.host_sequence, &frame).unwrap(),
                )
                .unwrap();
            self.host_sequence += 1;
            let (credit, payload) = self.read_outer();
            assert_eq!(
                (credit.record_type, credit.sequence),
                (OUTER_CREDIT, self.guest_sequence)
            );
            assert_eq!(decode_credit_payload(&payload).unwrap(), frame.len() as u32);
            self.guest_sequence += 1;
            let (data, frame) = self.read_outer();
            assert_eq!(
                (data.record_type, data.sequence),
                (OUTER_DATA, self.guest_sequence)
            );
            self.guest_sequence += 1;
            let frame = decode_app(&frame).unwrap();
            Response {
                kind: frame.kind,
                request_id: frame.request_id,
                status: frame.status,
                payload: frame.payload.to_vec(),
            }
        }

        fn stop(mut self) -> TestSystem {
            let response = self.request(APP_STOP, &[]);
            assert_eq!(
                (
                    response.kind,
                    response.request_id,
                    response.status,
                    response.payload.as_slice()
                ),
                (APP_STOPPED, 42, 0, b"".as_slice())
            );
            let (outcome, system) = self.thread.join().unwrap();
            assert!(matches!(outcome, Ok(Outcome::Stopped)));
            system
        }

        fn fail(mut self, record: &[u8]) -> Vec<u8> {
            self.host.write_all(record).unwrap();
            let (outcome, system) = self.thread.join().unwrap();
            assert!(outcome.is_err());
            system.diagnostics
        }

        fn read_outer(&mut self) -> (OuterHeader, Vec<u8>) {
            let mut header = [0u8; OUTER_HEADER_LEN];
            self.host.read_exact(&mut header).unwrap();
            let header = decode_outer_header(&header).unwrap();
            let mut payload = vec![0; header.length];
            self.host.read_exact(&mut payload).unwrap();
            (header, payload)
        }
    }

    #[test]
    fn agent_advertises_the_control_features_of_its_mode_and_stops() {
        for (direct, expected) in [
            (true, GuestFeatures::DIRECT_AGENT),
            (false, GuestFeatures::SANDBOX_AGENT),
        ] {
            let mut harness = Harness::new(direct);
            let response = harness.request(APP_FEATURES, &[]);
            assert_eq!(
                (response.kind, response.request_id, response.status),
                (APP_READY, 42, 0)
            );
            assert_eq!(GuestFeatures::decode(&response.payload).unwrap(), expected);
            let system = harness.stop();
            assert_eq!(system.tty_drained, 1);
        }
    }

    #[test]
    fn agent_refuses_feature_payloads_and_unannounced_mapping_tables() {
        let mut harness = Harness::new(true);
        for (kind, payload) in [
            (APP_FEATURES, b"abc".as_slice()),
            (APP_MAPS, b"\0\0\0\0\x01\0\0\0\0\0\x01\0\x02\0".as_slice()),
        ] {
            let response = harness.request(kind, payload);
            assert_eq!(
                (response.kind, response.request_id, response.status),
                (APP_ERROR, 42, Errno::EINVAL as i32)
            );
            assert_eq!(response.payload, INVALID_REQUEST.as_bytes());
        }
        harness.stop();
    }

    #[test]
    fn agent_refuses_malformed_working_directories() {
        let mut harness = Harness::new(true);
        let argument = [9u32.to_le_bytes().as_slice(), b"/bin/true"].concat();
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&argument);
        let response = harness.request(APP_EXEC, &payload);
        assert_eq!(
            (response.kind, response.status, response.payload.as_slice()),
            (APP_ERROR, Errno::EINVAL as i32, INVALID_REQUEST.as_bytes())
        );
        harness.stop();
    }

    #[test]
    fn data_validation_diagnostics_preserve_the_c_failure_stage_and_status() {
        let data = format!(
            "NVX-MANAGED-ERROR: stage=data status={}\n",
            Errno::EPROTO as i32
        );
        let frame = encode_app(APP_PING, 42, 0, &[]);
        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 9, &frame).unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-sequence status=9\n",
                data.as_bytes()
            ]
            .concat()
        );

        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 2, 8, &frame).unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-identity status=2\n",
                data.as_bytes()
            ]
            .concat()
        );

        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 8, b"x").unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-application status=1\n",
                data.as_bytes()
            ]
            .concat()
        );
    }

    #[test]
    fn a_request_that_fails_after_validation_reports_the_data_stage() {
        let frame = encode_app(APP_STOP, 42, 0, b"x");
        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 8, &frame).unwrap());
        assert_eq!(
            diagnostics,
            format!(
                "NVX-MANAGED-ERROR: stage=data status={}\n",
                Errno::EPROTO as i32
            )
            .as_bytes()
        );
    }
}
