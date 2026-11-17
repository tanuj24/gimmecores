#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::fresh_node;
use gimmecores_node::api;
use gimmecores_node::node::Node;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::client_client::ClientClient;
use gimmecores_proto::local::v1::control_client::ControlClient;
use gimmecores_proto::peer::v1 as pb;
use tonic::transport::Channel;

struct Api {
    client: ClientClient<Channel>,
    control: ControlClient<Channel>,
}

async fn serve(node: &Node) -> Api {
    tokio::spawn(api::serve(node.clone()));
    let paths = node.paths().clone();
    for _ in 0..100 {
        if paths.control_socket().exists() && paths.client_socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Api {
        client: ClientClient::new(api::channel(&paths.client_socket()).await.unwrap()),
        control: ControlClient::new(api::channel(&paths.control_socket()).await.unwrap()),
    }
}

async fn session_with_code(ctl: &mut ControlClient<Channel>) -> l::PairingSession {
    for _ in 0..200 {
        let s = ctl
            .list_pairings(l::ListPairingsRequest {})
            .await
            .unwrap()
            .into_inner()
            .sessions;
        if let Some(s) = s.into_iter().find(|s| !s.code.is_empty()) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no pairing code");
}

#[tokio::test]
async fn whole_flow_through_the_local_api() {
    let (laptop, _h1) = fresh_node("Laptop").await;
    let (desktop, _h2) = fresh_node("Desktop").await;
    let mut lap = serve(&laptop).await;
    let mut desk = serve(&desktop).await;

    // Sockets are owner-only.
    use std::os::unix::fs::PermissionsExt;
    for p in [
        desktop.paths().client_socket(),
        desktop.paths().control_socket(),
    ] {
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600,
            "{p:?}"
        );
    }

    // Lending starts off; the lender's user turns it on.
    let st = desk
        .client
        .get_status(l::GetStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!st.lending_enabled);
    desk.control
        .set_lending(l::SetLendingRequest {
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();
    // Containers only after install; the user adds the sandbox.
    assert_eq!(st.lend_modes, [pb::ExecutionMode::Container as i32]);
    let st = desk
        .control
        .set_lend_modes(l::SetLendModesRequest {
            modes: vec![
                pb::ExecutionMode::Container as i32,
                pb::ExecutionMode::Sandbox as i32,
            ],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.lend_modes.len(), 2);

    // Pair by ticket; both users confirm the same code.
    let ticket = desk
        .control
        .open_pairing(l::OpenPairingRequest {})
        .await
        .unwrap()
        .into_inner()
        .ticket;
    assert!(ticket.starts_with("gmc1:"));
    let started = lap
        .control
        .start_pairing(l::StartPairingRequest {
            target: Some(l::start_pairing_request::Target::Ticket(ticket)),
        })
        .await
        .unwrap()
        .into_inner();
    let a = session_with_code(&mut lap.control).await;
    let b = session_with_code(&mut desk.control).await;
    assert_eq!(a.code, b.code);
    assert_eq!(a.session_id, started.session_id);
    lap.control
        .confirm_pairing(l::ConfirmPairingRequest {
            session_id: a.session_id,
            codes_match: true,
        })
        .await
        .unwrap();
    desk.control
        .confirm_pairing(l::ConfirmPairingRequest {
            session_id: b.session_id,
            codes_match: true,
        })
        .await
        .unwrap();
    for _ in 0..200 {
        if laptop.is_paired(&desktop.key()) && desktop.is_paired(&laptop.key()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let peers = lap
        .client
        .list_peers(l::ListPeersRequest {
            include_discovered: false,
        })
        .await
        .unwrap()
        .into_inner()
        .peers;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].device_name, "Desktop");

    // Request a grant; the lender's user sees it and accepts.
    let mut lap_client = lap.client.clone();
    let request = tokio::spawn(async move {
        lap_client
            .request_grant(l::RequestGrantRequest {
                no_wait: false,
                peer_fingerprint: "Desktop".into(),
                request: Some(pb::GrantRequest {
                    limits: Some(pb::Limits {
                        cpu_millis: 2000,
                        memory_bytes: 2 << 30,
                        disk_bytes: 1 << 30,
                        gpu: pb::GpuKind::None as i32,
                        max_concurrent_tasks: 2,
                    }),
                    modes: vec![
                        pb::ExecutionMode::Container as i32,
                        pb::ExecutionMode::Sandbox as i32,
                    ],
                    duration: Some(prost_types::Duration {
                        seconds: 3600,
                        nanos: 0,
                    }),
                    reason: "api test".into(),
                    ..Default::default()
                }),
            })
            .await
    });
    let pending = loop {
        let g = desk
            .client
            .list_grants(l::ListGrantsRequest {
                include_inactive: false,
            })
            .await
            .unwrap()
            .into_inner()
            .grants;
        if let Some(p) = g
            .into_iter()
            .find(|g| g.state == pb::GrantState::Requested as i32)
        {
            break p;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(pending.state_reason.contains("api test"));
    desk.control
        .respond_to_grant(l::RespondToGrantRequest {
            grant_id: pending.grant_id.clone(),
            decision: l::respond_to_grant_request::Decision::Accept as i32,
            edited: None,
            // "Always accept requests like this": a standing grant under the same prompt.
            always: true,
        })
        .await
        .unwrap();
    let granted = request.await.unwrap().unwrap().into_inner();
    assert_eq!(granted.state, pb::GrantState::Active as i32);
    let laptop_there = desk
        .client
        .list_peers(l::ListPeersRequest {
            include_discovered: false,
        })
        .await
        .unwrap()
        .into_inner()
        .peers
        .into_iter()
        .find(|p| p.device_name == "Laptop")
        .unwrap();
    let rule = laptop_there.standing.expect("a standing grant for Laptop");
    assert_eq!(rule.limits.unwrap().cpu_millis, 2000);
    assert_eq!(
        rule.max_hours, 1,
        "as long as the grant accepted, at most 8 h"
    );
    // The same request again is accepted without anyone answering.
    let again = lap
        .client
        .clone()
        .request_grant(l::RequestGrantRequest {
            no_wait: false,
            peer_fingerprint: "Desktop".into(),
            request: Some(pb::GrantRequest {
                limits: Some(pb::Limits {
                    cpu_millis: 1000,
                    memory_bytes: 1 << 30,
                    disk_bytes: 1 << 30,
                    gpu: pb::GpuKind::None as i32,
                    max_concurrent_tasks: 1,
                }),
                modes: vec![pb::ExecutionMode::Sandbox as i32],
                duration: Some(prost_types::Duration {
                    seconds: 1800,
                    nanos: 0,
                }),
                ..Default::default()
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.state, pb::GrantState::Active as i32);
    assert!(again.grant.unwrap().by_standing_rule);

    // Run a job through the API and read the streamed events.
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("hello.txt"), "from laptop").unwrap();
    let job = l::JobSpec {
        project_root: project.path().display().to_string(),
        inline_tasks: vec![l::InlineTask {
            work: Some(l::inline_task::Work::Command(pb::Command {
                argv: vec!["sh".into(), "-c".into(), "cat hello.txt; exit 4".into()],
                ..Default::default()
            })),
            resources: Some(pb::Limits {
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut stream = lap.client.submit_job(job).await.unwrap().into_inner();
    let (mut out, mut exit) = (String::new(), None);
    while let Some(ev) = stream.message().await.unwrap() {
        match ev.event {
            Some(l::job_event::Event::Task(t)) => match t.event {
                Some(pb::task_event::Event::Log(log)) => {
                    out.push_str(&String::from_utf8_lossy(&log.data))
                }
                Some(pb::task_event::Event::Finished(r)) => exit = Some((r.status, r.exit_code)),
                _ => {}
            },
            Some(l::job_event::Event::Done(_)) => break,
            _ => {}
        }
    }
    assert_eq!(out, "from laptop");
    assert_eq!(exit, Some((pb::task_result::Status::Failed as i32, 4)));

    // Stop all lending through the Client API (reduce-only call).
    let st = desk
        .client
        .stop_all_lending(l::StopAllLendingRequest {
            reason: "test".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!st.lending_enabled);
}
