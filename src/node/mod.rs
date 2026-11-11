//! Node runtime, configuration, and service orchestration.

pub mod config;
pub mod runtime;

pub use config::NodeConfig;
pub use runtime::{
    candidate_wins_fork_choice, BlockProcessingOutcome, NodeCommand, NodeHandle, NodeRuntime,
    NodeStatus, RuntimeError,
};
