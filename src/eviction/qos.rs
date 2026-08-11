use fleetos_core::{PodSpec, QosClass};

pub struct QosRanker;

impl QosRanker {
    /// Sorts pods by eviction priority (BestEffort evicted first [0], Guaranteed last [2])
    pub fn rank_for_eviction(pods: &mut [PodSpec]) {
        pods.sort_by_key(|p| match p.qos {
            QosClass::BestEffort => 0,
            QosClass::Burstable => 1,
            QosClass::Guaranteed => 2,
        });
    }
}
