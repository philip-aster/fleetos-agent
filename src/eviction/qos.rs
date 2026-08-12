use fleetos_core::{PodSpec, QosClass};

pub struct QosRanker;

impl QosRanker {
    /// Sorts pods in ascending order of eviction protection.
    /// Lowest index [0] is evicted first (BestEffort -> Burstable -> Guaranteed).
    pub fn rank_for_eviction(pods: &mut [PodSpec]) {
        pods.sort_by(|a, b| {
            let score_a = qos_score(&a.qos);
            let score_b = qos_score(&b.qos);

            // Primary sort by QoS class score
            match score_a.cmp(&score_b) {
                std::cmp::Ordering::Equal => {
                    // Tie-breaker: Compare pod IDs deterministically if QoS score matches
                    a.id.cmp(&b.id)
                }
                ord => ord,
            }
        });
    }

    /// Selects eviction candidate pod IDs required to satisfy a target memory reclamation deficit
    pub fn select_eviction_candidates(
        mut pods: Vec<PodSpec>,
        reclaim_target_mb: u64,
    ) -> Vec<String> {
        Self::rank_for_eviction(&mut pods);

        let mut candidate_ids = Vec::new();
        let mut reclaimed_mb: u64 = 0;

        for pod in pods {
            // Never evict Guaranteed pods automatically during memory pressure
            if matches!(pod.qos, QosClass::Guaranteed) {
                continue;
            }

            // Estimate memory usage from pod spec resources (or default estimate)
            let pod_mem_estimate = estimate_pod_memory_mb(&pod);
            candidate_ids.push(pod.id.clone());
            reclaimed_mb = reclaimed_mb.saturating_add(pod_mem_estimate);

            if reclaimed_mb >= reclaim_target_mb {
                break;
            }
        }

        candidate_ids
    }
}

fn qos_score(qos: &QosClass) -> u32 {
    match qos {
        QosClass::BestEffort => 0,
        QosClass::Burstable => 1,
        QosClass::Guaranteed => 2,
    }
}

fn estimate_pod_memory_mb(pod: &PodSpec) -> u64 {
    // If pod uses CloudHypervisor runtime spec, read memory_mb directly
    if let fleetos_core::RuntimeEngine::CloudHypervisor(ref cfg) = pod.runtime {
        return cfg.memory_mb;
    }
    // Default fallback estimate for OCI containers
    256
}
