package main

const (
	linuxCgroupV2CleanupSchema   = "winn-phase1-cgroup-v2-cleanup/v1"
	nonApplicableCleanupSchema   = "winn-phase1-containment-not-applicable/v1"
	controllerDelegationSubgroup = "controller"
)

// CycleContainmentCleanup is the closed result of one containment lifecycle.
//
// Linux returns the exact final cgroup.events bytes read through the held child
// descriptor and only after descriptor-relative removal has been verified.
// The non-applicable shape is explicit rather than an all-zero value, so a
// future receipt cannot confuse "not required" with missing evidence.
type CycleContainmentCleanup struct {
	Schema            string `json:"schema"`
	ChildCgroupInode  uint64 `json:"child_cgroup_inode"`
	FinalCgroupEvents string `json:"final_cgroup_events"`
	ChildRemoved      bool   `json:"child_removed"`
}

func nonApplicableContainmentCleanup() CycleContainmentCleanup {
	return CycleContainmentCleanup{
		Schema: nonApplicableCleanupSchema,
	}
}
