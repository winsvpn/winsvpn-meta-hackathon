package main

import (
	"errors"
	"io"
	"math"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// resourceProfile describes occupied payload backing for the initial gateway
// configuration. It is not a process memory budget or a lifetime widening rule.
type resourceProfile struct {
	SchemaVersion                      uint64   `json:"schema_version"`
	MaxSessions                        uint64   `json:"max_sessions"`
	PathMTU                            uint64   `json:"path_mtu"`
	MigrationPlan                      []string `json:"migration_plan"`
	MessageBytes                       uint64   `json:"message_bytes"`
	InnerPayloadBytes                  uint64   `json:"inner_payload_bytes"`
	SendQueuePackets                   uint64   `json:"send_queue_packets"`
	SendBufferSlabBytes                uint64   `json:"send_buffer_slab_bytes"`
	PipeInboxPackets                   uint64   `json:"pipe_inbox_packets"`
	PipeBufferSlabBytes                uint64   `json:"pipe_buffer_slab_bytes"`
	DemuxBufferBytes                   uint64   `json:"demux_buffer_bytes"`
	DemuxPacketsPerSide                uint64   `json:"demux_packets_per_side"`
	DemuxSides                         uint64   `json:"demux_sides"`
	BatchReceiveSlots                  uint64   `json:"batch_receive_slots"`
	SendPayloadBackingPerSessionBytes  uint64   `json:"send_payload_backing_per_session_bytes"`
	PipePayloadBackingPerSessionBytes  uint64   `json:"pipe_payload_backing_per_session_bytes"`
	SharedDemuxAdmittedBackingBytes    uint64   `json:"shared_demux_admitted_backing_bytes"`
	SharedDemuxStagingBackingBytes     uint64   `json:"shared_demux_staging_backing_bytes"`
	ConfiguredQueuePayloadBackingBytes uint64   `json:"configured_queue_payload_backing_bytes"`
	AccountingScope                    string   `json:"accounting_scope"`
	NotIncluded                        []string `json:"not_included"`
}

func resourceProduct(values ...uint64) (uint64, error) {
	n := uint64(1)
	for _, v := range values {
		if v != 0 && n > math.MaxUint64/v {
			return 0, errors.New("resource payload product overflows uint64")
		}
		n *= v
	}
	return n, nil
}

func resourceSum(values ...uint64) (uint64, error) {
	var n uint64
	for _, v := range values {
		if n > math.MaxUint64-v {
			return 0, errors.New("resource payload sum overflows uint64")
		}
		n += v
	}
	return n, nil
}

func buildResourceProfile(opts serveOptions) (resourceProfile, error) {
	if opts.maxSessions < 1 {
		return resourceProfile{}, errors.New("-max-sessions must be positive")
	}
	sizing, classes, err := buildServeSizing(opts)
	if err != nil {
		return resourceProfile{}, err
	}
	if sizing.MessageSize < 1 || sizing.MessageSize > core.MaxTransportPayload || sizing.InnerMTU < 1 {
		return resourceProfile{}, errors.New("resource sizing is outside the validated payload range")
	}
	depth, err := resolveUplinkInboxDepth(opts.uplinkInboxDepth)
	if err != nil {
		return resourceProfile{}, err
	}
	p := resourceProfile{
		SchemaVersion: 1, MaxSessions: uint64(opts.maxSessions), PathMTU: uint64(sizing.PathMTU),
		MessageBytes: uint64(sizing.MessageSize), InnerPayloadBytes: uint64(sizing.InnerMTU),
		SendQueuePackets: gatewaySendQueue, SendBufferSlabBytes: session.DataBufferSlabBytes,
		PipeInboxPackets: uint64(depth), PipeBufferSlabBytes: carrier.PipeBufferSlabBytes,
		DemuxBufferBytes: uint64(demuxBufferCapacity(sizing.MessageSize)), DemuxPacketsPerSide: demuxChanDepth,
		// Use the maximum batch staging allowance; scalar fallback uses one slab.
		DemuxSides: demuxSideCount, BatchReceiveSlots: demuxBatchSize,
		AccountingScope: "queue_payload_backing_only",
		NotIncluded:     []string{"queue_and_packet_metadata", "runtime_gc_and_pool_retention", "session_device_cover_and_kernel_storage", "non_demux_in_flight_producer_and_consumer_buffers", "retained_and_temporary_send_receive_and_parser_batch_storage", "future_lifetime_ceiling_widening"},
	}
	for _, class := range classes {
		p.MigrationPlan = append(p.MigrationPlan, class.String())
	}
	if p.SendPayloadBackingPerSessionBytes, err = resourceProduct(p.SendQueuePackets, max(p.SendBufferSlabBytes, p.InnerPayloadBytes)); err != nil {
		return resourceProfile{}, err
	}
	if p.PipePayloadBackingPerSessionBytes, err = resourceProduct(p.PipeInboxPackets, max(p.PipeBufferSlabBytes, p.MessageBytes)); err != nil {
		return resourceProfile{}, err
	}
	if p.SharedDemuxAdmittedBackingBytes, err = resourceProduct(p.DemuxSides, p.DemuxPacketsPerSide, p.DemuxBufferBytes); err != nil {
		return resourceProfile{}, err
	}
	if p.SharedDemuxStagingBackingBytes, err = resourceProduct(p.BatchReceiveSlots, p.DemuxBufferBytes); err != nil {
		return resourceProfile{}, err
	}
	perSession, err := resourceSum(p.SendPayloadBackingPerSessionBytes, p.PipePayloadBackingPerSessionBytes)
	if err != nil {
		return resourceProfile{}, err
	}
	allSessions, err := resourceProduct(p.MaxSessions, perSession)
	if err != nil {
		return resourceProfile{}, err
	}
	p.ConfiguredQueuePayloadBackingBytes, err = resourceSum(allSessions, p.SharedDemuxAdmittedBackingBytes, p.SharedDemuxStagingBackingBytes)
	if err != nil {
		return resourceProfile{}, err
	}
	return p, nil
}

func runResources(opts serveOptions, out io.Writer) error {
	p, err := buildResourceProfile(opts)
	if err != nil {
		return err
	}
	return writeJSON(out, p)
}
