//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package types

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LoaderContext) DeepEqual(other *LoaderContext) bool {
	if other == nil {
		return false
	}

	if !in.LocalNode.DeepEqual(&other.LocalNode) {
		return false
	}

	if ((in.Devices != nil) && (other.Devices != nil)) || ((in.Devices == nil) != (other.Devices == nil)) {
		in, other := &in.Devices, &other.Devices
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual((*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.DeviceNames != nil) && (other.DeviceNames != nil)) || ((in.DeviceNames == nil) != (other.DeviceNames == nil)) {
		in, other := &in.DeviceNames, &other.DeviceNames
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if ((in.NodeAddrs != nil) && (other.NodeAddrs != nil)) || ((in.NodeAddrs == nil) != (other.NodeAddrs == nil)) {
		in, other := &in.NodeAddrs, &other.NodeAddrs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}
