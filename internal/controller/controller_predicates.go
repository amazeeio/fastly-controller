package controller

// contains all the event watch conditions for secret and ingresses

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// SecretPredicates is used for event filtering on secret resources.
type SecretPredicates struct {
	predicate.Funcs
}

// Create watches for creation events.
func (SecretPredicates) Create(e event.CreateEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if value, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value == "true" {
			return true
		}
	}
	return false
}

// Delete watches for deletion events.
func (SecretPredicates) Delete(e event.DeleteEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if value, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value == "true" {
			return true
		}
	}
	return false
}

// Update watches for update events.
func (SecretPredicates) Update(e event.UpdateEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if value, ok := e.ObjectNew.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value == "true" {
			return true
		}
	}
	if value, ok := e.ObjectOld.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value == "true" {
			return true
		}
	}
	return false
}

// Generic watches for generic events.
func (SecretPredicates) Generic(e event.GenericEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if value, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value == "true" {
			return true
		}
	}
	return false
}

// IngressPredicates is used for event filtering on ingress resources.
type IngressPredicates struct {
	predicate.Funcs
}

// Create watches for creation events.
func (IngressPredicates) Create(e event.CreateEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if _, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value, ok2 := e.Object.GetAnnotations()["fastly.amazee.io/service-id"]; ok2 {
			if value != "" {
				return true
			}
		}
	}
	return false
}

// Delete watches for deletion events.
func (IngressPredicates) Delete(e event.DeleteEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if _, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value, ok2 := e.Object.GetAnnotations()["fastly.amazee.io/service-id"]; ok2 {
			if value != "" {
				return true
			}
		}
	}
	return false
}

// Update watches for update events.
func (IngressPredicates) Update(e event.UpdateEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if watch, ok := e.ObjectNew.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if _, okOld := e.ObjectOld.GetAnnotations()["fastly.amazee.io/watch"]; okOld {
			if val, ok2 := e.ObjectNew.GetAnnotations()["fastly.amazee.io/service-id"]; ok2 {
				if valOld2, okOld2 := e.ObjectOld.GetAnnotations()["fastly.amazee.io/service-id"]; okOld2 {
					if val == valOld2 {
						return true
					}
				}
				if val != "" {
					return true
				}
			}
		}
		if watch == "true" {
			if val, ok2 := e.ObjectNew.GetAnnotations()["fastly.amazee.io/service-id"]; ok2 {
				if val != "" {
					return true
				}
			}
		}
	}
	return false
}

// Generic watches for generic events.
func (IngressPredicates) Generic(e event.GenericEvent) bool {
	// handle "fastly.amazee.io/watch" annotation
	if _, ok := e.Object.GetAnnotations()["fastly.amazee.io/watch"]; ok {
		if value, ok2 := e.Object.GetAnnotations()["fastly.amazee.io/service-id"]; ok2 {
			if value != "" {
				return true
			}
		}
	}
	return false
}
