package events

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// inspired by http://www.inanzzz.com/index.php/post/2qdl/event-listener-and-dispatcher-example-with-golang
// gotta give people the credit they deserve

// EventName is the unique name of the event
type EventName string

// Event is a event that can be dispatched and 0 .. n listeners may listen for
type Event interface {
	Name() EventName
}

// EventListener enables to listen for a certain event
type EventListener interface {
	ForEvent() EventName
	Handle(ctx context.Context, ev Event) error
}

// Dispatcher is used to dispatch events to listeners
type Dispatcher struct {
	log      *zap.Logger
	registry map[EventName][]EventListener
}

// NewDispatcher returns a new dispatcher instance
func NewDispatcher(log *zap.Logger) *Dispatcher {
	return &Dispatcher{
		log:      log,
		registry: make(map[EventName][]EventListener),
	}
}

// Register events listeners
func (d *Dispatcher) Register(listener ...EventListener) {
	for _, v := range listener {
		if _, ok := d.registry[v.ForEvent()]; !ok {
			d.registry[v.ForEvent()] = make([]EventListener, 0)
		}
		d.log.Debug("Registering event listener", zap.String("event", string(v.ForEvent())))
		d.registry[v.ForEvent()] = append(d.registry[v.ForEvent()], v)
	}
}

func (d *Dispatcher) executeEvent(ctx context.Context, el EventListener, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			d.log.Error("recovered from panicing event listener", zap.Any("recoverer", r), zap.String("event", string(ev.Name())), zap.String("event_listener", fmt.Sprintf("%T", el)))
		}
	}()
	err := el.Handle(ctx, ev)
	if err != nil {
		d.log.Error("Event listener returned error", zap.String("event_listener", fmt.Sprintf("%T", el)), zap.Error(err), zap.String("event", string(ev.Name())))
	}

}

// Dispatch given event
func (d *Dispatcher) Dispatch(ctx context.Context, event Event) {
	if e, ok := d.registry[event.Name()]; ok {
		for _, v := range e {
			d.executeEvent(ctx, v, event)
		}
	} else {
		d.log.Info("No event listener for event", zap.String("event", string(event.Name())))
	}
}
