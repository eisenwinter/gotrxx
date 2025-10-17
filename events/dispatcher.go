package events

import (
	"fmt"

	"github.com/eisenwinter/gotrxx/pkg/logging"
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
	Handle(ev Event) error
}

// Dispatcher is used to dispatch events to listeners
type Dispatcher struct {
	log      logging.Logger
	registry map[EventName][]EventListener
}

// NewDispatcher returns a new dispatcher instance
func NewDispatcher(log logging.Logger) *Dispatcher {
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
		d.log.Debug("registering event listener", "event", string(v.ForEvent()))
		d.registry[v.ForEvent()] = append(d.registry[v.ForEvent()], v)
	}
}

func (d *Dispatcher) executeEvent(el EventListener, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			d.log.Error(
				"recovered from panicing event listener",
				"recoverer", r,
				"event", string(ev.Name()),
				"event_listener", fmt.Sprintf("%T", el),
			)
		}
	}()
	err := el.Handle(ev)
	if err != nil {
		d.log.Error(
			"event listener returned error",
			"event_listener", fmt.Sprintf("%T", el),
			"err", err,
			"event", string(ev.Name()),
		)
	}

}

// Dispatch given event
func (d *Dispatcher) Dispatch(event Event) {
	if e, ok := d.registry[event.Name()]; ok {
		for _, v := range e {
			d.executeEvent(v, event)
		}
	} else {
		d.log.Info("no event listener for event", "event", string(event.Name()))
	}
}
