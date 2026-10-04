package command

import "context"

type Identity struct{ Source, Actor, ClientIP string }
type identityKey struct{}

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}
func IdentityFrom(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

type Caller interface {
	Call(context.Context, string, map[string]any) (any, error)
}
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Host    string `json:"host,omitempty"`
}

func (e *Error) Error() string { return e.Message }
