// Package echo is the echo integration of the Better IAM middleware. Middleware answers the IAM API (through the
// server's Node-style transport, so node protocol mounts such as the OAuth provider work) and gives every other request
// its helpers (FromContext, also `c.Get("iam")`); RequireSession and Authorize are route guards; ErrorHandler answers
// IAM refusals your handlers return.
//
//	iamEcho := echo.New(iam, middleware.Options{LoginPath: "/login"})
//	e := labstack.New()
//	e.HTTPErrorHandler = iamEcho.ErrorHandler(e.DefaultHTTPErrorHandler)
//	e.Use(iamEcho.Middleware())
//	e.GET("/projects/:id", handler, iamEcho.Authorize("projects:read", middleware.AuthorizeSpec[labstack.Context]{
//		Resource: func(c labstack.Context, _ *core.Object) (middleware.ResourceRef, error) {
//			return middleware.ResourceRef{Type: "project", ID: c.Param("id")}, nil
//		},
//	}))
package echo

import (
	"context"
	"net/http"

	labstack "github.com/labstack/echo/v4"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/server"
)

// ContextKey is the echo context key of the request helpers.
const ContextKey = "iam"

// IamEcho is the echo integration.
type IamEcho struct {
	integration *middleware.Integration
}

// New is the echo integration over a composed server.
func New(iam *server.BetterIam, options middleware.Options) *IamEcho {
	return NewWith(middleware.Server(iam), options)
}

// NewWith is the echo integration over any IAM implementation.
func NewWith(source middleware.IAM, options middleware.Options) *IamEcho {
	return &IamEcho{integration: middleware.NewIntegration(source, options)}
}

// NewLazy is the echo integration over an IAM instance resolved on use.
func NewLazy(resolve func(ctx context.Context) (middleware.IAM, error), options middleware.Options) *IamEcho {
	return &IamEcho{integration: middleware.NewLazyIntegration(resolve, options)}
}

// Resolve is the IAM instance.
func (e *IamEcho) Resolve(ctx context.Context) (middleware.IAM, error) {
	return e.integration.Resolve(ctx)
}

// FromContext is the request helpers of an echo request (nil when the integration has not seen it).
func FromContext(c labstack.Context) *middleware.Helpers {
	if helpers, ok := c.Get(ContextKey).(*middleware.Helpers); ok {
		return helpers
	}
	return middleware.FromRequest(c.Request())
}

// Helpers is the request helpers, created on first use.
func (e *IamEcho) Helpers(c labstack.Context) (*middleware.Helpers, error) {
	if existing := FromContext(c); existing != nil {
		return existing, nil
	}
	created, err := e.integration.NewHelpers(c.Response().Header(), c.Request())
	if err != nil {
		return nil, err
	}
	c.Set(ContextKey, created)
	c.SetRequest(c.Request().WithContext(middleware.WithHelpers(c.Request().Context(), created)))
	return created, nil
}

// Middleware answers the IAM API under the Serve prefixes and gives every other request its helpers.
func (e *IamEcho) Middleware() labstack.MiddlewareFunc {
	return func(next labstack.HandlerFunc) labstack.HandlerFunc {
		return func(c labstack.Context) error {
			iam, err := e.integration.Resolve(c.Request().Context())
			if err != nil {
				return err
			}
			serves, err := e.integration.Serves(iam, c.Request())
			if err != nil {
				return err
			}
			if serves {
				e.integration.ServeIAM(c.Response(), c.Request(), iam)
				return nil
			}
			if _, err := e.Helpers(c); err != nil {
				return err
			}
			return next(c)
		}
	}
}

// Answer answers an IAM refusal (the JSON error envelope, or a login / step-up redirect for pages); false when err is
// not one.
func (e *IamEcho) Answer(c labstack.Context, err error) bool {
	return e.integration.Answer(c.Response(), c.Request(), err)
}

func (e *IamEcho) guard(spec middleware.GuardSpec[labstack.Context]) labstack.MiddlewareFunc {
	return func(next labstack.HandlerFunc) labstack.HandlerFunc {
		return func(c labstack.Context) error {
			helpers, err := e.Helpers(c)
			if err == nil {
				_, err = middleware.Guard(c.Request().Context(), e.integration, helpers, c, c.Request(), spec)
			}
			if err != nil {
				if e.Answer(c, err) {
					return nil
				}
				return err
			}
			return next(c)
		}
	}
}

// RequireSession is a guard requiring a session (and stepUp, when given).
func (e *IamEcho) RequireSession(stepUp *middleware.StepUpRequirement) labstack.MiddlewareFunc {
	return e.guard(middleware.GuardSpec[labstack.Context]{StepUp: stepUp})
}

// Authorize is a guard requiring a session allowed to perform action (default resource: the tenant). Resource and
// TenantID receive the echo context (read route parameters with c.Param).
func (e *IamEcho) Authorize(action string, spec middleware.AuthorizeSpec[labstack.Context]) labstack.MiddlewareFunc {
	return e.guard(spec.Guard(action))
}

// ErrorHandler is an HTTPErrorHandler: IAM refusals become the JSON error envelope (or a login / step-up redirect for
// pages); other errors go to fallback (echo's HTTPErrors answer with their own response there), or a plain 500 when
// fallback is nil.
func (e *IamEcho) ErrorHandler(fallback labstack.HTTPErrorHandler) labstack.HTTPErrorHandler {
	return func(err error, c labstack.Context) {
		if c.Response().Committed {
			return
		}
		if e.Answer(c, err) {
			return
		}
		if fallback != nil {
			fallback(err, c)
			return
		}
		c.Logger().Error(err)
		_ = c.String(http.StatusInternalServerError, "Internal Server Error")
	}
}

// TenantFromParam is an authorize TenantID callback reading the tenant from a route parameter.
func TenantFromParam(name string) func(c labstack.Context, session *core.Object) (string, error) {
	return func(c labstack.Context, _ *core.Object) (string, error) { return c.Param(name), nil }
}

// ResourceFromParam is an authorize Resource callback naming a resource of resourceType by a route parameter.
func ResourceFromParam(resourceType, name string) func(c labstack.Context, session *core.Object) (middleware.ResourceRef, error) {
	return func(c labstack.Context, _ *core.Object) (middleware.ResourceRef, error) {
		return middleware.ResourceRef{Type: resourceType, ID: c.Param(name)}, nil
	}
}
