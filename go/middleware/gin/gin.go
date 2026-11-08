// Package gin is the gin integration of the Better IAM middleware. Middleware answers the IAM API (through the server's
// Node-style transport, so node protocol mounts such as the OAuth provider work) and gives every other request its
// helpers (FromContext, also `c.Get("iam")`); RequireSession and Authorize are route guards; ErrorHandler answers IAM
// refusals your handlers report with c.Error.
//
//	iamGin := gin.New(iam, middleware.Options{LoginPath: "/login"})
//	router := gingonic.New()
//	router.Use(iamGin.ErrorHandler(), iamGin.Middleware())
//	router.GET("/projects/:id", iamGin.Authorize("projects:read", middleware.AuthorizeSpec[*gingonic.Context]{
//		Resource: func(c *gingonic.Context, _ *core.Object) (middleware.ResourceRef, error) {
//			return middleware.ResourceRef{Type: "project", ID: c.Param("id")}, nil
//		},
//	}), handler)
package gin

import (
	"context"
	"net/http"

	gingonic "github.com/gin-gonic/gin"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/server"
)

// ContextKey is the gin context key of the request helpers.
const ContextKey = "iam"

// IamGin is the gin integration.
type IamGin struct {
	integration *middleware.Integration
}

// New is the gin integration over a composed server.
func New(iam *server.BetterIam, options middleware.Options) *IamGin {
	return NewWith(middleware.Server(iam), options)
}

// NewWith is the gin integration over any IAM implementation.
func NewWith(source middleware.IAM, options middleware.Options) *IamGin {
	return &IamGin{integration: middleware.NewIntegration(source, options)}
}

// NewLazy is the gin integration over an IAM instance resolved on use.
func NewLazy(resolve func(ctx context.Context) (middleware.IAM, error), options middleware.Options) *IamGin {
	return &IamGin{integration: middleware.NewLazyIntegration(resolve, options)}
}

// Resolve is the IAM instance.
func (g *IamGin) Resolve(ctx context.Context) (middleware.IAM, error) {
	return g.integration.Resolve(ctx)
}

// FromContext is the request helpers of a gin request (nil when the integration has not seen it).
func FromContext(c *gingonic.Context) *middleware.Helpers {
	if value, ok := c.Get(ContextKey); ok {
		if helpers, ok := value.(*middleware.Helpers); ok {
			return helpers
		}
	}
	return middleware.FromRequest(c.Request)
}

// Helpers is the request helpers, created on first use.
func (g *IamGin) Helpers(c *gingonic.Context) (*middleware.Helpers, error) {
	if existing := FromContext(c); existing != nil {
		return existing, nil
	}
	created, err := g.integration.NewHelpers(c.Writer.Header(), c.Request)
	if err != nil {
		return nil, err
	}
	c.Set(ContextKey, created)
	c.Request = c.Request.WithContext(middleware.WithHelpers(c.Request.Context(), created))
	return created, nil
}

// Middleware answers the IAM API under the Serve prefixes and gives every other request its helpers.
func (g *IamGin) Middleware() gingonic.HandlerFunc {
	return func(c *gingonic.Context) {
		iam, err := g.integration.Resolve(c.Request.Context())
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		serves, err := g.integration.Serves(iam, c.Request)
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if serves {
			c.Abort()
			g.integration.ServeIAM(c.Writer, c.Request, iam)
			return
		}
		if _, err := g.Helpers(c); err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.Next()
	}
}

// Answer answers an IAM refusal (the JSON error envelope, or a login / step-up redirect for pages); false when err is
// not one.
func (g *IamGin) Answer(c *gingonic.Context, err error) bool {
	return g.integration.Answer(c.Writer, c.Request, err)
}

func (g *IamGin) guard(spec middleware.GuardSpec[*gingonic.Context]) gingonic.HandlerFunc {
	return func(c *gingonic.Context) {
		helpers, err := g.Helpers(c)
		if err == nil {
			_, err = middleware.Guard(c.Request.Context(), g.integration, helpers, c, c.Request, spec)
		}
		if err != nil {
			if g.Answer(c, err) {
				c.Abort()
				return
			}
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.Next()
	}
}

// RequireSession is a guard requiring a session (and stepUp, when given).
func (g *IamGin) RequireSession(stepUp *middleware.StepUpRequirement) gingonic.HandlerFunc {
	return g.guard(middleware.GuardSpec[*gingonic.Context]{StepUp: stepUp})
}

// Authorize is a guard requiring a session allowed to perform action (default resource: the tenant). Resource and
// TenantID receive the gin context (read route parameters with c.Param).
func (g *IamGin) Authorize(action string, spec middleware.AuthorizeSpec[*gingonic.Context]) gingonic.HandlerFunc {
	return g.guard(spec.Guard(action))
}

// ErrorHandler answers the last error a handler reported with c.Error: an IAM refusal becomes the JSON error envelope
// (or a login / step-up redirect for pages), any other error a 500, unless the response already started.
func (g *IamGin) ErrorHandler() gingonic.HandlerFunc {
	return func(c *gingonic.Context) {
		c.Next()
		last := c.Errors.Last()
		if last == nil || c.Writer.Written() {
			return
		}
		if !g.Answer(c, last.Err) {
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}
	}
}

// TenantFromParam is an authorize TenantID callback reading the tenant from a route parameter.
func TenantFromParam(name string) func(c *gingonic.Context, session *core.Object) (string, error) {
	return func(c *gingonic.Context, _ *core.Object) (string, error) { return c.Param(name), nil }
}

// ResourceFromParam is an authorize Resource callback naming a resource of resourceType by a route parameter.
func ResourceFromParam(resourceType, name string) func(c *gingonic.Context, session *core.Object) (middleware.ResourceRef, error) {
	return func(c *gingonic.Context, _ *core.Object) (middleware.ResourceRef, error) {
		return middleware.ResourceRef{Type: resourceType, ID: c.Param(name)}, nil
	}
}
