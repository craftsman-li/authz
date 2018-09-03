package authz

import (
	"github.com/Sirupsen/logrus"
	"github.com/casbin/casbin"
	"github.com/craftsman-li/kit-wrapper/di"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Config struct {
	SecretKey   string `cfg:"secret_key"`
	UserInfoKey string `cfg:"user_info_key"`
}

// 可以由外部解析生成
//      type A struct {
//          AuthzConfig *authz.Config `cfg:"authz_config"`
//      }
//      authz.AUthzConfig = a.AuthzConfig
var AuthzConfig *Config

func init() {
	AuthzConfig = &Config{
		SecretKey:   "authz.,",
		UserInfoKey: "user.info.session",
	}
	di.Register("authz_config", AuthzConfig)
}

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func NewAuthorizer(e *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		a := &BasicAuthorizer{enforcer: e}

		if permission, login := a.CheckPermission(c); !permission && !login {
			a.RequirePermission(c.Writer)
		}
	}
}

// BasicAuthorizer stores the casbin handler
type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

type AuthzClaims struct {
	*jwt.StandardClaims
	TokenType string
	CustomerInfo
}

type CustomerInfo struct {
	Id       string
	UserName string
	Email    string
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *BasicAuthorizer) GetUserName(c *gin.Context) string {
	if nil == AuthzConfig {
		logrus.Fatalln("authz config not init.")
		return defaultUser
	}
	session := sessions.Default(c)
	u := session.Get(AuthzConfig.UserInfoKey)

	if nil == u {
		// 尝试jwt
		token, err := request.ParseFromRequest(c.Request, request.AuthorizationHeaderExtractor,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(AuthzConfig.SecretKey), nil
			})
		if nil != err {
			a.NeedLogin(c.Writer)
			return defaultUser
		}
		if token.Valid {
			claims := token.Claims.(AuthzClaims)
			session.Set(AuthzConfig.UserInfoKey, claims.CustomerInfo)
			return claims.CustomerInfo.Id
		} else {
			a.NeedLogin(c.Writer)
		}
	} else {
		return u.(CustomerInfo).Id
	}

	return defaultUser

}

const defaultUser = "______......-------1024"

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *BasicAuthorizer) CheckPermission(c *gin.Context) (bool, bool) {
	r := c.Request
	user := a.GetUserName(c)
	if user == defaultUser {
		return false, true
	}
	method := r.Method
	path := r.URL.Path
	return a.enforcer.Enforce(user, path, method), false
}

// RequirePermission returns the 403 Forbidden to the client
func (a *BasicAuthorizer) RequirePermission(w http.ResponseWriter) {
	w.WriteHeader(403)
	w.Write([]byte("403 Forbidden\n"))
}

// RequirePermission returns the 401 Unauthorized to the client
func (a *BasicAuthorizer) NeedLogin(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("403 Forbidden\n"))
}
