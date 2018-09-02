package authz

import (
	"github.com/Sirupsen/logrus"
	"github.com/craftsman-li/kit-wrapper/di"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

const (
	RbacDefaultEngine     = "web.engine"
	RbacDefaultRouteGroup = "web.routerGroup"
)

type RbacConfig struct {
	// 是否校验允不允许登录
	// 如果为true, 则在账号密码验证通过后，检验是否有此路径登录的权限
	LoginCheckEnable bool   `yaml:"login.check"`
	LoginUrl         string `yaml:"login.url"`
}

func NewDefaultRbacConfig() *RbacConfig {
	return &RbacConfig{
		LoginUrl: "/api/login",
	}
}

type Rbac struct {
	Gin         *gin.Engine      `inject:"web.engine"`
	RouterGroup *gin.RouterGroup `inject:"web.routerGroup"`
	RbacConfig  *RbacConfig      `inject:"rbac.config"`
	Db          *gorm.DB         `inject:"db"`
}

func init() {
	di.Register("rbac", &Rbac{})
}

func (r *Rbac) Open() error {
	if nil == r.RbacConfig {
		logrus.Debugf("rbac config not exist. set a default value.")
		r.RbacConfig = NewDefaultRbacConfig()
	}
	if nil != r.Gin && nil != r.RouterGroup {
		r.Gin.POST(r.RbacConfig.LoginUrl, r.Login)
	} else {
		logrus.Debugf("di container no routeGroup instance. rbac disable.")
	}
	if nil != r.RouterGroup {
		r.RouterGroup.GET("/logout", r.LogOut)
	}

	r.Db.AutoMigrate(&User{})
	return nil
}

func (r *Rbac) Close() {

}

func (r *Rbac) Login(c *gin.Context) {
	// 校验账号密码
	// 校验登录页面权限
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func (r *Rbac) LogOut(c *gin.Context) {

}
