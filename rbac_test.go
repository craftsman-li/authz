package authz

import (
	"fmt"
	"github.com/craftsman-li/kit-wrapper/di"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogin(t *testing.T) {
	engine := gin.Default()
	group := engine.Group("/api/user")
	di.Register(RbacDefaultEngine, engine)
	di.Register(RbacDefaultRouteGroup, group)

	di.Resolve()

	req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(""))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// 提取响应
	result := w.Result()
	defer result.Body.Close()

	// 读取响应body
	body, _ := ioutil.ReadAll(result.Body)

	fmt.Println(string(body))
}
