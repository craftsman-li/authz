package authz

import "github.com/jinzhu/gorm"

type User struct {
	gorm.Model

	Email    string `gorm:"size(60);unique_index" json:"email"`
	UserName string `gorm:"size(60);unique_index" json:"user_name"`
	Phone    string `gorm:"size(12);unique_index" json:"phone"`
	Status   int8   `json:"status"`
}
