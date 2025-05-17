package handles

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"time"

	"github.com/Xhofe/go-cache"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/op"
	"github.com/alist-org/alist/v3/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
    	"strings"
    	"os"

)

var telegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN") // Set this in your environment


var loginCache = cache.NewMemCache[int]()
var (
	defaultDuration = time.Minute * 5
	defaultTimes    = 5
)

type LoginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password"`
	OtpCode  string `json:"otp_code"`
}

func Login(c *gin.Context) {
	// check count of login
	ip := c.ClientIP()
	count, ok := loginCache.Get(ip)
	if ok && count >= defaultTimes {
		common.ErrorStrResp(c, "Too many unsuccessful sign-in attempts have been made using an incorrect username or password, Try again later.", 429)
		loginCache.Expire(ip, defaultDuration)
		return
	}
	// check username
	var req LoginReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user, err := op.GetUserByName(req.Username)
	if err != nil {
		common.ErrorResp(c, err, 400)
		loginCache.Set(ip, count+1)
		return
	}
	// validate password
	if err := user.ValidatePassword(req.Password); err != nil {
		common.ErrorResp(c, err, 400)
		loginCache.Set(ip, count+1)
		return
	}
	// check 2FA
	if user.OtpSecret != "" {
		if !totp.Validate(req.OtpCode, user.OtpSecret) {
			common.ErrorStrResp(c, "Invalid 2FA code", 402)
			loginCache.Set(ip, count+1)
			return
		}
	}
	// generate token
	token, err := common.GenerateToken(user.Username)
	if err != nil {
		common.ErrorResp(c, err, 400, true)
		return
	}
	common.SuccessResp(c, gin.H{"token": token})
	loginCache.Del(ip)
}

type UserResp struct {
	model.User
	Otp bool `json:"otp"`
}

// CurrentUser get current user by token
// if token is empty, return guest user
func CurrentUser(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	userResp := UserResp{
		User: *user,
	}
	userResp.Password = ""
	if userResp.OtpSecret != "" {
		userResp.Otp = true
	}
	common.SuccessResp(c, userResp)
}

func UpdateCurrent(c *gin.Context) {
	var req model.User
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	user.Username = req.Username
	if req.Password != "" {
		user.Password = req.Password
	}
	user.SsoID = req.SsoID
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

func Generate2FA(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, "Guest user can not generate 2FA code", 403)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Alist",
		AccountName: user.Username,
	})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	img, err := key.Image(400, 400)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	// to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	common.SuccessResp(c, gin.H{
		"qr":     "data:image/png;base64," + b64,
		"secret": key.Secret(),
	})
}

type Verify2FAReq struct {
	Code   string `json:"code" binding:"required"`
	Secret string `json:"secret" binding:"required"`
}

func Verify2FA(c *gin.Context) {
	var req Verify2FAReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.MustGet("user").(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, "Guest user can not generate 2FA code", 403)
		return
	}
	if !totp.Validate(req.Code, req.Secret) {
		common.ErrorStrResp(c, "Invalid 2FA code", 400)
		return
	}
	user.OtpSecret = req.Secret
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

// Helper function to verify Telegram data
func verifyTelegramAuth(data url.Values) bool {
    hash := data.Get("hash")
    data.Del("hash")

    var keys []string
    for k := range data {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    var dataStrings []string
    for _, k := range keys {
        dataStrings = append(dataStrings, k+"="+data.Get(k))
    }
    dataCheckString := strings.Join(dataStrings, "\n")

    secretKey := sha256.Sum256([]byte(telegramBotToken))
    h := hmac.New(sha256.New, secretKey[:])
    h.Write([]byte(dataCheckString))
    calculatedHash := hex.EncodeToString(h.Sum(nil))

    return calculatedHash == hash
}

// Handler for Telegram login
func TelegramLogin(c *gin.Context) {
    params := c.Request.URL.Query()

    if !verifyTelegramAuth(params) {
        common.ErrorStrResp(c, "Invalid Telegram login", 400)
        return
    }

    telegramID := params.Get("id")
    username := params.Get("username")
    if telegramID == "" || username == "" {
        common.ErrorStrResp(c, "Missing Telegram data", 400)
        return
    }

    // Try to fetch user by username, or by SsoID if your user model supports it
    user, err := op.GetUserByName(username)
    if err != nil {
        // User not found, create new user
        user = &model.User{
            Username: username,
            Password: "", // No password required
            SsoID:    telegramID,
        }
        if err := op.CreateUser(user); err != nil {
            common.ErrorResp(c, err, 500)
            return
        }
    }

    // Generate token
    token, err := common.GenerateToken(user.Username)
    if err != nil {
        common.ErrorResp(c, err, 500)
        return
    }

    // Set cookie for 1 week
    c.SetCookie("token", token, 7*24*3600, "/", "", false, true)
    common.SuccessResp(c, gin.H{"token": token, "username": user.Username})
}
