package user

import (
	"errors"
	"time"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/google/uuid"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/bcrypt"
)

type userSignin struct {
	ud *db.UserData
}

// CanLogin returs true if the user is eligble for login
func (p *userSignin) CanLogin() bool {
	return !p.IsLocked() && p.IsConfirmed() && p.ud.BannedOn == nil
}

// IsLocked returns true if the user is locked
// this means there were too many failed login attempts recently
func (p *userSignin) IsLocked() bool {
	return p.ud.LockoutTill != nil && time.Now().UTC().Before(*p.ud.LockoutTill)
}

// IsConfirmed returns true if the user is confirmed
func (p *userSignin) IsConfirmed() bool {
	return p.ud.EmailConfirmed != nil
}

// ValidatePassword validates the users password
func (p *userSignin) ValidatePassword(password string) bool {
	res := bcrypt.CompareHashAndPassword(p.ud.PasswordHash, []byte(password))
	return res == nil
}

// Gets the current failed login count
func (p *userSignin) CurrentFailureCount() int {
	return p.ud.CurrentFailureCount
}

// Id - User ID
func (p *userSignin) ID() uuid.UUID {
	return p.ud.ID
}

// MFAEnabled returns true if mfa is required for login
// MFA BREAKS PASSWORD FLOW BE VARY OF THAT
func (p *userSignin) MFAEnabled() bool {
	return p.ud.TwoFactor
}

func (p *userSignin) ValidateOTP(otp string) error {
	//very basic technique to avoid replay attacks
	if !p.ud.OtpPending {
		return errors.New("already consumed")
	}
	topt := gotp.NewDefaultTOTP(p.ud.TwoFactorSecret)
	if !topt.Verify(otp, time.Now().Unix()) {
		return errors.New("invalid otp")
	}
	return nil
}
