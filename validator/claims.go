package validator

import (
	"encoding/json"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims map[string]interface{}

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDateFromClaim(c["exp"])
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDateFromClaim(c["iat"])
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return numericDateFromClaim(c["nbf"])
}

func (c Claims) GetIssuer() (string, error) {
	value, _ := c["iss"].(string)
	return value, nil
}

func (c Claims) GetSubject() (string, error) {
	return c.Sub(), nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	switch value := c["aud"].(type) {
	case nil:
		return nil, nil
	case string:
		return jwt.ClaimStrings{value}, nil
	case []string:
		return jwt.ClaimStrings(value), nil
	case []interface{}:
		audience := make(jwt.ClaimStrings, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, nil
			}
			audience = append(audience, text)
		}
		return audience, nil
	default:
		return nil, nil
	}
}

func numericDateFromClaim(value interface{}) (*jwt.NumericDate, error) {
	seconds, ok := floatSecondsFromClaim(value)
	if !ok {
		return nil, nil
	}
	return jwt.NewNumericDate(timeFromFloatSeconds(seconds)), nil
}

func floatSecondsFromClaim(value interface{}) (float64, bool) {
	switch typedValue := value.(type) {
	case float64:
		return typedValue, true
	case float32:
		return float64(typedValue), true
	case int:
		return float64(typedValue), true
	case int64:
		return float64(typedValue), true
	case int32:
		return float64(typedValue), true
	case json.Number:
		parsedValue, err := typedValue.Float64()
		if err != nil {
			return 0, false
		}
		return parsedValue, true
	default:
		return 0, false
	}
}

func timeFromFloatSeconds(seconds float64) time.Time {
	integerPart, decimalPart := math.Modf(seconds)
	return time.Unix(int64(integerPart), int64(decimalPart*(1e9)))
}
