package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/garyburd/redigo/redis"
	"github.com/twinj/uuid"
)

const (
	// GetPermission = permission to get (and transform) images
	GetPermission = "get"
	// UploadPermission = permission to upload images
	UploadPermission = "upload"
)

var (
	permissionsByKey map[string]map[string]string
)

func init() {
	// Change the UUID format to remove surrounding braces and dashes
	uuid.SwitchFormat(uuid.Clean)
}

func authInit() error {
	keys, err := listKeys()
	if err != nil {
		return err
	}

	permissionsByKey = make(map[string]map[string]string)

	// Set up permissions for when there's no API key
	permissionsByKey[""] = make(map[string]string)
	permissionsByKey[""][GetPermission] = Config.authorisedGet
	permissionsByKey[""][UploadPermission] = Config.authorisedUpload

	// Set up get permissions for API keys
	for _, key := range keys {
		permissionsByKey[key] = make(map[string]string)
		getPermissions, err := infoAboutKey(key, "get")
		if err != nil {
			return err
		}
		uploadPermissions, err := infoAboutKey(key, "upload")
		if err != nil {
			return err
		}

		for i, getPermission := range getPermissions {
			if i == 0 {
				permissionsByKey[key]["get"] = getPermission
			} else {
				permissionsByKey[key]["get"] = fmt.Sprintf("%s,%s", permissionsByKey[key]["get"], getPermission)
			}
		}

		for i, uploadPermission := range uploadPermissions {
			if i == 0 {
				permissionsByKey[key]["upload"] = uploadPermission
			} else {
				permissionsByKey[key]["upload"] = fmt.Sprintf("%s,%s", permissionsByKey[key]["upload"], uploadPermission)
			}
		}
	}

	return nil
}

func hasPermission(key, permission, prefix string) bool {
	val, ok := permissionsByKey[key][permission]
	if ok {
		return strings.Contains(val, prefix)
	}
	return false
}

func generateKey(getPrefixes, uploadPrefixes []string) (string, string, error) {
	key := uuid.NewV4().String()
	secretKey := uuid.NewV4().String()
	_, err := Conn.Do("SADD", "api-keys", key)
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return "", "", fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err := Conn.Do("SADD", "api-keys", key)
		if err != nil {
			return "", "", err
		}
	}
	_, err = Conn.Do("HSET", "key:"+key, "secret", secretKey)
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return "", "", fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err = Conn.Do("HSET", "key:"+key, "secret", secretKey)
		if err != nil {
			return "", "", err
		}
	}
	if permissionsByKey != nil {
		permissionsByKey[key] = make(map[string]string)
	} else {
		permissionsByKey = make(map[string]map[string]string)
		permissionsByKey[key] = make(map[string]string)
	}
	args := []interface{}{"key:" + key + ":permissions:" + GetPermission}
	for i, getPrefix := range getPrefixes {
		args = append(args, getPrefix)
		if i == 0 {
			permissionsByKey[key]["get"] = getPrefix
		} else {
			permissionsByKey[key]["get"] = fmt.Sprintf("%s,%s", permissionsByKey[key]["get"], getPrefix)
		}
	}
	if len(args) > 1 {
		_, err = Conn.Do("SADD", args...)
	}
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return "", "", fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err = Conn.Do("SADD", args...)
		if err != nil {
			return "", "", err
		}
	}
	args = []interface{}{"key:" + key + ":permissions:" + UploadPermission}
	for i, uploadPrefix := range uploadPrefixes {
		args = append(args, uploadPrefix)
		if i == 0 {
			permissionsByKey[key]["upload"] = uploadPrefix
		} else {
			permissionsByKey[key]["upload"] = fmt.Sprintf("%s,%s", permissionsByKey[key]["upload"], uploadPrefix)
		}
	}
	if len(args) > 1 {
		_, err = Conn.Do("SADD", args...)
		if err != nil {
			redisCleanUp()
			err2 := redisInit()
			if err2 != nil {
				log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
				return key, secretKey, fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
			}
			_, err = Conn.Do("SADD", args...)
		}
	}
	return key, secretKey, err
}

func generateSecret(key string) (string, error) {
	err := checkKeyExists(key)
	if err != nil {
		return "", err
	}

	secretKey := uuid.NewV4().String()
	_, err = Conn.Do("HSET", "key:"+key, "secret", secretKey)
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return "", fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err = Conn.Do("HSET", "key:"+key, "secret", secretKey)
		if err != nil {
			return "", err
		}
	}

	return secretKey, nil
}

func infoAboutKey(key string, permissionType string) ([]string, error) {
	err := checkKeyExists(key)
	if err != nil {
		return nil, err
	}
	permissions, err := redis.Strings(Conn.Do("SMEMBERS", "key:"+key+":permissions:"+permissionType))
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return nil, fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		permissions, err = redis.Strings(Conn.Do("SMEMBERS", "key:"+key+":permissions:"+permissionType))
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(permissions)
	return permissions, nil
}

func listKeys() ([]string, error) {
	keys, err := redis.Strings(Conn.Do("SMEMBERS", "api-keys"))
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return keys, fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		return redis.Strings(Conn.Do("SMEMBERS", "api-keys"))
	}
	return keys, err
}

func modifyKey(key, op, permissionType, permission string) error {
	err := checkKeyExists(key)
	if err != nil {
		return err
	}
	if op != "add" && op != "remove" {
		return errors.New("modifier needs to be 'add' or 'remove'")
	}
	if permissionType != GetPermission && permissionType != UploadPermission {
		return fmt.Errorf("modifier needs to end with a valid permissionType: %s or %s", GetPermission, UploadPermission)
	}
	if op == "add" {
		_, err = Conn.Do("SADD", "key:"+key+":permissions:"+permissionType, permission)
		if err != nil {
			redisCleanUp()
			err2 := redisInit()
			if err2 != nil {
				log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			} else {
				_, err = Conn.Do("SADD", "key:"+key+":permissions:"+permissionType, permission)
			}
		}

		if permissionsByKey[key][permissionType] != "" {
			permissionsByKey[key][permissionType] = fmt.Sprintf("%s,%s", permissionsByKey[key][permissionType], permission)
		} else {
			permissionsByKey[key][permissionType] = permission
		}
	} else {
		_, err = Conn.Do("SREM", "key:"+key+":permissions:"+permissionType, permission)
		if err != nil {
			redisCleanUp()
			err2 := redisInit()
			if err2 != nil {
				log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			} else {
				_, err = Conn.Do("SREM", "key:"+key+":permissions:"+permissionType, permission)
			}
		}
		permissionsByKey[key][permissionType] = strings.Replace(permissionsByKey[key][permissionType], permission+",", "", 1) //if it is at the beginning or middle
		permissionsByKey[key][permissionType] = strings.Replace(permissionsByKey[key][permissionType], permission, "", 1)     //if it is at the end
	}
	return err
}

func removeKey(key string) error {
	err := checkKeyExists(key)
	if err != nil {
		return err
	}
	_, err = Conn.Do("SREM", "api-keys", key)
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err = Conn.Do("SREM", "api-keys", key)
		if err != nil {
			return err
		}
	}
	_, err = Conn.Do("DEL", "key:"+key+":permissions:get")
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		_, err = Conn.Do("DEL", "key:"+key+":permissions:get")
		if err != nil {
			return err
		}
	}
	_, err = Conn.Do("DEL", "key:"+key+":permissions:upload")
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		} else {
			_, err = Conn.Do("DEL", "key:"+key+":permissions:upload")
		}
	}
	permissionsByKey[key] = nil
	return err
}

func getSecretForKey(key string) (string, error) {
	err := checkKeyExists(key)
	if err != nil {
		return "", err
	}

	secret, err := redis.String(Conn.Do("HGET", "key:"+key, "secret"))

	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return "", fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		secret, err = redis.String(Conn.Do("HGET", "key:"+key, "secret"))
		if err != nil {
			return "", err
		}
	}

	return secret, nil
}

func authPermissionsOptions() string {
	return fmt.Sprintf("%s/%s", GetPermission, UploadPermission)
}

func checkKeyExists(key string) error {
	exists, err := redis.Bool(Conn.Do("SISMEMBER", "api-keys", key))
	if err != nil {
		redisCleanUp()
		err2 := redisInit()
		if err2 != nil {
			log.Printf("Reconnecting to redis failed: %s after error: %s", err2, err)
			return fmt.Errorf("Reconnecting to redis failed: %s after error: %s", err2, err)
		}
		exists, err = redis.Bool(Conn.Do("SISMEMBER", "api-keys", key))
		if err != nil {
			return err
		}
	}
	if !exists {
		return fmt.Errorf("key does not exist")
	}
	return nil
}

func isValidSignature(signature, secret string, queryParams map[string]string) bool {
	var keys []string
	for key := range queryParams {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	queryString := ""
	for _, key := range keys {
		if queryString != "" {
			queryString += "&"
		}
		queryString += key + "=" + queryParams[key]
	}

	expected := signQueryString(queryString, secret)
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(decodedSignature, expected)
}

func signQueryString(queryString, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(queryString))
	return mac.Sum(nil)
}
