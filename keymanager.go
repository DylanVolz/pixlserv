// keymanager.go
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
)

func runKeyManager() {
	router := NewRouter()

	log.Fatal(endless.ListenAndServe(":1337", router))
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func use(h http.HandlerFunc, middleware ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for _, m := range middleware {
		h = m(h)
	}

	return h
}

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return router
}

//use(myHandler, basicAuth)
var routes = Routes{
	Route{
		"addKey",
		"PUT",
		"/key",
		use(addKey),
	},
	Route{
		"showKey",
		"GET",
		"/key/{key}",
		use(showKey),
	},
	Route{
		"editKey",
		"POST",
		"/key/{key}",
		use(editKey),
	},
	Route{
		"deleteKey",
		"DELETE",
		"/key/{key}",
		use(deleteKey),
	},
	Route{
		"showKeys",
		"GET",
		"/keys",
		use(showAllKeys),
	},
	Route{
		"generateSecret",
		"POST",
		"/generatesecret/{key}",
		use(httpGenerateSecret),
	},
}

type Permissions struct {
	Get    []string
	Upload []string
}

type KeyPair struct {
	Key       string
	SecretKey string
}

type KeyInfo struct {
	Key         string
	Permissions Permissions
}

func logAndRespond(w http.ResponseWriter, err error, errorCode int) { //add logging levels, and seperate http error message
	log.Print(err)
	http.Error(w, err.Error(), errorCode)
}

func addKey(w http.ResponseWriter, r *http.Request) {
	buffer, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		log.Fatalf("Error reading request body: %s", err.Error())
		return
	}
	var permissions Permissions
	err = json.Unmarshal(buffer, &permissions)
	if err != nil {
		logAndRespond(w, err, http.StatusBadRequest)
		return
	}
	key, secretKey, err := generateKey(permissions.Get, permissions.Upload)
	if err != nil {
		log.Println("Adding a new API key failed, please try again")
		logAndRespond(w, fmt.Errorf("adding a new API key failed: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	log.Printf("Key added: %s, secret: %s\nPlease save these now!", key, secretKey)
	keyPair := KeyPair{
		Key:       key,
		SecretKey: secretKey,
	}
	if err := json.NewEncoder(w).Encode(keyPair); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError) //may need to change this handling
	}
}

func showKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]

	permissionTypes := []string{GetPermission, UploadPermission}

	log.Println("Key:", key)
	keyInfo := KeyInfo{
		Key: key,
	}
	for _, permissionType := range permissionTypes {
		permissions, err := infoAboutKey(key, permissionType)
		if err != nil {
			logAndRespond(w, err, http.StatusBadRequest)
			return
		}
		log.Printf("%s Permissions: %v", permissionType, permissions)
		if permissionType == GetPermission {
			keyInfo.Permissions = Permissions{
				Get: permissions,
			}
		} else if permissionType == UploadPermission {
			keyInfo.Permissions.Upload = permissions
		}
	}
	if err := json.NewEncoder(w).Encode(keyInfo); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError) //may need to change this handling
	}
}

type EditKey struct {
	Key         string
	Operation   string
	Permissions Permissions
}

func editKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]
	//"You need to provide an existing key, operation, permissionType and a permission"
	buffer, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		logAndRespond(w, fmt.Errorf("Error reading request body: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	var editKey EditKey
	err = json.Unmarshal(buffer, &editKey)
	if err != nil {
		logAndRespond(w, err, http.StatusBadRequest)
		return
	}

	permissionTypes := []string{GetPermission, UploadPermission}
	for _, permissionType := range permissionTypes {
		var permissions []string
		if permissionType == GetPermission {
			permissions = editKey.Permissions.Get
		} else if permissionType == UploadPermission {
			permissions = editKey.Permissions.Upload
		}
		for _, permission := range permissions {
			err := modifyKey(key, editKey.Operation, permissionType, permission)
			if err != nil {
				logAndRespond(w, err, http.StatusInternalServerError)
				return
			}
		}
	}
	log.Println("The key has been updated")

	if _, err := w.Write([]byte("The key has been updated")); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError)
	}
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]
	err := removeKey(key)
	if err != nil {
		logAndRespond(w, err, http.StatusInternalServerError)
		return
	}
	log.Println("The key was successfully removed")

	if _, err := w.Write([]byte("The key was successfully removed")); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError)
	}
}

func showAllKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := listKeys()
	if err != nil {
		logAndRespond(w, fmt.Errorf("Retrieving the list of all keys failed"), http.StatusInternalServerError)
		return
	}

	log.Println("Keys:", keys)
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError) //may need to change this handling
	}
}

func httpGenerateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]

	secret, err := generateSecret(key)
	if err != nil {
		logAndRespond(w, err, http.StatusInternalServerError)
		return
	}

	log.Printf("The new secret is: %s. Please save it now.", secret)
	keyPair := KeyPair{
		Key:       key,
		SecretKey: secret,
	}
	if err := json.NewEncoder(w).Encode(keyPair); err != nil {
		logAndRespond(w, err, http.StatusInternalServerError) //may need to change this handling
	}
}
