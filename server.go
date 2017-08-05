package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/codegangsta/cli"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/binding"
	"github.com/martini-contrib/cors"
	"github.com/martini-contrib/secure"
	"github.com/tgulacsi/go/temp"
	"gopkg.in/throttled/throttled.v2"
	"gopkg.in/throttled/throttled.v2/store"
)

// UploadForm is a form structure to use when an image is POSTed to the server
type UploadForm struct {
	PhotoUpload *multipart.FileHeader `form:"image" binding:"required"`
	Timestamp   int64                 `form:"timestamp" binding:"required"`
	Signature   string                `form:"signature" binding:"required"`
}

var (
	uploadURLRe = regexp.MustCompile("/upload$")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	// Set up logging for CLI
	log.SetPrefix("")
	log.SetFlags(0) // Remove the timestamp

	// Connect to redis
	err := redisInit()
	if err != nil {
		log.Println("Connecting to redis failed", err)
		return
	}

	app := cli.NewApp()
	app.Name = "pixlserv"
	app.Usage = "transform and serve images"
	app.Version = "1.0"
	app.Commands = []cli.Command{
		{
			Name:  "run",
			Usage: "Runs the server (run [config-file] [server-name])",
			Action: func(c *cli.Context) {
				// Set up logging for server
				log.SetPrefix("[pixlserv] ")

				if len(c.Args()) < 1 {
					log.Println("You need to provide a path to a config file")
					return
				}
				log.Printf("%+v",c.Args())
				configFilePath := c.Args().First()
				serverName := c.Args()[1]

				// Initialise configuration
				err := configInit(configFilePath)
				if err != nil {
					log.Println("Configuration reading failed:", err)
					return
				}
				log.Printf("Running with server name: %s", serverName)
				log.Printf("Running with config: %+v", Config)

				// Initialise authentication
				err = authInit()
				if err != nil {
					log.Println("Authentication initialisation failed:", err)
					return
				}

				// Initialise storage
				err = storageInit()
				if err != nil {
					log.Println("Storage initialisation failed:", err)
					return
				}

				// Run the server
				m := martini.Classic()

				martini.Env = martini.Prod
				sslHost := fmt.Sprintf("%s:8443",serverName)
				m.Use(secure.Secure(secure.Options{
					SSLRedirect: true,
					SSLHost:     sslHost,
				}))

				if Config.throttlingRate > 0 {
					m.Use(throttler(Config.throttlingRate))
				}
				m.Use(func(res http.ResponseWriter, req *http.Request) {
					log.Println("in the use call...")
					log.Printf("%+v\n", req)
					if uploadURLRe.MatchString(req.URL.Path) {
						// The upload handler returns JSON
						res.Header().Set("Content-Type", "application/json")
					}
				})
				if Config.corsAllowOrigins != nil {
					m.Use(cors.Allow(&cors.Options{
						AllowOrigins: Config.corsAllowOrigins,
					}))
				}
				m.Get("/", func() string {
					return "It works!"
				})
				m.Get("/((?P<apikey>[a-z0-9]+)/)?image/:parameters/**", transformationHandler)
				m.Post("/((?P<apikey>[a-z0-9]+)/)?upload", binding.MultipartForm(UploadForm{}), uploadHandler)
				certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem",serverName)
				keyPath := fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem",serverName)
				go func() {
					if err := http.ListenAndServeTLS(":8443", certPath, keyPath, m); err != nil {
						fmt.Println(err)
					}
				}()
				go runKeyManager()

				// Wait for when the program is terminated
				ch := make(chan os.Signal)
				signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
				<-ch

				// Clean up
				redisCleanUp()
				storageCleanUp()
			},
		},
		{
			Name:  "api-key",
			Usage: "Manages API keys",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "Adds a new one",
					Action: func(c *cli.Context) {
						permissionsSet := c.Args()
						if permissionsSet[0] != GetPermission {

							return
						}

						key, secretKey, err := generateKey(permissionsSet[1:], permissionsSet[:])
						if err != nil {
							log.Println("Adding a new API key failed, please try again")
							return
						}

						log.Printf("Key added: %s, secret: %s\nPlease save these now!", key, secretKey)
					},
				},
				{
					Name:  "generatesecret",
					Usage: "Generates a new secret key for a given API key (generatesecret [key])",
					Action: func(c *cli.Context) {
						if len(c.Args()) < 1 {
							log.Println("You need to provide an existing key")
							return
						}
						key := c.Args().First()
						secret, err := generateSecret(key)
						if err != nil {
							log.Println(err.Error())
							return
						}
						log.Printf("The new secret is: %s. Please save it now.", secret)
					},
				},
				{
					Name:  "info",
					Usage: "Shows information about a key (info [key])",
					Action: func(c *cli.Context) {
						if len(c.Args()) < 1 {
							log.Println("You need to provide an existing key")
							return
						}
						permissionTypes := []string{GetPermission, UploadPermission}

						key := c.Args().First()
						log.Println("Key:", key)
						for _, permissionType := range permissionTypes {
							permissions, err := infoAboutKey(key, permissionType)
							if err != nil {
								log.Println(err.Error())
								return
							}
							log.Printf("%s Permissions: %v", permissionType, permissions)
						}
					},
				},
				{
					Name:  "list",
					Usage: "Shows all keys",
					Action: func(c *cli.Context) {
						keys, err := listKeys()
						if err != nil {
							log.Println("Retrieving the list of all keys failed")
							return
						}

						log.Println("Keys:", keys)
					},
				},
				{
					Name:  "modify",
					Usage: "Modifies permissions for a key (modify [key] [add/remove] [get/upload] [prefix])",
					Action: func(c *cli.Context) {
						if len(c.Args()) < 4 {
							log.Println("You need to provide an existing key, operation, permissionType and a permission")
							return
						}
						key := c.Args().First()
						err := modifyKey(key, c.Args()[1], c.Args()[2], c.Args()[3])
						if err != nil {
							log.Println(err.Error())
							return
						}
						log.Println("The key has been updated")
					},
				},
				{
					Name:  "remove",
					Usage: "Removes an existing key (remove [key])",
					Action: func(c *cli.Context) {
						if len(c.Args()) < 1 {
							log.Println("You need to provide an existing key")
							return
						}
						err := removeKey(c.Args().First())
						if err != nil {
							log.Println(err.Error())
							return
						}
						log.Println("The key was successfully removed")
					},
				},
			},
		},
	}

	app.Run(os.Args)
}

func transformationHandler(params martini.Params) (int, string) {
	baseImagePath, scale := parseBasePathAndScale(params["_1"])
	prefix := strings.Split(baseImagePath, "_")[0]
	if !hasPermission(params["apikey"], GetPermission, prefix) {
		return http.StatusUnauthorized, prefix
	}

	var transformation Transformation
	transformationName := parseTransformationName(params["parameters"])
	if transformationName != "" {
		var ok bool
		transformation, ok = Config.transformations[transformationName]
		if !ok {
			return http.StatusBadRequest, "Unknown transformation: " + transformationName
		}
	} else if Config.allowCustomTransformations {
		parameters, err := parseParameters(params["parameters"])
		if err != nil {
			return http.StatusBadRequest, err.Error()
		}
		transformation = Transformation{&parameters, nil, make([]*Text, 0)}
	} else {
		return http.StatusBadRequest, "Custom transformations not allowed"
	}
	//baseImagePath, scale := parseBasePathAndScale(params["_1"])
	if Config.allowCustomScale {
		parameters := transformation.params.WithScale(scale)
		transformation.params = &parameters
	}

	// Check if the image with the given parameters already exists
	// and return it
	fullImagePath, _ := transformation.createFilePath(baseImagePath)
	img, format, err := loadFromCache(fullImagePath)
	if err == nil {
		var buffer bytes.Buffer
		writeImage(img, format, &buffer)

		return http.StatusOK, buffer.String()
	}

	// Load the original image and process it
	if !imageExists(baseImagePath) {
		return http.StatusNotFound, "Image not found: " + baseImagePath
	}

	img, format, err = loadImage(baseImagePath)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}

	imgNew := transformCropAndResize(img, &transformation)

	var buffer bytes.Buffer
	err = writeImage(imgNew, format, &buffer)
	if err != nil {
		log.Println("Writing an image to the response failed:", err)
	}

	// Cache the image asynchronously to speed up the response
	go func() {
		err = addToCache(fullImagePath, imgNew, format)
		if err != nil {
			log.Println("Saving an image to cache failed:", err)
		}
	}()

	return http.StatusOK, buffer.String()
}

// UploadResponse is a struct to represent a JSON response for the upload handler
type UploadResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
	ImagePath    string `json:"imagePath"`
}

func uploadResponse(response UploadResponse) string {
	str, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error constructing JSON response for %v", response)
		return "{\"status\": \"error\", \"errorMessage\": \"server error\"}"
	}
	return string(str[:])
}

func uploadError(errorMessage string) string {
	return uploadResponse(UploadResponse{"error", errorMessage, ""})
}

func uploadSuccess(imagePath string) string {
	return uploadResponse(UploadResponse{"ok", "", imagePath})
}

func uploadHandler(params martini.Params, uf UploadForm) (int, string) {
	log.Println("Entered Upload")
	split := strings.Split(uf.PhotoUpload.Filename, "/")
	fileName := split[len(split)-1]
	uploadPrefix := strings.Split(fileName, "_")[1]

	fmt.Printf("checking uploadPrefix %s", uploadPrefix)

	if !hasPermission(params["apikey"], UploadPermission, uploadPrefix) {
		return http.StatusUnauthorized, uploadError("API key invalid or missing")
	}

	if uf.PhotoUpload == nil {
		return http.StatusBadRequest, uploadError("missing image field")
	}

	// Check signature only when API key is used
	// Note: when no API key is passed in but required for uploads, the above
	// hasPermission check should fail
	if params["apikey"] != "" {
		uploadTime := time.Unix(uf.Timestamp, 0)
		delta := time.Since(uploadTime).Minutes()
		if delta < 0 || delta > 5 {
			return http.StatusBadRequest, uploadError("invalid timestamp")
		}

		queryParams := make(map[string]string)
		queryParams["timestamp"] = strconv.FormatInt(uf.Timestamp, 10)

		secret, err := getSecretForKey(params["apikey"])
		if err != nil {
			return http.StatusBadRequest, uploadError("authorization error")
		}
		log.Printf("secret loaded from redis is: %s/n", secret)
		if !isValidSignature(uf.Signature, secret, queryParams) {
			return http.StatusBadRequest, uploadError(fmt.Sprintf("invalid signature: %s", uf.Signature))
		}
	}

	file, err := uf.PhotoUpload.Open()
	if err != nil {
		return http.StatusBadRequest, uploadError(err.Error())
	}

	reader, err := temp.NewReadSeeker(file)
	if err != nil {
		return http.StatusBadRequest, uploadError(err.Error())
	}

	c, _, err := image.DecodeConfig(reader)
	if err != nil {
		return http.StatusBadRequest, uploadError(err.Error())
	}
	reader.Seek(0, 0)

	pixels := c.Width * c.Height
	if pixels > Config.uploadMaxPixels {
		return http.StatusBadRequest, uploadError(fmt.Sprintf("too many pixels: %d, allowed: %d", pixels, Config.uploadMaxPixels))
	}

	limit := io.LimitReader(reader, int64(Config.uploadMaxFileSize+1))
	data, err := ioutil.ReadAll(limit)
	if err != nil {
		return http.StatusBadRequest, uploadError(err.Error())
	}
	if len(data) > Config.uploadMaxFileSize {
		return http.StatusBadRequest, uploadError("max file size exceeded")
	}

	img, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return http.StatusBadRequest, uploadError(err.Error())
	}

	defer file.Close()

	// Not a big fan of .jpeg file extensions

	baseImagePath := strings.Replace(fileName, "jpeg", "jpg", 1)
	log.Printf("Uploading %s", baseImagePath)

	// Eager transformations
	eagerlyTransform := func() {
		if len(Config.eagerTransformations) > 0 {
			for _, transformation := range Config.eagerTransformations {
				imgNew := transformCropAndResize(img, &transformation)
				fullImagePath, _ := transformation.createFilePath(baseImagePath)
				addToCache(fullImagePath, imgNew, format)
			}
		}
	}

	if Config.asyncUploads {
		go func() {
			_, err := saveImage(img, format, baseImagePath)
			if err != nil {
				log.Println("Error saving image:", err)
				return
			}
			go eagerlyTransform()
		}()
	} else {
		_, err := saveImage(img, format, baseImagePath)
		if err != nil {
			return http.StatusInternalServerError, uploadError("error saving image: " + err.Error())
		}
		go eagerlyTransform()
	}

	return http.StatusOK, uploadSuccess(baseImagePath)
}

func throttler(perMinRate int) http.Handler {
	t := throttled.RateLimit(throttled.PerMin(perMinRate), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(1000))
	return t.Throttle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Nothing needed here
	}))
}
