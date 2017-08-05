// keymanager_test
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var server *httptest.Server
var url string

func init() {
	// Connect to redis
	//err := redisInit()
	//if err != nil {
	//		fmt.Println(err)
	//	return
	//}
	//server = httptest.NewServer(NewRouter()) //Creating new server with the user handlers
	//url = server.URL

	url = "http://localhost:1337"
}

func TestCreateKey(t *testing.T) {
	permissions := Permissions{
		Get:    []string{"public", "private-key"},
		Upload: []string{"public", "private-key"},
	}
	permissionsJson, err := json.Marshal(permissions)
	if err != nil {
		t.Error(err)
	}

	request, err := http.NewRequest("PUT", fmt.Sprintf("%s/key", url), bytes.NewReader(permissionsJson)) //Create request with JSON body

	res, err := http.DefaultClient.Do(request)
	http.

	if err != nil {
		t.Error(err)
	}

	if res.StatusCode != 200 {
		t.Errorf("Success expected: %d", res.StatusCode) //Uh-oh this means our test failed
	}
	buffer, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	var keyPair KeyPair
	err = json.Unmarshal(buffer, &keyPair)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%+v\n", keyPair)

	request, err = http.NewRequest("GET", fmt.Sprintf("%s/key/%s", url, keyPair.Key), nil) //Create request with JSON body

	res, err = http.DefaultClient.Do(request)

	if err != nil {
		t.Error(err)
	}

	if res.StatusCode != 200 {
		t.Errorf("Success expected: %d", res.StatusCode) //Uh-oh this means our test failed
	}
	buffer, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	var keyInfo KeyInfo
	err = json.Unmarshal(buffer, &keyInfo)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%+v\n", keyInfo)

	//keyPair = KeyPair{Key: "b57bc2770d794d81bb93e5d25de9562d", SecretKey: "7391f823c86f43fa87eba91f64a53bcf"}
	//fmt.Printf("%+v\n", keyPair)

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	file := "/tmp/private-key_private-key_testimage.jpeg"
	// Add your image file
	f, err := os.Open(file)
	if err != nil {
		return
	}
	fw, err := w.CreateFormFile("image", file)
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, f); err != nil {
		return
	}
	// Add the other fields
	if fw, err = w.CreateFormField("timestamp"); err != nil {
		return
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	if _, err = fw.Write([]byte(timestamp)); err != nil {
		return
	}

	if fw, err = w.CreateFormField("signature"); err != nil {
		return
	}

	mac := hmac.New(sha256.New, []byte(keyPair.SecretKey))
	mac.Write([]byte(fmt.Sprintf("timestamp=%s", timestamp)))

	if _, err = fw.Write([]byte(hex.EncodeToString(mac.Sum(nil)))); err != nil {
		return
	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	pixlServUrl := fmt.Sprintf("https://tacklehealth.com:8443/%s/upload", keyPair.Key)

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", pixlServUrl, &b)
	if err != nil {
		t.Error(err)
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err = http.DefaultClient.Do(req)

	if err != nil {
		t.Error(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
		t.Error(err)
	}

	buffer, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(buffer))

	//	pixlServUrl = "http://localhost:3000/"

	//	// Now that you have a form, you can submit it to your handler.
	//	req, err = http.NewRequest("GET", pixlServUrl, nil)
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	// Don't forget to set the content type, this will contain the boundary.
	//	req.Header.Set("Content-Type", w.FormDataContentType())

	//	res, err = http.DefaultClient.Do(req)

	//	if err != nil {
	//		t.Error(err)
	//	}

	//	// Check the response
	//	if res.StatusCode != http.StatusOK {
	//		err = fmt.Errorf("bad status: %s", res.Status)
	//		t.Error(err)
	//	}

	//	buffer, err = ioutil.ReadAll(res.Body)
	//	if err != nil {
	//		t.Error(err)
	//	}

	//	fmt.Println(string(buffer))

	b.Reset()
	w = multipart.NewWriter(&b)
	file = "/tmp/public_private-key_testimage.jpeg"
	// Add your image file
	f, err = os.Open(file)
	if err != nil {
		return
	}
	fw, err = w.CreateFormFile("image", file)
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, f); err != nil {
		return
	}
	// Add the other fields
	if fw, err = w.CreateFormField("timestamp"); err != nil {
		return
	}
	timestamp = fmt.Sprintf("%d", time.Now().Unix())
	if _, err = fw.Write([]byte(timestamp)); err != nil {
		return
	}

	if fw, err = w.CreateFormField("signature"); err != nil {
		return
	}

	mac = hmac.New(sha256.New, []byte(keyPair.SecretKey))
	mac.Write([]byte(fmt.Sprintf("timestamp=%s", timestamp)))

	if _, err = fw.Write([]byte(hex.EncodeToString(mac.Sum(nil)))); err != nil {
		return
	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	pixlServUrl = fmt.Sprintf("https://tacklehealth.com:8443/%s/upload", keyPair.Key)

	// Now that you have a form, you can submit it to your handler.
	req, err = http.NewRequest("POST", pixlServUrl, &b)
	if err != nil {
		t.Error(err)
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err = http.DefaultClient.Do(req)

	if err != nil {
		t.Error(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
		t.Error(err)
	}

	buffer, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("SOOO CONFUSED")
	fmt.Println(string(buffer))
	var uploadResp UploadResponse
	err = json.Unmarshal(buffer, &uploadResp)
	if err != nil {
		t.Error(err)
	}

	fmt.Println("SOOO CONFUSED")

	permissions = Permissions{
		Get:    []string{"public"},
		Upload: []string{},
	}
	permissionsJson, err = json.Marshal(permissions)
	if err != nil {
		t.Error(err)
	}

	request, err = http.NewRequest("PUT", fmt.Sprintf("%s/key", url), bytes.NewReader(permissionsJson)) //Create request with JSON body

	res, err = http.DefaultClient.Do(request)

	if err != nil {
		t.Error(err)
	}

	if res.StatusCode != 200 {
		t.Errorf("Success expected: %d", res.StatusCode) //Uh-oh this means our test failed
	}
	buffer, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	var keyPair2 KeyPair
	err = json.Unmarshal(buffer, &keyPair2)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%+v\n", keyPair2)

	pixlServUrl = fmt.Sprintf("http://localhost:3000/%s/image/w_10,h_10/%s", keyPair2.Key, uploadResp.ImagePath)

	fmt.Println(pixlServUrl)

	// Now that you have a form, you can submit it to your handler.
	req, err = http.NewRequest("GET", pixlServUrl, nil)
	if err != nil {
		t.Error(err)
	}

	res, err = http.DefaultClient.Do(req)

	if err != nil {
		t.Error(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
		t.Error(err)
	}

	buffer, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(buffer))

	fmt.Println("EL FIN")
}
