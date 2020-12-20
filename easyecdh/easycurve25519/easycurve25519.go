package easycurve25519

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/sinambela/easybuffer/bytesbuff"
	"golang.org/x/crypto/curve25519"
)

var errPrivateKeyLenNotValid = errors.New("Private Key length not valid.")

var errPublicKeyLenNotValid = errors.New("Public Key length not valid.")

var errPrivateKPEMNotValid = errors.New("Private Key PEM not valid.")

var errPublicKPEMNotValid = errors.New("Public Key PEM not valid.")

//NewECDHCurve25519 for
func NewECDHCurve25519() (*ECDHCurve25519, error) {
	ecdhx := new(ECDHCurve25519)

	if err := ecdhx.initx(); err != nil {
		return nil, err
	}

	return ecdhx, nil
}

//ECDHCurve25519 for
type ECDHCurve25519 struct {
	privK []byte
	pubK  []byte
}

func (x *ECDHCurve25519) initx() error {
	(*x).privK = make([]byte, 32)

	n, err := rand.Read((*x).privK)
	if err != nil {
		return err
	}

	if n != curve25519.ScalarSize {
		return errPrivateKeyLenNotValid
	}

	//------------calculate public key--------------------
	pubK, err := curve25519.X25519((*x).privK, curve25519.Basepoint)
	if err != nil {
		return err
	}

	if len(pubK) != curve25519.ScalarSize {
		return errPublicKeyLenNotValid
	}

	(*x).pubK = pubK
	return nil
}

//GetRawKey for
func (x *ECDHCurve25519) GetRawKey() (privK, pubK []byte) {

	privK = (*x).privK
	pubK = (*x).pubK

	return
}

//GetKeyOnHexString for
func (x *ECDHCurve25519) GetKeyOnHexString() (privK, pubK string) {
	privK = hex.EncodeToString((*x).privK)

	pubK = hex.EncodeToString((*x).pubK)

	return
}

//GetPEMKey for
func (x *ECDHCurve25519) GetPEMKey() (privK, pubK string, err error) {

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PRIVATE KEY",
		Bytes: (*x).privK,
	})

	privK = string(privPEM)

	//--------------pub key------------------------
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PUBLIC KEY",
		Bytes: (*x).pubK,
	})

	pubK = string(pubPEM)

	return
}

//GetSharedKeyOfSomeOneElseFromPubKeyHexStr for
func (x *ECDHCurve25519) GetSharedKeyOfSomeOneElseFromPubKeyHexStr(pubKHexStr string) (shareKHexStr string, err error) {
	pubK, errx := hex.DecodeString(pubKHexStr)
	if errx != nil {
		err = errx

		return
	}

	if len(pubK) != curve25519.ScalarSize {
		err = errPublicKeyLenNotValid

		return
	}

	sharedKey, errx := curve25519.X25519((*x).privK, pubK)
	if errx != nil {
		err = errx
		return
	}

	shareKHexStr = hex.EncodeToString(sharedKey)

	return
}

//GetSharedKeyOfSomeOneElseFromPubKeyPEM for
func (x *ECDHCurve25519) GetSharedKeyOfSomeOneElseFromPubKeyPEM(pubKPEMStr string, buffPool *bytesbuff.EasyBytes) (string, error) {
	buff := buffPool.GetBytesBuffer()
	defer buffPool.PutBytesBuffer(buff)

	_, err := buff.WriteString(pubKPEMStr)
	if err != nil {
		return "", err
	}

	pubKPEM, _ := pem.Decode(buff.Bytes())
	if pubKPEM == nil {
		return "", errPublicKPEMNotValid
	}

	shareKey, err := curve25519.X25519((*x).privK, pubKPEM.Bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(shareKey), nil
}

//ConvertPEMKeyToRawKey for
func ConvertPEMKeyToRawKey(privKPEMStr, pubKPEMStr string, bytesPool *bytesbuff.EasyBytes) (*ECDHCurve25519, error) {
	ecdhx := new(ECDHCurve25519)

	buffx := bytesPool.GetBytesBuffer()
	defer bytesPool.PutBytesBuffer(buffx)

	//===============private key========================
	_, err := buffx.WriteString(privKPEMStr)
	if err != nil {
		return nil, err
	}

	privKPEM, _ := pem.Decode(buffx.Bytes())
	if privKPEM == nil {
		return nil, errPrivateKPEMNotValid
	}

	(*ecdhx).privK = privKPEM.Bytes

	if len((*ecdhx).privK) != curve25519.ScalarSize {
		return nil, errPrivateKeyLenNotValid
	}

	//-------------reset buffer---------------------------------
	buffx.Reset()

	//---------------public key-----------------------------------
	_, err = buffx.WriteString(pubKPEMStr)
	if err != nil {
		return nil, err
	}

	pubKPEM, _ := pem.Decode(buffx.Bytes())
	if pubKPEM == nil {
		return nil, errPublicKPEMNotValid
	}

	(*ecdhx).pubK = pubKPEM.Bytes

	if len((*ecdhx).pubK) != curve25519.ScalarSize {
		return nil, errPublicKeyLenNotValid
	}

	return ecdhx, nil
}
