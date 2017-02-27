package shine

import (
	"crypto/cipher"
	"crypto/aes"
	"errors"
	"crypto/md5"
	"io"
	"crypto/rand"
)

type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	iv   []byte
	info *cipherInfo
}

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

// iv: 初始向量（initialization vector）: 一个固定长度的输入值, 一般的使用上会要求它是随机数或拟随机数）
type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

// 高级加密标准（Advanced Encryption Standard，AES）
// AES加密数据块分组长度必须为128bit，密钥长度可以是128bit、192bit、256bit中的任意一个

// 5种加密模式：
// 1. ECB：电码本模式（Electronic Codebook Book)
// 2. CBC：密码分组链接模式（Cipher Block Chaining）
// 3. CTR：计算器模式（Counter）
// 4. CFB：密码反馈模式（Cipher FeedBack）
// 5. OFB：输出反馈模式（Output FeedBack）
var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb": {16, 16, newAESCFBStream},
	"aes-192-cfb": {24, 16, newAESCFBStream},
	"aes-256-cfb": {32, 16, newAESCFBStream},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = md5.Size

	// cnt := (keyLen-1)/md5Len + 1
	cnt := keyLen/md5Len
	if keyLen % md5Len >= 0 {
		cnt = cnt + 1
	}
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	info, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}
	key := evpBytesToKey(password, info.keyLen)
	c = &Cipher{key: key, info: info}
	return c, nil
}

func (c *Cipher) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

func (c *Cipher) encrypt(dst, src []byte){
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte){
	c.dec.XORKeyStream(dst, src)
}



// Copy creates a new cipher at it's initial state.
func (c *Cipher) Copy() *Cipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.
	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}
