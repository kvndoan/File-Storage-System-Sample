// Structs used
type User struct {
	Username string
	SourceKey      []byte
	PKEEncKey      userlib.PKEEncKey
	PKEDecKey      userlib.PKEDecKey
	DSSignKey      userlib.DSSignKey
	DSVerifyKey    userlib.DSVerifyKey
}

type FileReference struct {
	FileName  string
	Owner     bool
	UUID      uuid.UUID
	SymEncKey []byte
	HMACKey   []byte
}

type FileInfo struct {
	HeadUUID uuid.UUID
	OwnerUUID           uuid.UUID
	SymEncKey           []byte
	HMACKey             []byte
	AppendCount         int
	SharedTo            map[uuid.UUID][]uuid.UUID
	OutgoingInvitations []uuid.UUID
}

type FileContent struct {
	Curr uuid.UUID
}

type Invitation struct {
	FileInfoUUID     uuid.UUID
	FileSymmetricKey []byte
	FileHMACKey      []byte
}


// Initialize User
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		return nil, errors.New("Empty username")
	}
	userdata.Username = username
	userdata.HashedPassword = userlib.Hash([]byte(password))
	HashedUsername := userlib.Hash([]byte(username))
	UserUUID, err := uuid.FromBytes(HashedUsername[:16])
	print("username is: ", username, ", uuid is: ", UserUUID.String(), "\n")
	if err != nil {
		return nil, err
	}

	_, ok := userlib.DatastoreGet(UserUUID)
	if ok {
		return nil, errors.New("Username already exists")
	}

	userdata.SourceKey = userlib.RandomBytes(16)

	userdata.PKEEncKey, userdata.PKEDecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(userdata.Username+"_PKE", userdata.PKEEncKey)

	userdata.DSSignKey, userdata.DSVerifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(userdata.Username+"_DS", userdata.DSVerifyKey)

	SymmetricKey := userlib.Argon2Key(userdata.HashedPassword, HashedUsername, 16)
	iv := userlib.RandomBytes(16)
	JSONByteSlice, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	UserInfo := userlib.SymEnc(SymmetricKey, iv, JSONByteSlice)
	MAC, err := userlib.HashKDF(SymmetricKey, []byte("mac"))
	if err != nil {
		return nil, err
	}
	UserInfoMAC, err := userlib.HMACEval(MAC[:16], UserInfo)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(UserUUID, append(UserInfoMAC, UserInfo...))

	return &userdata, nil
}