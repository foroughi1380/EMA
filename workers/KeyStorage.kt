package workers;

import com.sun.org.apache.xml.internal.security.keys.keyresolver.implementations.PrivateKeyResolver
import java.io.File
import java.io.FileNotFoundException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.lang.Exception
import java.nio.file.FileAlreadyExistsException
import java.nio.file.InvalidPathException
import java.nio.file.NotDirectoryException
import java.security.*
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec

class KeyStorage {

    private val dir : File
    private val keys : ArrayList<String>
    private var publicKey : PublicKey?
    private val privateKey : PrivateKey?

    constructor(dir : File , pass : String){
        //check dir
        if (! dir.exists()) throw DirectoryNotExist("`${dir.absolutePath}` is not exist.")
        if (! dir.isDirectory) throw NotDirectoryException("`${dir.absolutePath}` is not a directory.")
        if (! (dir.canWrite() && dir.canRead())) throw NoPermissionException("`${dir.absolutePath}` Permission denied.")
        if (! File(dir , PAIR_FILE_FULL_NAME_STORAGE).exists()) throw InvalidPathException("`${dir.absolutePath}` Invalid path." , null)


        //init vars
        this.dir = dir
        this.keys = ArrayList<String>()

        //start read pair keys

        try {
            val key_pair = readPairKey(pass)
            this.publicKey = key_pair.public
            this.privateKey = key_pair.private
        }catch (e : Exception) {throw PassError("Invalid password")}

        //start load all public key
        loadKeyFiles()
    }

    // add remove and get public key
    fun add(name : String , publicKey: PublicKey){
        /*
        * this method store public key to a file with input name
        * */

        //create file output
        var key_file = File(dir , "$name.$KEY_TYPE")

        // check validation
        if (key_file.exists()) throw FileAlreadyExistsException("Can not store public key (${key_file.name} is alerity exist)")

        //start writing
        key_file.writeBytes(publicKey.encoded)

        //add to keys
        keys.add(name)
    }
    fun remove(name : String){
        /*
        * this method store public key to a file with input name
        * */

        //create file output
        var key_file = File(dir , "$name.$KEY_TYPE")

        // check validation
        if (! keys.contains(name)) throw NoKeyFound("$name not found")
        if (! key_file.exists()) throw FileNotFoundException("Can not store public key (${key_file.name} is alerity exist)")
        //delete file
        if (! key_file.delete()) throw CanNotRemoveFile("Can not remove Key file")
        keys.remove(name)
    }
    fun get(name : String) : PublicKey{
        /*
        * this method get the public key from file an return it to user
        * */

        //create file output
        var key_file = File(dir , "$name.$KEY_TYPE")

        // check validation
        if (! keys.contains(name)) throw NoKeyFound("$name not found")
        if (! key_file.exists()){
            keys.remove(name)
            throw FileNotFoundException("Can not store public key (${key_file.name} is alerity exist)")
        }

        //read key bytes
        var key_bytes = key_file.readBytes()

        return KeyFactory.getInstance(RSA).generatePublic(X509EncodedKeySpec(key_bytes))
    }
    fun getAll() : ArrayList<String>{
        return keys.clone() as ArrayList<String>
    }

    fun getPublicKey() : PublicKey{
        return this.publicKey?:throw NoKeyFound("KeyNotFound")
    }
    fun getPrivateKey() : PrivateKey{
        return this.privateKey?:throw NoKeyFound("KeyNotFound")
    }
    //main utility functions
    private fun loadKeyFiles(){
        /*
        * this method get list of file in main dir and add to keys
        * */

        //get directory list with
        var key_list = dir.list{file , name ->
            if (! file.isFile) return@list false
            var name_split = name.split(".")
            if (name_split[0].isNullOrBlank() || name_split[0].isEmpty()) return@list false
            if (! (name_split[-1] != KEY_TYPE)) return@list false

            return@list true
        }

        //add to array
        keys.clear()
        keys.addAll(key_list)
    }
    private fun readPairKey(pass : String) : KeyPair{
        /*
        * this method read a object of pair key in self.pairema
        * */

        //create key
        val md = MessageDigest.getInstance("md5")
        val byte_key = md.digest(pass.toByteArray())
        val key = SecretKeySpec(byte_key , AES)

        //create file to read from it
        val input_read = File(dir , PAIR_FILE_FULL_NAME_STORAGE)

        //create cipher
        val cipher = Cipher.getInstance(AES)
        cipher.init(Cipher.DECRYPT_MODE ,  key)
        val cipher_input = CipherInputStream(input_read.inputStream() , cipher)

        //init to read object
        val reader = ObjectInputStream(cipher_input)

        //start read
        val pair = reader.readObject() as KeyPair

        return pair
    }
    companion object{
        private const val PAIR_FILE_TYPE = "pairema"
        private const val PAIR_FILE_FULL_NAME_STORAGE = "self.$PAIR_FILE_TYPE"
        private const val KEY_TYPE = "key"
        private const val RSA = "RSA"
        private const val RSA_KEY_SIZE = 4096
        private const val AES = "AES"
        class DirectoryNotExist(message : String) : Exception(message)
        class NoPermissionException(message : String) : Exception(message)
        class NoKeyFound(message : String) : Exception(message)
        class CanNotRemoveFile(message : String) : Exception(message)
        class PassError(message : String) : Exception(message)

        //static functions
        fun createNewKeyDir(dir : File , pass : String) : KeyStorage{
            /*
            * this method create
            * */

            //check validation
            if (! dir.exists()) throw DirectoryNotExist("`${dir.path}` is not exist.")
            if (! dir.isDirectory) throw NotDirectoryException("`${dir.path}` is not a directory.")
            if (! (dir.canWrite() && dir.canRead())) throw NoPermissionException("`${dir.path}` can not read or write to this path")
            if (pass.trim().isNullOrEmpty()) throw PassError("the length of array is error.")

            //create byte for encrypt keys
            var md = MessageDigest.getInstance("md5")
            val key_byte = md.digest(pass.toByteArray())
            val key = SecretKeySpec(key_byte , AES)

            //init key file
            val key_file = File(dir  , PAIR_FILE_FULL_NAME_STORAGE)

            //init cipher
            val cipher = Cipher.getInstance(AES)
            cipher.init(Cipher.ENCRYPT_MODE , key)
            val cipher_output = CipherOutputStream(key_file.outputStream() , cipher)

            //init object output storage
            val writer = ObjectOutputStream(cipher_output)


            //create pair key
            val generator = KeyPairGenerator.getInstance(RSA)
            generator.initialize(RSA_KEY_SIZE)
            val pair_key = generator.generateKeyPair()

            //write the pair key
            writer.writeObject(pair_key)
            writer.close()

            return KeyStorage(dir , pass)
        }
    }
}
