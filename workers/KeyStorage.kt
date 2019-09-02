package workers;

import java.io.File
import java.io.FileNotFoundException
import java.lang.Exception
import java.nio.file.FileAlreadyExistsException
import java.nio.file.NotDirectoryException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.spec.SecretKeySpec

class KeyStorage {

    private val dir : File
    private val keys : ArrayList<String>

    constructor(dir : File){
        //check dir
        if (! dir.exists()) throw DirectoryNotExist("`${dir.absolutePath}` is not exist.")
        if (! dir.isDirectory) throw NotDirectoryException("`${dir.absolutePath}` is not a directory.")
        if (! (dir.canWrite() && dir.canRead())) throw NoPermissionException("`${dir.absolutePath}` Permission denied.")

        //init vars
        this.dir = dir
        this.keys = ArrayList<String>()

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

    //main utility functions
    fun loadKeyFiles(){
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

    companion object{
        private const val SELF_DIR = "self"
        private const val KEY_TYPE = "key"
        private const val RSA = "RSA"
        class DirectoryNotExist(message : String) : Exception(message)
        class NoPermissionException(message : String) : Exception(message)
        class NoKeyFound(message : String) : Exception(message)
        class CanNotRemoveFile(message : String) : Exception(message)
    }
}
