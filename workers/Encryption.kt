package workers

import java.io.*
import java.nio.file.FileAlreadyExistsException
import java.nio.file.InvalidPathException
import java.security.PrivateKey
import java.security.PublicKey
import java.util.RandomAccess
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.naming.InvalidNameException
import javax.naming.NoPermissionException


class Encryption{

    //streams
    private val input : File
    private val output : File
    private val inStream : InputStream
    private val outFile : File

    //keys
    private val publicKey : PublicKey
    private val privateKey : PrivateKey

    constructor(input : File, dir_output : File, publicKey: PublicKey, privateKey: PrivateKey, output_name : String? = input.name) {

        /*check validation*/
        if (!input.exists()) throw FileNotFoundException("`${input.absolutePath}` is not exist.")
        if (!input.isFile) throw InvalidPathException("`${input.absolutePath}` is not a File.", null)
        if (!input.canRead()) throw NoPermissionException("`${input.absolutePath}` permission denied.")
        if (input.name.toByteArray().size > 512 - (1 + 32 + 2 + 11) ) throw InvalidNameException("File name is large") // Head File is 512 Byte => 1 Byte to Store Version of Program , 32 Byte to store Secret Key , 2 Byte to Controller , other Byte to File name , 11 is padding

        if (!dir_output.exists()) throw FileAlreadyExistsException("`${dir_output.exists()}` is not exist.")
        if (!dir_output.isDirectory) throw InvalidPathException("`${dir_output.absolutePath}` is not a directory.", null)
        if (!dir_output.canWrite()) throw NoPermissionException("`${dir_output.absolutePath}` : Permission Denied.")


        /*init vars*/
        this.input = input
        this.output = dir_output
        this.inStream = input.inputStream()
        this.publicKey = publicKey
        this.privateKey = privateKey
        this.outFile = File("${dir_output.absolutePath}${File.separator}${output_name!!.split(".")[0]}.${TYPE}")
    }

    //Write , Read Head
    private fun writeHead(outputStream: OutputStream) : SecretKey{


        /*
        *  Head length = 512 Byte
        *  Head is : |one Byte Version|32 Byte Secret key|2 Byte Controller|
        * */
        val version = VERSION

        //create key
        val generator = KeyGenerator.getInstance(AES)
        generator.init(256)
        val key = generator.generateKey()

        val name_bytes = input.name.toByteArray()

        //create controller (convert a short value to 2 byte)
        val controller = ByteArray(2)
        val empty_byte = 512 - (name_bytes.size + 35) // 35 is version ,key and controller space
        controller[0] = (empty_byte and 0xff).toByte()
        controller[1] = (empty_byte shr 8 and 0xff).toByte()

        //create head byte array
        val head_bytes = arrayListOf<Byte>()
        head_bytes.add(version)
        head_bytes.addAll(key.encoded.toList())
        head_bytes.addAll(controller.toList())
        head_bytes.addAll(name_bytes.toList())


        //start write
        val cipher = Cipher.getInstance(RSA)
        cipher.init(Cipher.ENCRYPT_MODE , publicKey)
        val ebytes = cipher.doFinal(head_bytes.toByteArray())
        outputStream.write(ebytes)
        return key
    }
    private fun readHead() : HeadFile {
        /*
        * this method read head file
        * one byte to version
        * 32 byte to secret key
        * 2 byte to controller
        * and other to name file
        * */



        //init reader
        val cipher = Cipher.getInstance(RSA)
        cipher.init(Cipher.DECRYPT_MODE , privateKey)
        var buff = ByteArray(512)
        val head_reader = CipherInputStream(inStream , cipher)

        /* read data*/

        //read version
        val buff_version = ByteArray(1)
        head_reader.read(buff_version)
        val version = buff_version[0]

        //read secret key
        val buff_secret_key = ByteArray(32)
        head_reader.read(buff_secret_key)
        val secretKey = SecretKeySpec(buff_secret_key , AES)

        //read controller
        val buff_controller = ByteArray(2)
        head_reader.read(buff_controller)
        val controller : Short = (buff_controller[1].toInt() and 0xFF shl 8 or (buff_controller[0].toInt() and 0xFF)).toShort()

        //read file name
        val buff_name = ByteArray(512 - (1 + 32 + 2 + controller )) // controller is empty bytes
        head_reader.read(buff_name)
        val name = String(buff_name)

        //create and return the HeadFile
        return HeadFile(version , secretKey , controller , name)
    }

    //write and read File
    fun Encrypt(){

    }
    companion object{
        const val VERSION : Byte = 1
        const val AES = "AES"
        const val RSA = "RSA"
        const val TYPE = "ema"
        private data class HeadFile(val version : Byte , val key: SecretKey , val controller : Short , val name : String) // data class for store read head file
    }
}