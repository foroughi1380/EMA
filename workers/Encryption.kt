package workers

import java.io.File
import java.io.FileNotFoundException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.FileAlreadyExistsException
import java.nio.file.InvalidPathException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.naming.InvalidNameException
import javax.naming.NoPermissionException


class Encryption{

    //streams
    private val input : File
    private val output : File
    private val inStream : InputStream
    private val outStream : OutputStream

    //keys
    private val publicKey : PublicKey
    private val privateKey : PrivateKey

    constructor(input : File, dir_output : File, publicKey: PublicKey, privateKey: PrivateKey, outputname : String = input.name) {

        /*check validation*/
        if (!input.exists()) throw FileNotFoundException("`${input.absolutePath}` is not exist.")
        if (!input.isFile) throw InvalidPathException("`${input.absolutePath}` is not a File.", null)
        if (!input.canRead()) throw NoPermissionException("`${input.absolutePath}` : Permission Denied.")
        if (input.name.toByteArray().size > 512 - (1 + 32 + 2) ) throw InvalidNameException("File name is large") // Head File is 512 Byte => 1 Byte to Store Version of Program , 32 Byte to store Secret Key , 2 Byte to Controller , other Byte to File name

        if (!dir_output.exists()) throw FileAlreadyExistsException("`${dir_output.exists()}` is not exist.")
        if (!dir_output.isDirectory) throw InvalidPathException("`${dir_output.absolutePath}` is not a directory.", null)
        if (!dir_output.canWrite()) throw NoPermissionException("`${dir_output.absolutePath}` : Permission Denied.")

        /*init vars*/
        this.input = input
        this.output = dir_output
        this.inStream = input.inputStream()
        this.publicKey = publicKey
        this.privateKey = privateKey
        this.outStream = File("${dir_output.absolutePath}${File.separator}${outputname.split(".")[0]}.${TYPE}").outputStream()
    }

    //Write , Read Head
    fun writeHead() : SecretKey{
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

        //create head bytes

        val head_bytes = arrayListOf<Byte>()
        head_bytes.add(version)
        head_bytes.addAll(key.encoded.toList())
        head_bytes.addAll(controller.toList())
        head_bytes.addAll(name_bytes.toList())

        //create output writer
        val cipher = Cipher.getInstance(RSA)
        cipher.init(Cipher.ENCRYPT_MODE , publicKey)
        val head_writer = CipherOutputStream(outStream , cipher)

        //start Write
        head_writer.write(head_bytes.toByteArray())

        return key
    }

    companion object{
        const val VERSION : Byte = 1
        const val AES = "AES"
        const val RSA = "RSA"
        const val TYPE = "ema"
    }
}