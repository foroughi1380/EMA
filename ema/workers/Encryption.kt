package ema.workers

import java.io.*
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

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
        if (!input.isFile) throw InvalidPathException("`${input.absolutePath}` is not a File.")
        if (!input.canRead()) throw NoPermissionException("`${input.absolutePath}` permission denied.")
        if (input.name.toByteArray().size > 512 - (1 + 32 + 2 + 11) ) throw InvalidNameException("File name is large") // Head File is 512 Byte => 1 Byte to Store Version of Program , 32 Byte to store Secret Key , 2 Byte to Controller , other Byte to File name , 11 is padding

        if (!dir_output.exists()) throw DirectoryNotExistException ("`${dir_output.exists()}` is not exist.")
        if (!dir_output.isDirectory) throw IsNotDirectory("`${dir_output.absolutePath}` is not a directory.")
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
        *  Head is : |one Byte Version|32 Byte Secret key|2 Byte size Controller|2 byte controller|other byte for name
        * */
        val version = VERSION

        //create key
        val generator = KeyGenerator.getInstance(AES)
        generator.init(256)
        val key = generator.generateKey()

        val name_bytes = input.name.toByteArray()

        //create size controller (convert a short value to 2 byte)
        var total = inStream.available()
        var mode = 0
        if (total < FILE_READ_BUFF){
            mode = FILE_READ_BUFF - total
        }else{
            mode = FILE_READ_BUFF - (total % FILE_READ_BUFF)
        }
        var size_controller = ByteArray(2)
        size_controller[0] = (mode and 0xff).toByte()
        size_controller[1] = (mode shr 8 and 0xff).toByte()

        //create controller (convert a short value to 2 byte)
        val controller = ByteArray(2)
        val empty_byte = 512 - (name_bytes.size + 35) // 35 is version ,key and controller space
        controller[0] = (empty_byte and 0xff).toByte()
        controller[1] = (empty_byte shr 8 and 0xff).toByte()

        //create head byte array
        val head_bytes = arrayListOf<Byte>()
        head_bytes.add(version)
        head_bytes.addAll(key.encoded.toList())
        head_bytes.addAll(size_controller.toList())
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
        inStream.read(buff)
        buff = cipher.doFinal(buff)
        val head_reader = ByteArrayInputStream(buff)

        /* read data*/

        //read version
        val buff_version = ByteArray(1)
        head_reader.read(buff_version)
        val version = buff_version[0]

        //read secret key
        val buff_secret_key = ByteArray(32)
        head_reader.read(buff_secret_key)
        val secretKey = SecretKeySpec(buff_secret_key , AES)

        //read size controller
        //read controller
        val buff_size_controller = ByteArray(2)
        head_reader.read(buff_size_controller)
        val size_controller : Short = (buff_size_controller[1].toInt() and 0xFF shl 8 or (buff_size_controller[0].toInt() and 0xFF)).toShort()

        //read controller
        val buff_controller = ByteArray(2)
        head_reader.read(buff_controller)
        val controller : Short = (buff_controller[1].toInt() and 0xFF shl 8 or (buff_controller[0].toInt() and 0xFF)).toShort()

        //read file name
        val buff_name = ByteArray(512 - (1 + 32 + 2 + controller )) // controller is empty bytes
        head_reader.read(buff_name)
        val name = String(buff_name)

        //create and return the HeadFile
        return HeadFile(version , secretKey , size_controller , controller , name)
    }

    //write and read File
    fun encrypt(listener : ((p : Int) -> Unit)? = null){
        /*
        * this Encrypt the File
        * */
        var outputStream = outFile.outputStream()
        //First Write Head
        var key = writeHead(outputStream)

        //init cipher to coding
        var cipher = Cipher.getInstance(AES)
        cipher.init(Cipher.ENCRYPT_MODE , key)

        //get from input , Encrypt it and write it to output
        //get available byte an calc to call listener
        val total = inStream.available()
        val buff = ByteArray(FILE_READ_BUFF)
        var i = inStream.read(buff)
        while (i != -1){
            outputStream.write(cipher.doFinal(buff))
            i = inStream.read(buff)
            listener?.let { it((output.length() / total * 100).toInt()) }
        }
        inStream.close()
        outputStream.close()
    }
    fun decrypt(listener : ((p : Int) -> Unit)? = null , override : ((file_name : String ) -> Boolean)? = null ){
        /*
        * this method read head file and create the file
        * */
        var head = readHead() // read head file
        // init cipher
        var cipher = Cipher.getInstance(AES)
        cipher.init(Cipher.DECRYPT_MODE , head.key)


        //create output file
        var file = File(output , head.name)
        if (file.exists() && override != null){ // check and call to user to confirm override
            if (! override(file.name)) return // override permission is denied
        }


        //get Stream
        val outputStream = file.outputStream()
        //start decoding
        val buff = ByteArray(FILE_READ_BUFF_DECODE)
        var total = inStream.available()
        var i = inStream.read(buff)
        while (i != -1){
            var encode = cipher.doFinal(buff)

            if (inStream.available() == 0){ // trim the end of file
                encode = encode.sliceArray(0 until  (encode.size - head.size_controller))
            }

            outputStream.write(encode)
            i = inStream.read(buff)
            listener?.let { it((file.length() / total * 100).toInt())}
        }
        inStream.close()
    }
    companion object{
        const val VERSION : Byte = 1
        const val AES = "AES"
        const val RSA = "RSA"
        const val TYPE = "ema"
        private const val FILE_READ_BUFF = 2048
        private const val FILE_READ_BUFF_DECODE = 2064
        private data class HeadFile(val version : Byte , val key: SecretKey , val size_controller : Short , val controller : Short , val name : String) // data class for store read head file
        class DirectoryNotExistException(message : String) : Exception(message)
        class IsNotDirectory(message : String) : Exception(message)
        class NoPermissionException(message : String) : Exception(message)
        class InvalidPathException(message : String) : Exception(message)
        class InvalidNameException(message : String) : Exception(message)
    }
}