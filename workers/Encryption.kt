package workers

import java.io.File
import java.io.FileNotFoundException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.InvalidPathException
import java.security.PrivateKey
import java.security.PublicKey
import javax.naming.NoPermissionException

class Encryption{

    //streams
    private val input : File
    private val output : File

    //keys
    private val publicKey : PublicKey
    private val privateKey : PrivateKey

    constructor(input : File , dir_output : File , publicKey: PublicKey , privateKey: PrivateKey) {

        //check validation
        if (!input.exists()) throw FileNotFoundException("`${input.absolutePath}` is not exist.")
        if (!input.isFile) throw InvalidPathException("`${input.absolutePath}` is not a File.", null)
        if (!input.canRead()) throw NoPermissionException("`${input.absolutePath}` : Permission Denied.")

        if (!dir_output.exists()) throw FileAlreadyExistsException("`${dir_output.exists()}` is not exist.")
        if (!dir_output.isDirectory) throw InvalidPathException("`${dir_output.absolutePath}` is not a directory.", null)
        if (!dir_output.canWrite()) throw NoPermissionException("`${dir_output.absolutePath}` : Permission Denied.")

        //init vars
        this.input = input
        this.output = dir_output
        this.publicKey = publicKey
        this.privateKey = privateKey
    }
}