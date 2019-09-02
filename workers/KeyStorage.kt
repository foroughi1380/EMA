package workers;

import java.io.File
import java.lang.Exception
import java.nio.file.NotDirectoryException

class KeyStorage {

    private val dir : File

    constructor(dir : File){
        //check dir
        if (! dir.exists()) throw DirectoryNotExist("`${dir.absolutePath}` is not exist.")
        if (! dir.isDirectory) throw NotDirectoryException("`${dir.absolutePath}` is not a directory.")

        //init vars
        this.dir = dir
    }



    companion object{
        class DirectoryNotExist(message : String) : Exception(message)
    }
}
