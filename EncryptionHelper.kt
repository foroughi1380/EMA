import workers.Encryption
import workers.KeyStorage
import java.io.File
import java.nio.file.InvalidPathException
import java.nio.file.NotDirectoryException
import java.security.PrivateKey
import java.security.PublicKey

class EncryptionHelper{
    private lateinit var encryption : Encryption
    private lateinit var storage : KeyStorage
    private lateinit var privateKey : PrivateKey
    private lateinit var publicKey : PublicKey

    constructor(dir : File , pass : String , listener: InitListenerI){

        /*init key Storage*/
        try {

            this.storage = KeyStorage(dir , pass) // init storage

        }catch (de : KeyStorage.Companion.DirectoryNotExist){

            listener.initDirError(dir ,de)
            return

        }catch (de : NotDirectoryException){

            listener.initDirError(dir , de)
            return

        }catch (de : KeyStorage.Companion.NoPermissionException){

            listener.initPermissionDenied()
            return

        }catch (de : InvalidPathException){

            val res = listener.initInvalidKeyDirectory(dir)
            if (res.status == InitListenerI.Companion.NewKeyQ.Companion.Status.New){
                try {
                    this.storage = KeyStorage.createNewKeyDir(dir , res.pass)
                }catch (ps : KeyStorage.Companion.PassError){
                    res.Listener.initKeyPathIsDefined()
                }catch (e : java.lang.Exception){
                    res.Listener.noKnownError(e)
                }


            }else if (res.status == InitListenerI.Companion.NewKeyQ.Companion.Status.Import){

                if (res.file == null) {
                    res.Listener.keyFileNoFound()
                }

                KeyStorage.importKey(dir , res.file!!)
                val new_key = res.Listener.keyImportKey() // get import key from user
                this.storage = EncryptionHelper(dir , new_key , listener).storage

                if (this.storage == null) return

            }else{
                return
            }

        }catch (pe : KeyStorage.Companion.PassError){

            listener.initPasswordWrong()
            return

        }catch (e : java.lang.Exception){

            listener.noKnownError(e)
            return

        }


        //init private and public key
        this.privateKey = storage.getPrivateKey()
        this.publicKey = storage.getPublicKey()
    }

    companion object{
        interface InitListenerI{
            fun initDirError(dir : File , e : Exception)
            fun initPermissionDenied()
            fun initInvalidKeyDirectory(dir : File) : NewKeyQ
            fun initPasswordWrong()
            fun noKnownError(e : java.lang.Exception)

            companion object{
                data class NewKeyQ(val status : Status , val pass : String , val Listener : NewImportKeyI , val file : File?){
                    companion object{
                        enum class Status{No , New , Import}
                    }
                }

            }
        }
        interface NewImportKeyI : InitListenerI{
            fun initKeyPathIsDefined()
            fun keyFileNoFound()
            fun keyImportKey() : String
        }
    }
}