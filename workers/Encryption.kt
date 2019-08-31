package workers

import java.io.File
import java.security.PrivateKey
import java.security.PublicKey

class Encryption{

    //streams
    private val input : File
    private val output : File

    //keys
    private val publicKey : PublicKey
    private val privateKey : PrivateKey

    constructor(input : File , output : File , publicKey: PublicKey , privateKey: PrivateKey){
        this.input = input
        this.output = output
        this.publicKey = publicKey
        this.privateKey = privateKey
    }

}