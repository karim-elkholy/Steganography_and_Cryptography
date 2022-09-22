package cryptography

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.Charset
import javax.imageio.ImageIO

fun getLeastSignificantBit(pixel: Int): Int = pixel and 1

fun setLeastSignificantBitToOne(pixel: Int): Int
{
    return if (pixel % 2 == 0) pixel + 1 else pixel
}


/**
 * Gets the last bit of a number.
 *
 * @param pixel Number to update.
 * @return Returns the last bit of a number.
 */
fun getLastBit(pixel: Int): Int = pixel.and(1)

/**
 * Updates the last bit of a number.
 *
 * @param pixel Number to update.
 * @param bit Bit to be added to the last bit of the number.
 * @return Returns the new number.
 */
fun setLastBit(pixel: Int, bit: Int): Int = pixel.and(254).or(bit)

/**
 * Converts a string to a list of bits.
 *
 * @param message String to convert.
 * @return Returns the list of bits represented as strings.
 */
fun convertMessageToListOfBits(message: String) : List<Int>
{
    //Return the message as a list of bits
    return message.toByteArray() //Convert the message to bytes
        .map { BigInteger(byteArrayOf(it)).toString(2).toInt() }
        .joinToString(separator = "") { String.format("%08d", it) }//Pad to 8 digits
        .chunked(1) //Split each bit into its own string
        .map { it.toInt() } //Convert each string representation to an int
}

fun hide(
    inputImageFile: File,
    outputImageFile: File,
    decryptedMessage: String,
    password: String
): String {

    //Convert the password to bits
    val passwordAsBits = convertMessageToListOfBits(
        password
    )

    //Convert the decrypted message to bits
    val decryptedMessageAsBits = convertMessageToListOfBits(
        decryptedMessage
    )

    //Encrypt the message
    val encryptedMessage = encrypt(decryptedMessageAsBits, passwordAsBits)

    //Get the marker as a list of bits
    val markerAsBits = convertMessageToListOfBits(
        "\u0000\u0000\u0003"
    )

    //Create the message to write
    val message = encryptedMessage.toMutableList()
    message.addAll(markerAsBits)

    //Read the image
    val image: BufferedImage = ImageIO.read( inputImageFile)

    //Stores the size available
    val availableSize = image.height * image.width

    //Return if there is not enough space to store the string
    if ( message.size > availableSize ) return "The input image is not large enough to hold this message"

    //Holds the current message index
    var messageIndex = 0

    //Iterate through each row
    start@ for (y in 0 until image.height) {
        //Iterate through each column
        for (x in 0 until image.width) {

            //Exit the two loops if the string is already complete
            if ( messageIndex == message.size) break@start

            // Read color from the (x, y) position
            val color = Color(image.getRGB(x, y))

            //Create the new colour
            val newColor = Color(
                color.red,
                color.green,
                setLastBit(color.blue, message[messageIndex])
            )
            // Set the new color at the (x, y) position
            image.setRGB(x, y, newColor.rgb)

            //Update the message index
            messageIndex += 1
        }
    }

    //Save the image
    ImageIO.write(image, "png", outputImageFile)

    //Return the fact that the image is saved
    return "Message saved in $outputImageFile image."
}
fun hideCli()
{
    println("Input image file:")
    val inputFilename = readln()

    println("Output image file:")
    val outputFilename = readln()

    println("Message to hide:")
    val messageToHide = readln().trim()

    println("Password:")
    val password = readln()

    try {
        //Store the path to image files
        val inputImageFile = File(inputFilename)
        val outputImageFile = File(outputFilename)

        //Print the message
        println( hide(inputImageFile, outputImageFile, messageToHide, password) )

    } catch (e:IOException)
    {
        //Print the exception
        println(e.message)
    }
}

fun encrypt(decryptedMessage: List<Int>, password: List<Int>) : List<Int>
{
    //Holds the encrypted message
    val encryptedMessage = mutableListOf<Int>()

    //Holds the password index
    var passwordIndex = 0

    //Iterate through the decrypted message
    decryptedMessage.forEach { element ->

        //Use the XOR operator on each bit
        encryptedMessage.add( element.xor(password[passwordIndex]))

        //Add 1 to the password index
        passwordIndex += 1

        //Go back to the start of the password if the password index exceeds the password
        if ( passwordIndex == password.size ) passwordIndex = 0
    }

    //Return the encrypted message
    return encryptedMessage
}

fun decrypt(encryptedMessage: List<Int>, password: List<Int>) : List<Int>
{
    //Holds the decrypted message
    val decryptedMessage = mutableListOf<Int>()

    //Holds the password index
    var passwordIndex = 0

    //Iterate through the encrypted message
    encryptedMessage.forEach { element ->

        //Use the XOR operator on each bit
        decryptedMessage.add( element.xor(password[passwordIndex]))

        //Add 1 to the password index
        passwordIndex += 1

        //Go back to the start of the password if the password index exceeds the password
        if ( passwordIndex == password.size ) passwordIndex = 0
    }

    //Return the decrypted message
    return decryptedMessage
}

fun show(
    inputFile: File,
    password: String
) : String
{
    //Read the image
    val image: BufferedImage = ImageIO.read( inputFile)


    //Holds all the bits
    val bits : StringBuilder = StringBuilder()

    //Convert the bytes that mark the end of a message to a list of bits
    val bytesAsBits = convertMessageToListOfBits("\u0000\u0000\u0003")
        .joinToString(separator = ""){ it.toString() }

    //Iterate through each row
    for (y in 0 until image.height) {
        //Iterate through each column
        for (x in 0 until image.width) {

            // Read color from the (x, y) position
            val color = Color(image.getRGB(x, y))

            //Get the last bit of the blue pixel
            bits.append( getLastBit(color.blue).toString() )
        }
    }

    //If the marker is found
    if ( bits.contains(bytesAsBits) )
    {
        //Get the encrypted message as a list of bits
        val encryptedMessageAsBits = bits.substring(
            0, bits.indexOf(bytesAsBits)
        )
        .chunked(1) //Split each bit into its own string
        .map { it.toInt() } //Convert each string representation to an int

        //Convert the password to bits
        val passwordAsBits = convertMessageToListOfBits(
            password
        )

        //Decrypt the message and store it in binary as a string
        val decryptedMessageBits = decrypt(
            encryptedMessageAsBits,
            passwordAsBits
        ).joinToString(separator = "") { it.toString() }

        //Convert the decrypted message back to its original form
        val decryptedMessage = BigInteger(decryptedMessageBits, 2)
            .toByteArray()
            .toString(Charset.forName("UTF-8"))

        return "Message:\n$decryptedMessage"
    }

    //Return that no message was found
    return "No message found!"
}

fun showCli()
{
    println("Input image file:")
    val inputFilename = readln()

    println("Password:")
    val password = readln()

    try {
        //Store the path to image files
        val inputImageFile = File(inputFilename)

        //Print the message
        println( show(inputImageFile, password ) )

    } catch (e:IOException)
    {
        //Print the exception
        println(e.message)
    }
}

fun main(args: Array<String>) {

    while ( true )
    {
        println("Task (hide, show, exit):")
        val input = readln()

        when (input) {
            "exit" -> {
                println("Bye!")
                break
            }
            "hide" -> {

                hideCli()
            }
            "show" -> {
                showCli()
            }
            else -> {
                println("Wrong task: $input")
            }
        }
    }
}
