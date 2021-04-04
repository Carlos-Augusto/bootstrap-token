package com.flatmappable.util

import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.time.Clock
import java.util.{ Base64, TimeZone, UUID }

import com.ubirch.crypto.PrivKey
import org.joda.time.{ DateTime, DateTimeZone }
import org.json4s.jackson.JsonMethods.{ compact, parse }

object KeyRegistration {

  final val defaultDataFormat: SimpleDateFormat = {
    val _df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    _df.setTimeZone(TimeZone.getTimeZone("UTC"))
    _df
  }

  final val clock: Clock = Clock.systemUTC

  def dateTimeNowUTC: DateTime = DateTime.now(DateTimeZone.UTC)

  def now: Long = clock.millis()

  def pubKeyInfoData(
      algorithm: Symbol,
      created: String,
      hwDeviceId: String,
      pubKey: String,
      pubKeyId: String,
      validNotAfter: String,
      validNotBefore: String
  ): String = {
    s"""
       |{
       |   "algorithm": "${algorithm.name}",
       |   "created": "$created",
       |   "hwDeviceId": "$hwDeviceId",
       |   "pubKey": "$pubKey",
       |   "pubKeyId": "$pubKeyId",
       |   "validNotAfter": "$validNotAfter",
       |   "validNotBefore": "$validNotBefore"
       |}
    """.stripMargin
  }

  def pubKeyInfoData(clientUUID: UUID, algorithm: Symbol, sk: String, created: Long): String = {
    pubKeyInfoData(
      algorithm = algorithm,
      created = defaultDataFormat.format(created),
      hwDeviceId = clientUUID.toString,
      pubKey = sk,
      pubKeyId = sk,
      validNotAfter = defaultDataFormat.format(created + 31557600000L),
      validNotBefore = defaultDataFormat.format(created)
    )
  }

  def registrationData(pubKeyInfoData: String, signature: String): String = {
    s"""
       |{
       |   "pubKeyInfo": $pubKeyInfoData,
       |   "signature": "$signature"
       |}
    """.stripMargin
  }

  def createKey(
      uuid: UUID,
      algo: Symbol = KeyPairHelper.ECC_ED25519,
      clientKey: PrivKey = KeyPairHelper.privateKeyEd25519,
      created: Long = now
  ): (PrivKey, String, String) = {
    val pubKey = Base64.getEncoder.encodeToString(clientKey.getRawPublicKey)
    val info = compact(parse(pubKeyInfoData(uuid, algo, pubKey, created)))
    val signature = clientKey.sign(info.getBytes(StandardCharsets.UTF_8))
    val data = compact(parse(registrationData(info, Base64.getEncoder.encodeToString(signature))))
    val verification = clientKey.verify(info.getBytes, signature)

    if (!verification) throw new Exception("Key creation validation failed")

    (clientKey, info, data)

  }

}
