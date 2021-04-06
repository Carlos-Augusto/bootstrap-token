package com.flatmappable.util

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.{ Base64, UUID }

import com.flatmappable.util.KeyRegistration.createKey
import com.ubirch.client.keyservice.UbirchKeyService
import com.ubirch.client.protocol.{ CustomProtocol, DefaultProtocolSigner, DefaultProtocolVerifier }
import com.ubirch.crypto.PrivKey
import com.ubirch.protocol.{ Protocol, ProtocolMessage }
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.{ ByteArrayEntity, ContentType, StringEntity }
import org.apache.http.message.BasicNameValuePair
import org.json4s.JsonAST.{ JField, JObject, JString }

import scala.jdk.CollectionConverters._
import scala.util.Random

trait BootstrapHelper extends RequestClient {

  def env: String

  def getProtocol(privKey: PrivKey) = new CustomProtocol(
    new DefaultProtocolSigner(_ => Some(privKey)),
    new DefaultProtocolVerifier(new UbirchKeyService(s"https://key.$env.ubirch.com"))
  )

  def digestSHA512(data: Array[Byte]): Array[Byte] = {
    val digest: MessageDigest = MessageDigest.getInstance("SHA-512")
    digest.update(data)
    digest.digest
  }

  def signSHA512(privKey: PrivKey, data: Array[Byte]): Array[Byte] = {
    val dataToSign = digestSHA512(data)
    privKey.sign(dataToSign)
  }

  def getKeycloakToken(username: String, password: String, clientSecret: String): String = {
    val keycloakPost = new HttpPost(s"https://id.$env.ubirch.com/auth/realms/ubirch-default-realm/protocol/openid-connect/token")
    val clientIdParam = new BasicNameValuePair("client_id", "ubirch-2.0-user-access")
    val usernameParam = new BasicNameValuePair("username", username)
    val passwordParam = new BasicNameValuePair("password", password)
    val grantTypeParam = new BasicNameValuePair("grant_type", "password")
    val clientSecretParam = new BasicNameValuePair("client_secret", clientSecret)
    val params = List(clientIdParam, usernameParam, passwordParam, grantTypeParam, clientSecretParam)
    keycloakPost.setEntity(new UrlEncodedFormEntity(params.asJava, StandardCharsets.UTF_8))

    JsonHelper.use(call(keycloakPost).body).map { x =>
      (for {
        JObject(c) <- x
        JField("access_token", JString(token)) <- c
      } yield token).headOption.getOrElse(throw new Exception("No Access Token Retrieved: " + x))
    }
  }.getOrElse(throw new Exception("Error getting keycloak token"))

  def registerKey(uuid: UUID): PrivKey = {
    val algo = KeyPairHelper.ECC_ECDSA
    val clientKey = KeyPairHelper.getClientKey(algo)
    val (_, _, data) = createKey(uuid, algo = algo, clientKey = clientKey)

    val regRequest = new HttpPost(s"https://key.$env.ubirch.com/api/keyService/v1/pubkey")
    regRequest.setHeader("Content-Type", "application/json")
    regRequest.setEntity(new StringEntity(data))
    callAsString(regRequest)

    clientKey
  }

  def createBootstrapToken(keyCloakAccessToken: String, purpose: String, targetGroupId: String, tenantId: String): String = {
    val createBootstrapReq = new HttpPost(s"https://token.$env.ubirch.com/api/tokens/v2/create")
    val bootstrapTokenCreation =
      s"""
        |{
        |  "tenantId":"$tenantId",
        |  "purpose":"$purpose",
        |  "targetGroups": ["$targetGroupId"],
        |  "expiration": 6311390400,
        |  "notBefore":null,
        |  "scopes": ["thing:bootstrap"]
        |}""".stripMargin

    createBootstrapReq.setEntity(new StringEntity(bootstrapTokenCreation, ContentType.APPLICATION_JSON))
    createBootstrapReq.setHeader("Authorization", "bearer " + keyCloakAccessToken)

    JsonHelper.use(call(createBootstrapReq).body).map { x =>
      (for {
        JObject(c) <- x
        JField("data", JObject(d)) <- c
        JField("token", JString(token)) <- d
      } yield token).headOption.getOrElse(throw new Exception("No Bootstrap Token Retrieved"))
    }
  }.getOrElse(throw new Exception("Error getting ubirch token"))

  def useBootstrapToken(bootstrapToken: String, uuid: UUID, privKey: PrivKey): (String, String, String) = {
    val useBootstrapReq = new HttpPost(s"https://token.$env.ubirch.com/api/tokens/v2/bootstrap")
    val bootstrapUsage = s"""{"token":"$bootstrapToken","identity":"${uuid.toString}"}"""
    val signature = Base64.getEncoder.encodeToString(signSHA512(privKey, bootstrapUsage.getBytes(StandardCharsets.UTF_8)))

    useBootstrapReq.setEntity(new StringEntity(bootstrapUsage, ContentType.APPLICATION_JSON))
    useBootstrapReq.setHeader("Authorization", "bearer " + bootstrapToken)
    useBootstrapReq.setHeader("X-Ubirch-Signature", signature)

    JsonHelper.use(call(useBootstrapReq).body).map { x =>
      (for {
        JObject(c) <- x
        JField("data", JObject(d)) <- c
        JField("registration", JObject(token1data)) <- d
        JField("token", JString(token1)) <- token1data
        JField("anchoring", JObject(token2data)) <- d
        JField("token", JString(token2)) <- token2data
        JField("verification", JObject(token3data)) <- d
        JField("token", JString(token3)) <- token3data
      } yield (token1, token2, token3)).headOption.getOrElse(throw new Exception("No Bootstrap Tokens Retrieved"))
    }
  }.getOrElse(throw new Exception("Error getting ubirch bootstrap tokens"))

  def registerDevice(uuid: UUID, description: String, registrationToken: String): ResponseData[String] = {
    val consoleDeviceReq = new HttpPost(s"https://api.console.$env.ubirch.com/ubirch-web-ui/api/v1/devices/create")
    val registrationData =
      s"""
         |{
         |  "hwDeviceId":"$uuid",
         |  "description":"$description"
         |}""".stripMargin
    consoleDeviceReq.setEntity(new StringEntity(registrationData, ContentType.APPLICATION_JSON))
    consoleDeviceReq.setHeader("Authorization", "bearer " + registrationToken)

    callAsString(consoleDeviceReq)
  }

  def sendUPP(uuid: UUID, anchoringToken: String, protocol: CustomProtocol): (String, ResponseData[Array[Byte]]) = {

    val toSend = digestSHA512(Random.nextBytes(9))
    val dataToAnchorString = Base64.getEncoder.encodeToString(toSend)
    val upp = protocol.encodeSign(new ProtocolMessage(ProtocolMessage.SIGNED, uuid, 0x00, dataToAnchorString), Protocol.Format.MSGPACK)

    val regRequest = new HttpPost(s"https://niomon.$env.ubirch.com")
    regRequest.setHeader("Content-Type", "application/octet-stream")
    regRequest.setHeader("X-Ubirch-Hardware-Id", uuid.toString)
    regRequest.setHeader("X-Ubirch-Auth-Type", "ubirch-token")
    regRequest.setHeader("X-Ubirch-Credential", anchoringToken)
    regRequest.setEntity(new ByteArrayEntity(upp))

    (dataToAnchorString, call(regRequest))

  }

  def verifyHash(hash: String, verificationToken: String): String = {
    val consoleDeviceReq = new HttpPost(s"https://verify.$env.ubirch.com/api/v2/upp/verify")
    consoleDeviceReq.setEntity(new StringEntity(hash, ContentType.APPLICATION_JSON))
    consoleDeviceReq.setHeader("Authorization", "bearer " + verificationToken)
    val res = call(consoleDeviceReq)
    JsonHelper.use(res.body).map { x =>
      (for {
        JObject(c) <- x
        JField("upp", JString(token)) <- c
      } yield token).headOption.getOrElse(throw new Exception("No Verification Found:" + res.status))
    }.getOrElse(throw new Exception("Verification Failed:" + res.status))
  }

  def simpleExtractionTenantId(keycloakToken: String): Option[String] = {
    keycloakToken.split("\\.", 3).toList match {
      case List(_,p,_) =>
        val r = JsonHelper.use(Base64.getDecoder.decode(p)).map { x =>
          (for {
            JObject(c) <- x
            JField("sub", JString(tenantId)) <- c
          } yield tenantId).headOption.getOrElse(throw new Exception("No Tenant Found"))
        }.getOrElse(throw new Exception("Parsing failed"))
        Option(r)
      case Nil => None
    }

  }

}
