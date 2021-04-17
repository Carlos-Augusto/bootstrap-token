package com.flatmappable

import java.time.Clock

import pdi.jwt.{Jwt, JwtOptions}
import org.json4s._
import org.json4s.jackson.JsonMethods._

import scala.io.Source

object SimpleTokenAnalyzer {

  final val ISSUER = "iss"
  final val SUBJECT = "sub"
  final val AUDIENCE = "aud"
  final val EXPIRATION = "exp"
  final val NOT_BEFORE = "nbf"
  final val ISSUED_AT = "iat"
  final val JWT_ID = "jti"

  final val PURPOSE_KEY = "pur"
  final val TARGET_IDENTITIES_KEY = "tid"
  final val TARGET_GROUPS_KEY = "tgp"
  final val ORIGIN_KEY = "ord"
  final val SCOPES_KEY = "scp"

  implicit val clock: Clock = Clock.systemUTC

  def extractStringAsOpt(key: String, obj: JValue): Option[String] = {
    (for {
      JObject(child) <- obj
      JField(k, JString(value)) <- child if k == key
    } yield value).headOption
  }

  def extractString(key: String, obj: JValue): String = extractStringAsOpt(key, obj).getOrElse("")

  def extractListString(key: String, obj: JValue): List[String] = {
    for {
      JObject(child) <- obj
      JField(k, JArray(scopes)) <- child if k == key
      JString(scope) <- scopes
    } yield scope
  }

  def main(args: Array[String]): Unit = {

    //Put file in resources
    val data = Source.fromResource("tokens.json").getLines().mkString(" ")

    val json = parse(data)

    val ts = for {
      JObject(child) <- json
      JField("data", JArray(tokens)) <- child
      JObject(token) <- tokens
      JField("tokenValue", JString(v)) <- token
    } yield v

    val opts = JwtOptions.DEFAULT.copy(signature = false, expiration = false)
    val decoded = ts
      .map(x => Jwt.decode(x, opts))
      .filter(_.isSuccess)
      .map(_.get)
      .sortBy(_.issuedAt)


    require(ts.size == decoded.size)

    println(
      decoded
        .map( x => parse(x.content))
        .map{ x =>
          PURPOSE_KEY + " " + extractString(PURPOSE_KEY, x) + " " +
            TARGET_GROUPS_KEY + " " + extractListString(TARGET_GROUPS_KEY, x) + " " +
            TARGET_IDENTITIES_KEY + " " + extractListString(TARGET_IDENTITIES_KEY, x) + " " +
            SCOPES_KEY + " " + extractListString(SCOPES_KEY, x)
        }
        .mkString("\n")
    )

  }
}
