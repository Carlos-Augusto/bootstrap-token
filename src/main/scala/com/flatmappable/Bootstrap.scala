package com.flatmappable

import java.util.UUID

import com.flatmappable.util.BootstrapHelper
import scala.io.StdIn.readLine

object Bootstrap extends BootstrapHelper {

  private var currEvt = ""
  override def env: String = currEvt

  def main(args: Array[String]): Unit = {

    args.filter(_.nonEmpty).toList match {
      case List(env, username, password, secret) =>
        currEvt = env

        val purpose = {
          val p = readLine("Boostrap Token Purpose[Kitchen_Carlos]:")
          if(p.isEmpty) "Farm_Carlos"
          else p
        }

        val groupId = {
          val p = readLine("Group ID[d6e525c0-41e2-4a77-925c-4d6ea4fb8431]:")
          if(p.isEmpty) "d6e525c0-41e2-4a77-925c-4d6ea4fb8431"
          else p
        }

        println("- getting keycloak token for " + username + " @" + env)
        val keyCloakAccessToken = getKeycloakToken(username, password, secret)
        val tenantId = simpleExtractionTenantId(keyCloakAccessToken).getOrElse("963995ed-ce12-4ea5-89dc-b181701d1d7b")

        val uuid = UUID.randomUUID()
        println("- registering key for " + uuid.toString)
        val privKey = registerKey(uuid)
        println("- creating bootstrap token with purpose " + purpose + " for group " + groupId)
        val bootstrapToken = createBootstrapToken(keyCloakAccessToken, purpose, groupId, tenantId)
        println("- using bootstrap token")
        val (c, a, v) = useBootstrapToken(bootstrapToken, uuid, privKey)
        println(" c:" + c)
        println(" a:" + a)
        println(" v:" + v)
        println("- registering device with registration token")
        registerDevice(uuid, "borrador " + uuid, c) // check result
        println("- sending upp with anchoring token")
        val (hash, ur) = sendUPP(uuid, a, getProtocol(privKey))
        println(s" status:${ur.status}  | ${ur.headers.map(_.toString).mkString(",")}")
        println(" hash:" + hash)
        println("- verifying with verification token")
        Thread.sleep(2000)
        val vr = verifyHash(hash, v)
        println(" upp:" + vr)
        sys.exit(0)

      case _ =>
        println("params: env username password client_secret")
        sys.exit(1)

    }

  }

}

