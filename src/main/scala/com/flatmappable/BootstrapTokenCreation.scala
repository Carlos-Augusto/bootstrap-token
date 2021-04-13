package com.flatmappable

import com.flatmappable.util.BootstrapHelper

import scala.io.StdIn.readLine

object BootstrapTokenCreation extends BootstrapHelper {

  private var currEvt = ""
  override def env: String = currEvt

  def main(args: Array[String]): Unit = {

    args.filter(_.nonEmpty).toList match {
      case List(env, username, password, secret) =>
        currEvt = env

        val purpose = {
          val p = readLine("Boostrap Token Purpose[Med_Test]:")
          if(p.isEmpty) "Farm_Carlos"
          else p
        }

        val groupId = {
          val p = readLine("Group ID[c727e72d-c60d-45e2-8393-cfb8cc42b183]:")
          if(p.isEmpty) "c727e72d-c60d-45e2-8393-cfb8cc42b183"
          else p
        }

        val keyCloakAccessToken = getKeycloakToken(username, password, secret)
        val tenantId = simpleExtractionTenantId(keyCloakAccessToken).getOrElse(throw new Exception("No Tenant Id Found"))
        println("- creating bootstrap token with purpose " + purpose + " for group " + groupId + " for " + username + " @" + env)
        val bootstrapToken = createBootstrapToken(keyCloakAccessToken, purpose, groupId, tenantId)
        println(" " + bootstrapToken)

        sys.exit(0)

      case _ =>
        println("params: env username password client_secret")
        sys.exit(1)

    }

  }

}

