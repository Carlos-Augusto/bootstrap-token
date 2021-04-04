package com.flatmappable
package util

import java.io.ByteArrayInputStream

import org.json4s.JValue
import org.json4s.jackson.JsonMethods

object JsonHelper {

  def closableTry[A, B](resource: => A)(cleanup: A => Unit)(code: A => B): Either[Exception, B] = {
    try {
      val r = resource
      try { Right(code(r)) } finally { cleanup(r) }
    } catch { case e: Exception => Left(e) }
  }

  def use(bytes: Array[Byte]): Either[Exception, JValue] = {
    closableTry(new ByteArrayInputStream(bytes))(_.close()) { is =>
      JsonMethods.parse(is)
    }
  }

}
