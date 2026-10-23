// vettalon keep-path template v1 (experimental `--joern-keep`).
//
// Fixed code: vettalon never writes anything into this file. Every
// parameter (language, source patterns, claimed file:line) is DATA read
// from /in/params.tsv and checked again here; a line that does not match the
// expected shape stops the run. Results go to /work/result.tsv in a line
// format vettalon parses strictly.
//
// The answer is one-sided: a data-flow path from a fixed source pattern to a
// call on the claimed line is reported as `path`, with the number of all
// flows and of "strict" flows (no hop between two arguments of the same
// non-operator call). vettalon uses a path only to keep a finding open;
// `no_path` and `no_sink` never close anything.
//
// Output lines (tab-separated):
//   vettalon-joern-result 1 | sources <n> |
//   query <id> <path|no_path|no_sink|no_file> <flows> <strict flows> |
//   step <id> <k> <file> <line|-> <code> | done

import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode, Expression}
import io.shiftleft.semanticcpg.language.*

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.regex.Pattern
import scala.collection.mutable.ListBuffer
import scala.jdk.CollectionConverters.*

object VettalonKeepPath {
  val ParamsFile = "/in/params.tsv"
  val ResultFile = "/work/result.tsv"
  val SrcRoot    = "/src"
  val MaxSteps   = 12
  val MaxText    = 160
  val Langs       = Set("php", "python", "jssrc", "golang", "java", "c", "ruby", "csharpsrc")
  val SourceKinds = Set("call_name", "ident_name", "call_code")
  val FilePattern = Pattern.compile("[A-Za-z0-9._/@+~ ()\\[\\]-]{1,512}")
  val IdPattern   = Pattern.compile("[0-9]{1,6}")
  val LinePattern = Pattern.compile("[1-9][0-9]{0,6}")

  case class Query(id: String, file: String, line: Int)
  case class Source(kind: String, pattern: Pattern)

  def bad(msg: String): Nothing = throw new IllegalArgumentException(s"vettalon params: $msg")

  /** One output field: no tabs, newlines or other control characters. */
  def clean(s: String): String = {
    val flat = s.map(c => if (Character.isISOControl(c)) ' ' else c)
    // Cut on a code point boundary, never inside a surrogate pair.
    if (flat.codePointCount(0, flat.length) > MaxText) flat.substring(0, flat.offsetByCodePoints(0, MaxText))
    else flat
  }

  /** CPG file names may be absolute under /src or relative to it. */
  def norm(name: String): String = {
    val a = if (name.startsWith(SrcRoot + "/")) name.substring(SrcRoot.length + 1) else name
    if (a.startsWith("./")) a.substring(2) else a
  }

  def validFile(f: String): Boolean =
    FilePattern.matcher(f).matches() && !f.startsWith("/") && !f.split("/").contains("..")

  def readParams(): (String, List[Source], List[Query]) = {
    val lines = Files.readAllLines(Paths.get(ParamsFile), StandardCharsets.UTF_8).asScala.toList
    if (lines.headOption != Some("vettalon-joern-params\t1")) bad("header")
    var lang: Option[String] = None
    val sources              = ListBuffer.empty[Source]
    val queries              = ListBuffer.empty[Query]
    lines.tail.foreach { line =>
      line.split("\t", -1).toList match {
        case List("lang", v) if Langs.contains(v) && lang.isEmpty => lang = Some(v)
        case List("source", k, re) if SourceKinds.contains(k)    => sources += Source(k, Pattern.compile(re))
        case List("query", id, file, ln)
            if IdPattern.matcher(id).matches() && validFile(file) && LinePattern.matcher(ln).matches() =>
          queries += Query(id, file, ln.toInt)
        case _ => bad("line")
      }
    }
    if (sources.isEmpty || queries.isEmpty) bad("empty")
    (lang.getOrElse(bad("language")), sources.toList, queries.toList)
  }

  def importFor(lang: String): Cpg = lang match {
    case "php"       => importCode.php(SrcRoot, "src")
    case "python"    => importCode.python(SrcRoot, "src")
    case "jssrc"     => importCode.jssrc(SrcRoot, "src")
    case "golang"    => importCode.golang(SrcRoot, "src")
    case "java"      => importCode.java(SrcRoot, "src")
    case "c"         => importCode.c(SrcRoot, "src")
    case "ruby"      => importCode.ruby(SrcRoot, "src")
    case "csharpsrc" => importCode.csharpsrc(SrcRoot, "src")
    case _           => bad("language")
  }

  def sourceNodes(cpg: Cpg, sources: List[Source]): List[CfgNode] = {
    def any(kind: String, text: String): Boolean =
      sources.exists(s => s.kind == kind && s.pattern.matcher(text).matches())
    val calls  = cpg.call.filter(c => any("call_name", c.name) || any("call_code", c.code)).l
    val idents = cpg.identifier.filter(i => any("ident_name", i.name)).l
    calls ++ idents
  }

  /** A hop between two different arguments of the same non-operator call
    * (`mysqli_query($conn, $q)` tainting `$conn` from `$q`). Joern assumes
    * this for calls it has no semantics for; the smoke test showed it
    * carrying a source to an unrelated later call. Counted separately so the
    * development split can decide whether to require paths without it.
    */
  def crossArgHop(a: AstNode, b: AstNode): Boolean = (a, b) match {
    case (x: Expression, y: Expression) =>
      val px = x.astParent
      px == y.astParent && x.argumentIndex != y.argumentIndex && (px match {
        case c: Call => !c.name.startsWith("<operator>")
        case _       => false
      })
    case _ => false
  }

  def strict(path: Path): Boolean =
    !path.elements.sliding(2).exists {
      case List(a, b) => crossArgHop(a, b)
      case _          => false
    }

  def stepLine(id: String, k: Int, e: AstNode): String = {
    val file = e.file.name.headOption.map(norm).getOrElse("-")
    val line = e.lineNumber.map(_.toString).getOrElse("-")
    s"step\t$id\t$k\t${clean(file)}\t$line\t${clean(e.code)}\n"
  }

  def run(): Unit = {
    val (lang, sources, queries) = readParams()
    val cpg                      = importFor(lang)
    val srcs                     = sourceNodes(cpg, sources)
    val ctx                      = EngineContext()
    val out                      = new StringBuilder("vettalon-joern-result\t1\n")
    out.append(s"sources\t${srcs.size}\n")
    val files = cpg.file.name.map(norm).toSet
    queries.foreach { q =>
      val calls = cpg.call.filter(c => c.lineNumber.contains(q.line) && norm(c.method.filename) == q.file).l
      // The claimed file is not in the CPG (missing, unreadable, not parsed):
      // an error for vettalon, not an answer.
      if (!files.contains(q.file)) out.append(s"query\t${q.id}\tno_file\t0\t0\n")
      else if (calls.isEmpty) out.append(s"query\t${q.id}\tno_sink\t0\t0\n")
      else if (srcs.isEmpty) out.append(s"query\t${q.id}\tno_path\t0\t0\n")
      else {
        val sinks: List[CfgNode] = calls.flatMap(_.argument.l) ++ calls
        val flows                = sinks.reachableByFlows(srcs)(ctx).l
        if (flows.isEmpty) out.append(s"query\t${q.id}\tno_path\t0\t0\n")
        else {
          val strictFlows = flows.filter(strict)
          out.append(s"query\t${q.id}\tpath\t${flows.size}\t${strictFlows.size}\n")
          val best = (if (strictFlows.nonEmpty) strictFlows else flows).minBy(_.elements.size)
          best.elements.take(MaxSteps).zipWithIndex.foreach { case (e, k) => out.append(stepLine(q.id, k, e)) }
        }
      }
    }
    out.append("done\n")
    // getBytes replaces anything unencodable instead of throwing.
    Files.write(Paths.get(ResultFile), out.toString.getBytes(StandardCharsets.UTF_8))
  }
}

@main def exec(): Unit = VettalonKeepPath.run()
