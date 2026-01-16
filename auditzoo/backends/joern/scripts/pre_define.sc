import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, StoredNode}

def minimalCoveringNodeInfo(path: String, startLine: Int, endLine: Int): Option[Long] = {
  def intPropOpt(n: StoredNode, key: String): Option[Int] = {
    n.propertyOption[Any](key).flatMap {
      case i: java.lang.Integer => Some(i.intValue)
      case i: Int               => Some(i)
      case l: java.lang.Long    => Some(l.toInt)
      case _                    => None
    }
  }

  def startOpt(n: StoredNode): Option[Int] = intPropOpt(n, "LINE_NUMBER")
  def endOpt(n: StoredNode): Option[Int]   = intPropOpt(n, "LINE_NUMBER_END")

  def span(n: StoredNode): Int = endOpt(n).get - startOpt(n).get
  def subtreeSize(n: AstNode): Int = n.ast.size

  val candidates: List[AstNode] =
    cpg.file.nameExact(path).ast.l
      // ignore nodes that don't have LINE_NUMBER_END (and also require LINE_NUMBER for range logic)
      .filter(n => startOpt(n).isDefined && endOpt(n).isDefined)
      // must cover [startLine, endLine]
      .filter { n =>
        val s = startOpt(n).get
        val e = endOpt(n).get
        s <= startLine && e >= endLine
      }

  if (candidates.isEmpty) {
    None
  } else {
    val minSpan = candidates.map(span).min
    val minSpanNodes = candidates.filter(n => span(n) == minSpan)

    // If multiple minimal nodes exactly cover [startLine, endLine], pick the biggest (largest AST subtree)
    val exactMinSpan = minSpanNodes.filter { n =>
      startOpt(n).contains(startLine) && endOpt(n).contains(endLine)
    }

    val chosen =
      if (exactMinSpan.nonEmpty) exactMinSpan.maxBy(subtreeSize)
      else minSpanNodes.minBy(subtreeSize) // deterministic fallback

    Some(chosen.id)
  }
}
