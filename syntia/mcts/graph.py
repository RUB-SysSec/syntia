from collections import namedtuple
import re


class DiGraph(object):
    """
    Implementation of directed graph

    adapted from Miasm2
    """

    # Stand for a cell in a dot node rendering
    DotCellDescription = namedtuple("DotCellDescription",
                                    ["text", "attr"])

    def __init__(self):
        self._nodes = set()
        self._edges = []
        # N -> Nodes N2 with a edge (N -> N2)
        self._nodes_succ = {}
        # N -> Nodes N2 with a edge (N2 -> N)
        self._nodes_pred = {}

    def __repr__(self):
        out = []
        for node in self._nodes:
            out.append(str(node))
        for src, dst in self._edges:
            out.append("%s -> %s" % (src, dst))
        return '\n'.join(out)

    def nodes(self):
        return self._nodes

    def edges(self):
        return self._edges

    def merge(self, graph):
        """Merge the current graph with @graph
        @graph: DiGraph instance
        """
        for node in graph._nodes:
            self.add_node(node)
        for edge in graph._edges:
            self.add_edge(*edge)

    def __add__(self, graph):
        """Wrapper on `.merge`"""
        self.merge(graph)
        return self

    def copy(self):
        """Copy the current graph instance"""
        graph = self.__class__()
        return graph + self

    def __eq__(self, graph):
        if not isinstance(graph, self.__class__):
            return False
        return all((self._nodes == graph.nodes(),
                    sorted(self._edges) == sorted(graph.edges())))

    def add_node(self, node):
        """Add the node @node to the graph.
        If the node was already present, return False.
        Otherwise, return True
        """
        if node in self._nodes:
            return False
        self._nodes.add(node)
        self._nodes_succ[node] = []
        self._nodes_pred[node] = []
        return True

    def del_node(self, node):
        """Delete the @node of the graph; Also delete every edge to/from this
        @node"""

        if node in self._nodes:
            self._nodes.remove(node)
        for pred in self.predecessors(node):
            self.del_edge(pred, node)
        for succ in self.successors(node):
            self.del_edge(node, succ)

    def add_edge(self, src, dst):
        if not src in self._nodes:
            self.add_node(src)
        if not dst in self._nodes:
            self.add_node(dst)
        self._edges.append((src, dst))
        self._nodes_succ[src].append(dst)
        self._nodes_pred[dst].append(src)

    def add_uniq_edge(self, src, dst):
        """Add an edge from @src to @dst if it doesn't already exist"""
        if (src not in self._nodes_succ or
                dst not in self._nodes_succ[src]):
            self.add_edge(src, dst)

    def del_edge(self, src, dst):
        self._edges.remove((src, dst))
        self._nodes_succ[src].remove(dst)
        self._nodes_pred[dst].remove(src)

    def predecessors_iter(self, node):
        if not node in self._nodes_pred:
            raise StopIteration
        for n_pred in self._nodes_pred[node]:
            yield n_pred

    def predecessors(self, node):
        return [x for x in self.predecessors_iter(node)]

    def successors_iter(self, node):
        if not node in self._nodes_succ:
            raise StopIteration
        for n_suc in self._nodes_succ[node]:
            yield n_suc

    def successors(self, node):
        return [x for x in self.successors_iter(node)]

    def leaves_iter(self):
        for node in self._nodes:
            if not self._nodes_succ[node]:
                yield node

    def leaves(self):
        return [x for x in self.leaves_iter()]

    def heads_iter(self):
        for node in self._nodes:
            if not self._nodes_pred[node]:
                yield node

    def heads(self):
        return [x for x in self.heads_iter()]

    def nodeid(self, node):
        """
        Returns uniq id for a @node
        @node: a node of the graph
        """
        return hash(node) & 0xFFFFFFFFFFFFFFFF

    def node2lines(self, node):
        """
        Returns an iterator on cells of the dot @node.
        A DotCellDescription or a list of DotCellDescription are accepted
        @node: a node of the graph
        """
        yield self.DotCellDescription(text=str(node), attr={})

    def node_attr(self, node):
        """
        Returns a dictionary of the @node's attributes
        @node: a node of the graph
        """
        return {}

    def edge_attr(self, src, dst):
        """
        Return a dictionary of attributes for the edge between @src and @dst
        @src: the source node of the edge
        @dst: the destination node of the edge
        """
        return {}

    @staticmethod
    def _fix_chars(token):
        return "&#%04d;" % ord(token.group())

    @staticmethod
    def _attr2str(default_attr, attr):
        return ' '.join('%s="%s"' % (name, value)
                        for name, value in
                        dict(default_attr,
                             **attr).iteritems())

    def dot(self):
        """Render dot graph with HTML"""

        escape_chars = re.compile('[' + re.escape('{}') + '&|<>' + ']')
        td_attr = {'align': 'left'}
        nodes_attr = {'shape': 'Mrecord',
                      'fontname': 'Courier New'}

        out = ["digraph MCTS_TREE {\ngraph [pad=\".75\", ranksep=\"2\", nodesep=\"0.25\"];"]

        # Generate basic nodes
        out_nodes = []
        for node in self.nodes():
            node_id = self.nodeid(node)
            out_node = '%s [\n' % node_id
            out_node += self._attr2str(nodes_attr, self.node_attr(node))
            out_node += 'label =<<table border="0" cellborder="0" cellpadding="3">'

            node_html_lines = []

            for lineDesc in self.node2lines(node):
                out_render = ""
                if isinstance(lineDesc, self.DotCellDescription):
                    lineDesc = [lineDesc]
                for col in lineDesc:
                    out_render += "<td %s>%s</td>" % (
                        self._attr2str(td_attr, col.attr),
                        escape_chars.sub(self._fix_chars, str(col.text)))
                node_html_lines.append(out_render)

            node_html_lines = ('<tr>' +
                               ('</tr><tr>').join(node_html_lines) +
                               '</tr>')

            out_node += node_html_lines + "</table>> ];"
            out_nodes.append(out_node)

        out += out_nodes

        # Generate links
        for src, dst in self.edges():
            attrs = self.edge_attr(src, dst)

            attrs = ' '.join('%s="%s"' % (name, value)
                             for name, value in attrs.iteritems())

            out.append('%s -> %s' % (self.nodeid(src), self.nodeid(dst)) +
                       '[' + attrs + '];')

        out.append("}")
        return '\n'.join(out)

    @staticmethod
    def _reachable_nodes(head, next_cb):
        """Generic algorithm to compute all nodes reachable from/to node
        @head"""

        todo = set([head])
        reachable = set()
        while todo:
            node = todo.pop()
            if node in reachable:
                continue
            reachable.add(node)
            yield node
            for next_node in next_cb(node):
                todo.add(next_node)

    def reachable_sons(self, head):
        """Compute all nodes reachable from node @head. Each son is an
        immediate successor of an arbitrary, already yielded son of @head"""
        return self._reachable_nodes(head, self.successors_iter)

    def reachable_parents(self, leaf):
        """Compute all parents of node @leaf. Each parent is an immediate
        predecessor of an arbitrary, already yielded parent of @leaf"""
        return self._reachable_nodes(leaf, self.predecessors_iter)

    def _walk_generic_first(self, head, flag, succ_cb):
        """
        Generic algorithm to compute breadth or depth first search
        for a node.
        @head: the head of the graph
        @flag: denotes if @todo is used as queue or stack
        @succ_cb: returns a node's predecessors/successors
        :return: next node
        """
        todo = [head]
        done = set()

        while todo:
            node = todo.pop(flag)
            if node in done:
                continue
            done.add(node)

            for succ in succ_cb(node):
                todo.append(succ)

            yield node

    def walk_breadth_first_forward(self, head):
        """Performs a breadth first search on the graph from @head"""
        return self._walk_generic_first(head, 0, self.successors_iter)

    def walk_depth_first_forward(self, head):
        """Performs a depth first search on the graph from @head"""
        return self._walk_generic_first(head, -1, self.successors_iter)

    def walk_breadth_first_backward(self, head):
        """Performs a breadth first search on the reversed graph from @head"""
        return self._walk_generic_first(head, 0, self.predecessors_iter)

    def walk_depth_first_backward(self, head):
        """Performs a depth first search on the reversed graph from @head"""
        return self._walk_generic_first(head, -1, self.predecessors_iter)
