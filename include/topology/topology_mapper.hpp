#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "topology/edge.hpp"
#include "topology/node.hpp"

class TopologyMapper
{
public:

    void clear();

    void addNode(
        const Node& node
    );

    void addEdge(
        const Edge& edge
    );

    void display() const;

    std::size_t nodeCount() const;

    std::size_t edgeCount() const;

private:

    bool hasNode(
        const Node& node
    ) const;

    bool hasEdge(
        const Edge& edge
    ) const;

private:

    std::vector<Node> nodes;

    std::vector<Edge> edges;
};