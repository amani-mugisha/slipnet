#pragma once

#include <vector>

#include "topology/node.hpp"

#include "topology/edge.hpp"

class TopologyMapper
{
public:

    void addNode(
        const Node& node
    );

    void addEdge(
        const Edge& edge
    );

    void display() const;

private:

    std::vector<Node> nodes;

    std::vector<Edge> edges;
};