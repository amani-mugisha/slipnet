#include "topology/topology_mapper.hpp"

#include <iostream>

void TopologyMapper::addNode(
    const Node& node
)
{
    nodes.push_back(node);
}

void TopologyMapper::addEdge(
    const Edge& edge
)
{
    edges.push_back(edge);
}

void TopologyMapper::display() const
{
    std::cout
        << "\nTOPOLOGY\n"
        << "========\n";

    std::cout
        << "\nNodes:\n";

    for (const auto& node : nodes)
    {
        std::cout
            << "  "
            << node.name
            << " ["
            << node.address
            << "] "
            << node.type
            << '\n';
    }

    std::cout
        << "\nConnections:\n";

    for (const auto& edge : edges)
    {
        std::cout
            << "  "
            << edge.from
            << " -> "
            << edge.to
            << '\n';
    }
}