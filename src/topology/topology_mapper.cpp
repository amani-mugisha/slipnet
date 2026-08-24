#include "topology/topology_mapper.hpp"

#include <iostream>
#include <iomanip>

void TopologyMapper::clear()
{
    nodes.clear();
    edges.clear();
}


bool TopologyMapper::hasNode(
    const Node& node
) const
{
    for (const auto& existing : nodes)
    {
        /*
         * Address is the primary identity of a
         * network node when available.
         */
        if (
            !node.address.empty() &&
            existing.address == node.address
        )
        {
            return true;
        }

        /*
         * Fall back to the node name when an
         * address is unavailable.
         */
        if (
            node.address.empty() &&
            !node.name.empty() &&
            existing.name == node.name
        )
        {
            return true;
        }
    }

    return false;
}


bool TopologyMapper::hasEdge(
    const Edge& edge
) const
{
    for (const auto& existing : edges)
    {
        /*
         * Treat the topology as directional.
         *
         * A -> B is different from B -> A.
         */
        if (
            existing.from == edge.from &&
            existing.to == edge.to
        )
        {
            return true;
        }
    }

    return false;
}


void TopologyMapper::addNode(
    const Node& node
)
{
    if (node.name.empty() && node.address.empty())
    {
        return;
    }

    if (hasNode(node))
    {
        return;
    }

    nodes.push_back(node);
}


void TopologyMapper::addEdge(
    const Edge& edge
)
{
    if (
        edge.from.empty() ||
        edge.to.empty()
    )
    {
        return;
    }

    if (edge.from == edge.to)
    {
        return;
    }

    if (hasEdge(edge))
    {
        return;
    }

    edges.push_back(edge);
}


std::size_t TopologyMapper::nodeCount() const
{
    return nodes.size();
}


std::size_t TopologyMapper::edgeCount() const
{
    return edges.size();
}


void TopologyMapper::display() const
{
    std::cout
        << "\n"
        << "================================================================\n"
        << "                    NETWORK TOPOLOGY\n"
        << "================================================================\n";


    /*
     * ============================================================
     * NODES
     * ============================================================
     */

    std::cout
        << "\n"
        << " Nodes\n"
        << "----------------------------------------------------------------\n";

    if (nodes.empty())
    {
        std::cout
            << "  No nodes discovered.\n";
    }
    else
    {
        for (const auto& node : nodes)
        {
            std::cout
                << "  "
                << std::left
                << std::setw(18)
                << node.name
                << " ["
                << node.address
                << "]";

            if (!node.type.empty())
            {
                std::cout
                    << "  "
                    << node.type;
            }

            std::cout
                << '\n';
        }
    }


    /*
     * ============================================================
     * CONNECTIONS
     * ============================================================
     */

    std::cout
        << "\n"
        << " Connections\n"
        << "----------------------------------------------------------------\n";

    if (edges.empty())
    {
        std::cout
            << "  No connections mapped.\n";
    }
    else
    {
        for (const auto& edge : edges)
        {
            std::cout
                << "  "
                << edge.from
                << "  ->  "
                << edge.to
                << '\n';
        }
    }


    /*
     * ============================================================
     * SUMMARY
     * ============================================================
     */

    std::cout
        << "\n"
        << " Topology Summary\n"
        << "----------------------------------------------------------------\n"
        << "  Nodes         : "
        << nodes.size()
        << '\n'
        << "  Connections   : "
        << edges.size()
        << '\n'
        << "----------------------------------------------------------------\n";
}