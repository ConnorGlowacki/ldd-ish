#include <stdlib.h>
#include <stdio.h>
#include "graph.h"

// Function to create a new node with a given data value
Node* createNode(char *data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

// Function to initialize the graph with a given number of nodes
Graph* createGraph(int numNodes) {
    Graph* graph = (Graph*)malloc(sizeof(Graph));
    graph->numNodes = numNodes;
    graph->adjacencyList = (Node**)malloc(numNodes * sizeof(Node*));

    // Initialize the adjacency lists with NULL (no edges initially)
    for (int i = 0; i < numNodes; i++) {
        graph->adjacencyList[i] = NULL;
    }

    return graph;
}

// Function to add a directed edge between two nodes (fromNode to toNode)
void addEdge(Graph* graph, char *data, int fromNode, int toNode) {
    if (fromNode < 0 || fromNode >= graph->numNodes || toNode < 0 || toNode >= graph->numNodes) {
        // Invalid node indices
        return;
    }

    Node* newNode = createNode(data);
    newNode->next = graph->adjacencyList[fromNode];
    graph->adjacencyList[fromNode] = newNode;
}

// Function to print the adjacency list representation of the graph
void printGraph(Graph* graph) {
    for (int i = 0; i < graph->numNodes; i++) {
        printf("Adjacency list for node %d: ", i);
        Node* currentNode = graph->adjacencyList[i];
        while (currentNode != NULL) {
            printf("%s -> ", currentNode->data);
            currentNode = currentNode->next;
        }
        printf("NULL\n");
    }
}

// Function to free the memory allocated for the graph
void destroyGraph(Graph* graph) {
    if (graph == NULL) {
        return;
    }

    for (int i = 0; i < graph->numNodes; i++) {
        Node* currentNode = graph->adjacencyList[i];
        while (currentNode != NULL) {
            Node* nextNode = currentNode->next;
            free(currentNode);
            currentNode = nextNode;
        }
    }

    free(graph->adjacencyList);
    free(graph);
}
