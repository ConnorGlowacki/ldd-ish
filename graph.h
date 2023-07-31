#ifndef GRAPH_H
#define GRAPH_H

typedef struct Node {
    char *data;
    struct Node* next;
} Node;

typedef struct Graph {
    int numNodes;
    Node** adjacencyList;
} Graph;

Node* createNode(char *data);
Graph* createGraph(int numNodes);
void addEdge(Graph* graph, char *data, int fromNode, int toNode);
void printGraph(Graph* graph);
void destroyGraph(Graph* graph);

#endif