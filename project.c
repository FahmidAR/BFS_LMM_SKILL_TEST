/*
 * Breadth-First Search (BFS) - Safe Implementation
 * Graph traversal using adjacency list and a bounded queue.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NODES  100
#define MAX_LABEL  32
#define QUEUE_SIZE 100

/* ---------- Graph ---------- */

typedef struct Node {
    int dest;
    struct Node *next;
} Node;

typedef struct {
    Node   *head[MAX_NODES];
    char    label[MAX_NODES][MAX_LABEL];
    int     count;
} Graph;

Graph *graph_create(void) {
    Graph *g = calloc(1, sizeof(Graph));
    return g;
}

void graph_free(Graph *g) {
    for (int i = 0; i < g->count; i++) {
        Node *cur = g->head[i];
        while (cur) {
            Node *tmp = cur;
            cur = cur->next;
            free(tmp);
        }
    }
    free(g);
}

int graph_add_node(Graph *g, const char *label) {
    if (g->count >= MAX_NODES) {
        fprintf(stderr, "Error: max node limit (%d) reached.\n", MAX_NODES);
        return -1;
    }
    strncpy(g->label[g->count], label, MAX_LABEL - 1);
    g->label[g->count][MAX_LABEL - 1] = '\0';
    return g->count++;
}

int graph_add_edge(Graph *g, int src, int dest) {
    if (src < 0 || src >= g->count || dest < 0 || dest >= g->count) {
        fprintf(stderr, "Error: invalid edge (%d -> %d).\n", src, dest);
        return -1;
    }
    Node *n = malloc(sizeof(Node));
    if (!n) { perror("malloc"); return -1; }
    n->dest = dest;
    n->next = g->head[src];
    g->head[src] = n;
    return 0;
}

/* ---------- Bounded Queue ---------- */

typedef struct {
    int data[QUEUE_SIZE];
    int front, rear, size;
} Queue;

void queue_init(Queue *q) {
    q->front = q->rear = q->size = 0;
}

int queue_is_empty(const Queue *q) { return q->size == 0; }

int queue_enqueue(Queue *q, int val) {
    if (q->size >= QUEUE_SIZE) {
        fprintf(stderr, "Error: queue overflow prevented.\n");
        return -1;
    }
    q->data[q->rear] = val;
    q->rear = (q->rear + 1) % QUEUE_SIZE;
    q->size++;
    return 0;
}

int queue_dequeue(Queue *q) {
    if (queue_is_empty(q)) {
        fprintf(stderr, "Error: dequeue on empty queue.\n");
        return -1;
    }
    int val = q->data[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    q->size--;
    return val;
}

/* ---------- BFS ---------- */

void bfs(const Graph *g, int start) {
    if (start < 0 || start >= g->count) {
        fprintf(stderr, "Error: start node %d out of range.\n", start);
        return;
    }

    int visited[MAX_NODES] = {0};
    Queue q;
    queue_init(&q);

    visited[start] = 1;
    queue_enqueue(&q, start);

    printf("BFS traversal from node \"%s\" (id=%d):\n", g->label[start], start);

    while (!queue_is_empty(&q)) {
        int cur = queue_dequeue(&q);
        printf("  Visited: %s\n", g->label[cur]);

        for (Node *nb = g->head[cur]; nb; nb = nb->next) {
            if (!visited[nb->dest]) {
                visited[nb->dest] = 1;
                queue_enqueue(&q, nb->dest);
            }
        }
    }
}

/* ---------- Main ---------- */

int main(void) {
    Graph *g = graph_create();

    /* Build a sample graph:
     *   A -- B -- D
     *   |    |
     *   C -- E
     */
    int a = graph_add_node(g, "A");
    int b = graph_add_node(g, "B");
    int c = graph_add_node(g, "C");
    int d = graph_add_node(g, "D");
    int e = graph_add_node(g, "E");

    graph_add_edge(g, a, b);
    graph_add_edge(g, a, c);
    graph_add_edge(g, b, d);
    graph_add_edge(g, b, e);
    graph_add_edge(g, c, e);

    bfs(g, a);

    /* Accept a custom start label from stdin safely */
    char input[MAX_LABEL];
    printf("\nEnter a node label to start BFS from: ");
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        int found = -1;
        for (int i = 0; i < g->count; i++) {
            if (strncmp(g->label[i], input, MAX_LABEL) == 0) {
                found = i;
                break;
            }
        }
        if (found == -1)
            printf("Node \"%s\" not found in graph.\n", input);
        else
            bfs(g, found);
    }

    graph_free(g);
    return 0;
}
