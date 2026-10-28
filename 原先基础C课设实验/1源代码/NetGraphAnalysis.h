#ifndef NET_GRAPH_ANALYSIS_H
#define NET_GRAPH_ANALYSIS_H

// 防止重复包含的宏定义
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

// ===================== 常量定义 =====================
#define MAX_IP_LEN 16
#define MAX_CSV_LINE 256
#define MAX_NODE_NUM 3000
#define MAX_EDGE_NUM 10000
#define MAX_PATH_LEN 1000000  
 

// 控件ID
#define ID_BTN_LOAD_FILE     1000  // 加载文件按钮
#define ID_BTN_NODE_FLOW     1001  // 节点流量排序
#define ID_BTN_HTTPS_FILTER  1002  // HTTPS筛选+排序
#define ID_BTN_UNI_FILTER    1003  // 单向流量筛选+排序
#define ID_BTN_PATH_FIND     1004  // 路径查找
#define ID_BTN_DETECT_STAR   1005  // 星型结构检测（仅一条边规则）
#define ID_BTN_CHECK_SECURITY 1006 // IP安全规则检测
#define ID_BTN_EXPORT_SUB    1007  // 导出子图按钮
#define ID_EDIT_FILE_PATH    2000  // 文件路径输入框
#define ID_EDIT_SRC_IP       2001  // 起点IP（路径查找用）
#define ID_EDIT_DST_IP       2002  // 终点IP（路径查找用）
#define ID_EDIT_ADDR1        2003  // 地址1
#define ID_EDIT_ADDR2        2004  // 地址2
#define ID_EDIT_ADDR3        2005  // 地址3
#define ID_EDIT_TARGET_IP    2006  // 目标IP输入框
#define ID_TXT_RESULT        3001  // 结果显示区

// ===================== 数据结构声明 =====================
// 边结构体：记录会话通信信息（有向边）
typedef struct Edge {
    int to;                 // 目的节点索引
    int proto;              // 协议：6=TCP,17=UDP,1=ICMP
    int src_port;           // 源端口
    int dst_port;           // 目的端口
    int data_size;          // 单条会话流量大小
    float duration;         // 单条会话时长
    int proto_flow[20];     // 按协议编号存储流量
    float proto_duration[20];// 按协议编号存储时长
    struct Edge *next;
} Edge;

// 节点结构体：表示IP节点
typedef struct Node {
    char ip[MAX_IP_LEN];    // 节点IP
    int total_flow;         // 总流量（入+出）
    int out_flow;           // 发出流量
    int in_flow;            // 接收流量
    Edge *first_edge;       // 出边链表头
} Node;

// 图结构体：有向图
typedef struct Graph {
    Node nodes[MAX_NODE_NUM];// 节点数组
    int node_count;         // 节点总数
    int edge_count;         // 边总数
} Graph;

// 路径结构体：用于路径查找
typedef struct Path {
    int node_indexs[MAX_NODE_NUM];// 路径节点索引
    int step;               // 路径跳数（step-1）
    int total_data_size;    // 路径总流量
    float total_duration;   // 路径总时长
    float congestion;       // 拥塞程度（总流量/总时长）
} Path;

// 并查集结构体（子图导出用）
typedef struct {
    int parent[MAX_NODE_NUM];
    int rank[MAX_NODE_NUM];  // 按秩合并，优化效率
} UnionFind;

// ===================== 全局变量声明（extern） =====================
extern Graph g_graph;             // 全局图结构
extern Path g_all_paths[MAX_NODE_NUM];// 所有路径
extern int g_path_count;          // 路径总数
extern bool g_visited[MAX_NODE_NUM];// DFS访问标记
extern HWND g_hWndResult;         // 结果显示框句柄
extern char g_csv_path[MAX_PATH]; // 数据文件路径（初始为空）

// ===================== 函数原型声明 =====================
// 工具函数
void InitGraph(Graph *G);
int FindNodeIndex(Graph *G, const char *ip);
int AddNode(Graph *G, const char *ip);
void AddEdge(Graph *G, const char *src_ip, const char *dst_ip, int proto, 
             int src_port, int dst_port, int data_size, float duration);
int safe_atoi(const char *str);
int CountOutEdges(Graph *G, int node_idx);
int CountInEdges(Graph *G, int node_idx);

// CSV加载
bool LoadCSV(const char *csv_path, Graph *G);

// 流量排序功能
void DoNodeFlowSort(Graph *G, HWND hResult);
void DoHTTPSFilterSort(Graph *G, HWND hResult);
void DoUniFilterSort(Graph *G, HWND hResult);

// 路径查找
void DFS(Graph *G, int cur, int dst, int cur_path[], int step, int total_data, float total_duration);
void DoPathFind(Graph *G, HWND hResult, const char *src_ip, const char *dst_ip);

// 星型结构检测
bool IsOnlyOneEdgeWithCenter(Graph *G, int node_idx, int center_idx);
void DetectStarStructure(Graph *G, HWND hResult);

// IP安全规则检测
bool IsIPInRange(const char *ip, const char *start_ip, const char *end_ip);
void CheckIPSecurityRule(Graph *G, HWND hResult, const char *addr1, const char *addr2, const char *addr3);

// 子图导出
void UF_Init(UnionFind *uf, int n);
int UF_Find(UnionFind *uf, int x);
void UF_Union(UnionFind *uf, int x, int y);
void ExportSubgraph(Graph *G, const char *target_ip, HWND hResult);

// GUI相关
void CreateControl(HWND hParent, const char *className, const char *text, 
                   int x, int y, int w, int h, int id, DWORD style);
void InitUI(HWND hWnd);
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#endif // NET_GRAPH_ANALYSIS_H
