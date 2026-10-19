#include "NetGraphAnalysis.h"

// ===================== 全局变量定义 =====================
Graph g_graph;             // 全局图结构
Path g_all_paths[MAX_NODE_NUM];// 所有路径
int g_path_count = 0;      // 路径总数
bool g_visited[MAX_NODE_NUM];// DFS访问标记
HWND g_hWndResult;         // 结果显示框句柄
char g_csv_path[MAX_PATH] = "";// 数据文件路径（初始为空）

// ===================== 工具函数实现 =====================
// 初始化图
void InitGraph(Graph *G) {
    G->node_count = 0;
    G->edge_count = 0;
    for (int i = 0; i < MAX_NODE_NUM; i++) {
        memset(&G->nodes[i], 0, sizeof(Node));
        G->nodes[i].first_edge = NULL;
    }
}

// 查找节点索引（不存在返回-1）
int FindNodeIndex(Graph *G, const char *ip) {
    for (int i = 0; i < G->node_count; i++) {
        if (strcmp(G->nodes[i].ip, ip) == 0) return i;
    }
    return -1;
}

// 添加节点（返回新节点索引）
int AddNode(Graph *G, const char *ip) {
    if (G->node_count >= MAX_NODE_NUM) return -1;
    strcpy(G->nodes[G->node_count].ip, ip);
    G->node_count++;
    return G->node_count - 1;
}

// 添加有向边（构建图核心）
void AddEdge(Graph *G, const char *src_ip, const char *dst_ip, int proto, 
             int src_port, int dst_port, int data_size, float duration) {
    // 查找/添加源节点和目的节点
    int src_idx = FindNodeIndex(G, src_ip);
    if (src_idx == -1) src_idx = AddNode(G, src_ip);
    int dst_idx = FindNodeIndex(G, dst_ip);
    if (dst_idx == -1) dst_idx = AddNode(G, dst_ip);

    // 创建新边
    Edge *new_edge = (Edge*)malloc(sizeof(Edge));
    memset(new_edge, 0, sizeof(Edge));
    new_edge->to = dst_idx;
    new_edge->proto = proto;
    new_edge->src_port = src_port;
    new_edge->dst_port = dst_port;
    new_edge->data_size = data_size;
    new_edge->duration = duration;
    new_edge->proto_flow[proto] += data_size;
    new_edge->proto_duration[proto] += duration;
    new_edge->next = G->nodes[src_idx].first_edge;
    G->nodes[src_idx].first_edge = new_edge;

    // 更新节点流量统计
    G->nodes[src_idx].out_flow += data_size;
    G->nodes[dst_idx].in_flow += data_size;
    G->nodes[src_idx].total_flow += data_size;
    G->nodes[dst_idx].total_flow += data_size;
    G->edge_count++;
}

// 安全转换整数（处理空端口）
int safe_atoi(const char *str) {
    if (str == NULL || strlen(str) == 0 || strcmp(str, " ") == 0) return 0;
    return atoi(str);
}

// 统计节点的出边总数
int CountOutEdges(Graph *G, int node_idx) {
    int count = 0;
    Edge *e = G->nodes[node_idx].first_edge;
    while (e != NULL) {
        count++;
        e = e->next;
    }
    return count;
}

// 统计节点的入边总数（来自所有其他节点）
int CountInEdges(Graph *G, int node_idx) {
    int count = 0;
    for (int i = 0; i < G->node_count; i++) {
        if (i == node_idx) continue;
        Edge *e = G->nodes[i].first_edge;
        while (e != NULL) {
            if (e->to == node_idx) {
                count++;
                break; // 每个节点对当前节点最多算一条入边（避免重复统计）
            }
            e = e->next;
        }
    }
    return count;
}

// ===================== 功能1：数据读取（CSV） =====================
bool LoadCSV(const char *csv_path, Graph *G) {
    // 先清空图数据
    InitGraph(G);
    
    FILE *fp = fopen(csv_path, "r");
    if (!fp) {
        char err_msg[256];
        sprintf(err_msg, "文件不存在：%s", csv_path);
        MessageBox(NULL, err_msg, "CSV加载失败", MB_ICONERROR);
        return false;
    }

    char line[MAX_CSV_LINE];
    // 跳过表头
    while (fgets(line, MAX_CSV_LINE, fp)) {
        if (strlen(line) > 5) break;
    }

    int line_num = 2;
    while (fgets(line, MAX_CSV_LINE, fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) { line_num++; continue; }

        // 分割字段（兼容空端口）
        char src_ip[MAX_IP_LEN] = "", dst_ip[MAX_IP_LEN] = "";
        char proto_str[16] = "", src_port_str[16] = "", dst_port_str[16] = "";
        char data_size_str[16] = "", duration_str[16] = "";
        
        char *token = strtok(line, ",");
        if (token) strncpy(src_ip, token, MAX_IP_LEN - 1);
        token = strtok(NULL, ",");
        if (token) strncpy(dst_ip, token, MAX_IP_LEN - 1);
        token = strtok(NULL, ",");
        if (token) strncpy(proto_str, token, 15);
        token = strtok(NULL, ",");
        if (token) strncpy(src_port_str, token, 15);
        token = strtok(NULL, ",");
        if (token) strncpy(dst_port_str, token, 15);
        token = strtok(NULL, ",");
        if (token) strncpy(data_size_str, token, 15);
        token = strtok(NULL, ",");
        if (token) strncpy(duration_str, token, 15);

        // 类型转换
        int proto = safe_atoi(proto_str);
        int src_port = safe_atoi(src_port_str);
        int dst_port = safe_atoi(dst_port_str);
        int data_size = safe_atoi(data_size_str);
        float duration = (float)atof(duration_str);

        // 核心字段校验
        if (strlen(src_ip) > 0 && strlen(dst_ip) > 0) {
            AddEdge(G, src_ip, dst_ip, proto, src_port, dst_port, data_size, duration);
        }
        line_num++;
    }
    fclose(fp);
    
    if (G->node_count == 0) {
        MessageBox(NULL, "CSV文件无有效数据！", "警告", MB_ICONWARNING);
        return false;
    }
    
    return true;
}

// ===================== 功能2：流量排序 =====================
// 排序结构体（用于节点流量排序）
typedef struct SortNode {
    int idx;
    int total_flow;
} SortNode;

// 冒泡排序（降序）
void BubbleSort(SortNode *arr, int n) {
    for (int i = 0; i < n-1; i++) {
        for (int j = 0; j < n-i-1; j++) {
            if (arr[j].total_flow < arr[j+1].total_flow) {
                SortNode temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
        }
    }
}

// 2.1 节点流量排序（总流量=入+出）
void DoNodeFlowSort(Graph *G, HWND hResult) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }
    
    char result[MAX_PATH_LEN] = {0};
    char *p = result;
    int remaining = MAX_PATH_LEN - 1;
    
    p += snprintf(p, remaining, "===== 节点流量排序（总流量=入+出）=====\r\n");
    
    SortNode nodes[MAX_NODE_NUM];
    int count = 0;
    for (int i = 0; i < G->node_count; i++) {
        nodes[count].idx = i;
        nodes[count].total_flow = G->nodes[i].total_flow;
        count++;
    }
    BubbleSort(nodes, count);
    
    for (int i = 0; i < count && p < result + remaining - 256; i++) {
        Node *node = &G->nodes[nodes[i].idx];
        p += snprintf(p, remaining - (p - result), 
            "第%d名：IP=%s | 总流量=%d | 发出流量=%d | 接收流量=%d\r\n",
            i+1, node->ip, node->total_flow, node->out_flow, node->in_flow);
    }
    p += snprintf(p, remaining - (p - result), 
        "\r\n总计：%d个节点，%d条通信边\r\n", G->node_count, G->edge_count);
    SetWindowText(hResult, result);
}

// 2.2 HTTPS筛选+排序（修复版：覆盖源/目的443端口）
void DoHTTPSFilterSort(Graph *G, HWND hResult) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }
    
    char result[MAX_PATH_LEN] = {0};
    char *p = result;
    int remaining = MAX_PATH_LEN - 1;
    
    p += snprintf(p, remaining, "===== HTTPS筛选+排序（TCP+443端口）=====\r\n");
    p += snprintf(p, remaining - (p - result), "规则：节点参与过TCP+443端口通信（无论作为源/目的）\r\n\r\n");
    
    typedef struct {
        int idx;
        int https_flow;  // 该节点所有TCP+443流量总和
    } HTTPSNode;
    HTTPSNode https_nodes[MAX_NODE_NUM];
    int count = 0;
    
    // 初始化每个节点的HTTPS流量为0
    int node_https_flow[MAX_NODE_NUM] = {0};
    
    // 遍历所有边，统计每个节点的TCP+443流量（覆盖两种场景）
    for (int src_idx = 0; src_idx < G->node_count; src_idx++) {
        Edge *p_edge = G->nodes[src_idx].first_edge;
        while (p_edge) {
            
            if (p_edge->proto == 6 && p_edge->dst_port == 443) {
                node_https_flow[src_idx] += p_edge->data_size;  // 源节点流量累加
                node_https_flow[p_edge->to] += p_edge->data_size; // 目的节点流量累加
            }
            
            p_edge = p_edge->next;
        }
    }
    
    // 收集所有有HTTPS流量的节点
    for (int i = 0; i < G->node_count; i++) {
        if (node_https_flow[i] > 0) {
            https_nodes[count].idx = i;
            https_nodes[count].https_flow = node_https_flow[i];
            count++;
        }
    }
    
    if (count == 0) {
        p += snprintf(p, remaining, "未找到HTTPS（TCP+443）流量节点！");
        SetWindowText(hResult, result);
        return;
    }
    
    // 按HTTPS流量降序排序
    for (int i = 0; i < count-1; i++) {
        for (int j = 0; j < count-i-1; j++) {
            if (https_nodes[j].https_flow < https_nodes[j+1].https_flow) {
                HTTPSNode temp = https_nodes[j];
                https_nodes[j] = https_nodes[j+1];
                https_nodes[j+1] = temp;
            }
        }
    }
    
    // 输出结果
    for (int i = 0; i < count && p < result + remaining - 256; i++) {
        Node *node = &G->nodes[https_nodes[i].idx];
        p += snprintf(p, remaining - (p - result), 
            "第%d名：IP=%s | HTTPS总流量=%d | 节点总流量=%d\r\n",
            i+1, node->ip, https_nodes[i].https_flow, node->total_flow);
    }
    p += snprintf(p, remaining - (p - result), 
        "\r\n总计：%d个HTTPS流量节点\r\n", count);
    SetWindowText(hResult, result);
}

// 2.3 单向流量筛选+排序（发出流量占比>80%）
void DoUniFilterSort(Graph *G, HWND hResult) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }
    
    char result[MAX_PATH_LEN] = {0};
    char *p = result;
    int remaining = MAX_PATH_LEN - 1;
    
    p += snprintf(p, remaining, "===== 单向流量筛选+排序（发出占比>80%）=====\r\n");
    
    typedef struct {
        int idx;
        int total_flow;
        float out_ratio;
    } UniNode;
    UniNode uni_nodes[MAX_NODE_NUM];
    int count = 0;
    
    for (int i = 0; i < G->node_count; i++) {
        Node *node = &G->nodes[i];
        if (node->total_flow == 0) continue;
        
        float out_ratio = (float)node->out_flow / node->total_flow;
        if (out_ratio > 0.8) {
            uni_nodes[count].idx = i;
            uni_nodes[count].total_flow = node->total_flow;
            uni_nodes[count].out_ratio = out_ratio;
            count++;
        }
    }
    
    if (count == 0) {
        p += snprintf(p, remaining, "未找到单向流量占比>80%的节点！");
        SetWindowText(hResult, result);
        return;
    }
    
    for (int i = 0; i < count-1; i++) {
        for (int j = 0; j < count-i-1; j++) {
            if (uni_nodes[j].total_flow < uni_nodes[j+1].total_flow) {
                UniNode temp = uni_nodes[j];
                uni_nodes[j] = uni_nodes[j+1];
                uni_nodes[j+1] = temp;
            }
        }
    }
    
    for (int i = 0; i < count && p < result + remaining - 256; i++) {
        Node *node = &G->nodes[uni_nodes[i].idx];
        p += snprintf(p, remaining - (p - result), 
            "第%d名：IP=%s | {总流量=%d，发出占比=%.2f%%}\r\n",
            i+1, node->ip, uni_nodes[i].total_flow, uni_nodes[i].out_ratio * 100);
    }
    p += snprintf(p, remaining - (p - result), 
        "\r\n总计：%d个单向流量异常节点\r\n", count);
    SetWindowText(hResult, result);
}

// ===================== 功能3：路径查找 =====================
// DFS查找所有路径
void DFS(Graph *G, int cur, int dst, int cur_path[], int step, int total_data, float total_duration) {
    g_visited[cur] = true;
    cur_path[step] = cur;
    step++;
    
    if (cur == dst) {
        if (g_path_count < MAX_NODE_NUM) {
            g_all_paths[g_path_count].step = step;
            g_all_paths[g_path_count].total_data_size = total_data;
            g_all_paths[g_path_count].total_duration = total_duration;
            if (total_duration < 1e-7) {
                g_all_paths[g_path_count].congestion = 0;
            } else {
                g_all_paths[g_path_count].congestion = (float)total_data / total_duration;
            }
            memcpy(g_all_paths[g_path_count].node_indexs, cur_path, step * sizeof(int));
            g_path_count++;
        }
        g_visited[cur] = false;
        return;
    }
    
    Edge *p = G->nodes[cur].first_edge;
    while (p) {
        if (!g_visited[p->to] && g_path_count < MAX_NODE_NUM) {
            DFS(G, p->to, dst, cur_path, step, total_data + p->data_size, total_duration + p->duration);
        }
        p = p->next;
    }
    g_visited[cur] = false;
}

// 查找拥塞最小和跳数最小路径
void DoPathFind(Graph *G, HWND hResult, const char *src_ip, const char *dst_ip) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }
    
    char result[MAX_PATH_LEN] = {0};
    char *p = result;
    int remaining = MAX_PATH_LEN - 1;
    
    g_path_count = 0;
    memset(g_visited, false, sizeof(g_visited));
    memset(g_all_paths, 0, sizeof(g_all_paths));
    
    int src_idx = FindNodeIndex(G, src_ip);
    int dst_idx = FindNodeIndex(G, dst_ip);
    if (src_idx == -1 || dst_idx == -1) {
        p += snprintf(p, remaining, "错误：源IP(%s)或目的IP(%s)不存在！", src_ip, dst_ip);
        SetWindowText(hResult, result);
        return;
    }
    
    int cur_path[MAX_NODE_NUM] = {0};
    DFS(G, src_idx, dst_idx, cur_path, 0, 0, 0.0f);
    
    if (g_path_count == 0) {
        p += snprintf(p, remaining, "无可行路径：%s → %s", src_ip, dst_ip);
        SetWindowText(hResult, result);
        return;
    }
    
    int min_congest = 0, min_hop = 0;
    for (int i = 1; i < g_path_count; i++) {
        if (g_all_paths[i].congestion < g_all_paths[min_congest].congestion) {
            min_congest = i;
        }
        if (g_all_paths[i].step < g_all_paths[min_hop].step) {
            min_hop = i;
        }
    }
    
    p += snprintf(p, remaining - (p - result), "===== 路径查找结果 =====\r\n");
    p += snprintf(p, remaining - (p - result), "源IP：%s → 目的IP：%s\r\n\r\n", src_ip, dst_ip);
    
    p += snprintf(p, remaining - (p - result), "拥塞最小路径\r\n");
    p += snprintf(p, remaining - (p - result), 
        "跳数：%d | 总流量：%d | 总时长：%.2f | 拥塞程度：%.2f\r\n路径：",
        g_all_paths[min_congest].step - 1,
        g_all_paths[min_congest].total_data_size,
        g_all_paths[min_congest].total_duration,
        g_all_paths[min_congest].congestion);
    for (int i = 0; i < g_all_paths[min_congest].step && p < result + remaining - 64; i++) {
        p += snprintf(p, remaining - (p - result), "%s", G->nodes[g_all_paths[min_congest].node_indexs[i]].ip);
        if (i < g_all_paths[min_congest].step - 1) {
            p += snprintf(p, remaining - (p - result), " → ");
        }
    }
    
    p += snprintf(p, remaining - (p - result), "\r\n\r\n跳数最小路径\r\n");
    p += snprintf(p, remaining - (p - result), 
        "跳数：%d | 总流量：%d | 总时长：%.2f | 拥塞程度：%.2f\r\n路径：",
        g_all_paths[min_hop].step - 1,
        g_all_paths[min_hop].total_data_size,
        g_all_paths[min_hop].total_duration,
        g_all_paths[min_hop].congestion);
    for (int i = 0; i < g_all_paths[min_hop].step && p < result + remaining - 64; i++) {
        p += snprintf(p, remaining - (p - result), "%s", G->nodes[g_all_paths[min_hop].node_indexs[i]].ip);
        if (i < g_all_paths[min_hop].step - 1) {
            p += snprintf(p, remaining - (p - result), " → ");
        }
    }
    
    SetWindowText(hResult, result);
}

// ===================== 功能4：星型结构检测 =====================
// 校验：节点仅与中心有一条边（无论方向），且无其他通信
bool IsOnlyOneEdgeWithCenter(Graph *G, int node_idx, int center_idx) {
    // 1. 卫星节点的所有出边只能指向中心
    Edge *sat_out = G->nodes[node_idx].first_edge;
    while (sat_out != NULL) {
        if (sat_out->to != center_idx) return false;
        sat_out = sat_out->next;
    }

    // 2. 卫星节点的所有入边只能来自中心
    for (int i = 0; i < G->node_count; i++) {
        if (i == node_idx || i == center_idx) continue;
        Edge *other_out = G->nodes[i].first_edge;
        while (other_out != NULL) {
            if (other_out->to == node_idx) return false;
            other_out = other_out->next;
        }
    }

    // 3. 卫星节点与中心节点之间仅存在一条边（无论方向）
    int out_edge_count = CountOutEdges(G, node_idx); // 卫星→中心的边数
    int in_edge_count = CountInEdges(G, node_idx);   // 中心→卫星的边数（仅算1条，避免重复）
    
    // 总边数必须为1（要么卫星→中心，要么中心→卫星，仅一条）
    return (out_edge_count + in_edge_count) == 1;
}

void DetectStarStructure(Graph *G, HWND hResult) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }

    char result[MAX_PATH_LEN] = {0};
    int res_len = 0;

    // 1. 定位中心节点
    const char *center_ip = "218.106.117.236";
    int center_idx = FindNodeIndex(G, center_ip);
    if (center_idx == -1) {
        snprintf(result, MAX_PATH_LEN, "未找到中心节点：%s", center_ip);
        SetWindowText(hResult, result);
        return;
    }

    // 2. 筛选：仅与中心有一条边+无其他通信
    int valid_satellites[MAX_NODE_NUM];
    int valid_count = 0;

    for (int i = 0; i < G->node_count; i++) {
        if (i == center_idx) continue;
        if (IsOnlyOneEdgeWithCenter(G, i, center_idx)) {
            valid_satellites[valid_count++] = i;
        }
    }

    // 3. 输出结果
    res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "===== 星型结构检测结果（仅一条边规则）=====\r\n");
    res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "中心节点IP：%s\r\n", center_ip);
    res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "仅与中心有一条边的卫星节点数：%d\r\n", valid_count);
    res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "=========================================\r\n");
    res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "卫星节点列表：\r\n");

    // 按IP排序
    for (int i = 0; i < valid_count; i++) {
        for (int j = i + 1; j < valid_count; j++) {
            if (strcmp(G->nodes[valid_satellites[i]].ip, G->nodes[valid_satellites[j]].ip) > 0) {
                int temp = valid_satellites[i];
                valid_satellites[i] = valid_satellites[j];
                valid_satellites[j] = temp;
            }
        }
    }

    // 打印节点
    for (int i = 0; i < valid_count && res_len < MAX_PATH_LEN - 64; i++) {
        res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "%d. %s\r\n", i + 1, G->nodes[valid_satellites[i]].ip);
    }

    // 结论
    if (valid_count >= 20) {
        res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "\r\n结论：该网络结构为星型结构（中心连接%d个卫星节点，各仅一条边）", valid_count);
    } else {
        res_len += snprintf(result + res_len, MAX_PATH_LEN - res_len, "\r\n结论：非星型结构（卫星节点数<20）");
    }

    SetWindowText(hResult, result);
}

// ===================== 功能5：IP安全规则检测 =====================
// 判断IP是否在[start_ip, end_ip]范围内
bool IsIPInRange(const char *ip, const char *start_ip, const char *end_ip) {
    return (strcmp(ip, start_ip) >= 0 && strcmp(ip, end_ip) <= 0);
}

// 自定义安全规则检测
void CheckIPSecurityRule(Graph *G, HWND hResult, const char *addr1, const char *addr2, const char *addr3) {
    if (G->node_count == 0) {
        SetWindowText(hResult, "请先加载CSV数据文件！");
        return;
    }
    
    char result[MAX_PATH_LEN] = {0};
    char *p = result;
    int remaining = MAX_PATH_LEN - 1;
    int violation_count = 0;

    p += snprintf(p, remaining, "===== IP安全规则检测结果 =====\r\n");
    p += snprintf(p, remaining - (p - result), 
        "规则：禁止 %s 与 [%s, %s] 范围内的地址通信\r\n\r\n",
        addr1, addr2, addr3);

    int idx1 = FindNodeIndex(G, addr1);
    if (idx1 == -1) {
        p += snprintf(p, remaining - (p - result), "错误：地址 %s 不存在于图中。\r\n", addr1);
        SetWindowText(hResult, result);
        return;
    }

    for (int i = 0; i < G->node_count; i++) {
        Node *src_node = &G->nodes[i];
        Edge *e = src_node->first_edge;
        while (e) {
            Node *dst_node = &G->nodes[e->to];

            bool is_violation = false;
            if (strcmp(src_node->ip, addr1) == 0 && IsIPInRange(dst_node->ip, addr2, addr3)) {
                is_violation = true;
            } else if (strcmp(dst_node->ip, addr1) == 0 && IsIPInRange(src_node->ip, addr2, addr3)) {
                is_violation = true;
            }

            if (is_violation && p < result + remaining - 256) {
                violation_count++;
                p += snprintf(p, remaining - (p - result), 
                    "违规会话：%s → %s | 协议：%d | 流量：%d | 时长：%.2f\r\n",
                    src_node->ip, dst_node->ip, e->proto, e->data_size, e->duration);
            }

            e = e->next;
        }
    }

    if (violation_count == 0) {
        p += snprintf(p, remaining - (p - result), "\r\n未发现违反安全规则的会话。\r\n");
    } else {
        p += snprintf(p, remaining - (p - result), "\r\n总计发现 %d 条违规会话。\r\n", violation_count);
    }

    SetWindowText(hResult, result);
}

// ===================== 功能6：子图可视化导出（无限制+极速加载版） =====================
// 初始化并查集
void UF_Init(UnionFind *uf, int n) {
    for (int i = 0; i < n; i++) {
        uf->parent[i] = i;
        uf->rank[i] = 0;
    }
}

// 查找根节点（路径压缩）
int UF_Find(UnionFind *uf, int x) {
    if (uf->parent[x] != x) {
        uf->parent[x] = UF_Find(uf, uf->parent[x]);
    }
    return uf->parent[x];
}

// 合并两个集合（按秩合并）
void UF_Union(UnionFind *uf, int x, int y) {
    int fx = UF_Find(uf, x);
    int fy = UF_Find(uf, y);
    if (fx == fy) return;
    
    if (uf->rank[fx] < uf->rank[fy]) {
        uf->parent[fx] = fy;
    } else {
        uf->parent[fy] = fx;
        if (uf->rank[fx] == uf->rank[fy]) {
            uf->rank[fx]++;
        }
    }
}

// 导出目标IP所在子图为HTML（无数量限制+极速加载）
void ExportSubgraph(Graph *G, const char *target_ip, HWND hResult) {
    // 基础校验
    if (G == NULL || G->node_count == 0) {
        SetWindowText(hResult, "错误：请先加载有效的CSV数据！");
        return;
    }

    // 1. 查找目标IP索引
    int target_idx = FindNodeIndex(G, target_ip);
    if (target_idx == -1) {
        char err_msg[256];
        sprintf(err_msg, "错误：目标IP %s 不存在于网络中！", target_ip);
        SetWindowText(hResult, err_msg);
        return;
    }

    // 2. 初始化并查集，构建连通分量
    UnionFind uf;
    UF_Init(&uf, G->node_count);
    
    for (int u = 0; u < G->node_count; u++) {
        Edge *edge = G->nodes[u].first_edge;
        while (edge != NULL) {
            int v = edge->to;
            UF_Union(&uf, u, v);
            edge = edge->next;
        }
    }

    // 3. 收集目标IP所在连通子图的所有节点（无数量限制）
    int target_root = UF_Find(&uf, target_idx);
    int sub_node_count = 0;
    int sub_nodes[MAX_NODE_NUM] = {0};
    
    for (int i = 0; i < G->node_count; i++) {
        if (UF_Find(&uf, i) == target_root) {
            sub_nodes[sub_node_count++] = i;
        }
    }

    if (sub_node_count == 0) {
        SetWindowText(hResult, "错误：未找到目标IP所在的连通子图！");
        return;
    }

    // 4. 收集子图的所有边（无数量限制）
    typedef struct {
        int from;
        int to;
        int data_size;
    } SubEdge;
    
    SubEdge sub_edges[MAX_EDGE_NUM] = {0};
    int sub_edge_count = 0;
    
    for (int u = 0; u < G->node_count; u++) {
        if (UF_Find(&uf, u) != target_root) continue;
        
        Edge *edge = G->nodes[u].first_edge;
        while (edge != NULL) {
            int v = edge->to;
            if (UF_Find(&uf, v) == target_root) {
                sub_edges[sub_edge_count].from = u;
                sub_edges[sub_edge_count].to = v;
                sub_edges[sub_edge_count].data_size = edge->data_size;
                sub_edge_count++;
            }
            edge = edge->next;
        }
    }

    // 5. 生成可视化HTML文件
    FILE *fp = fopen("subgraph_view.html", "w");
    if (fp == NULL) {
        SetWindowText(hResult, "错误：无法创建HTML文件！请检查文件权限。");
        return;
    }

    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html lang=\"zh-CN\">\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "    <meta charset=\"UTF-8\">\n");
    fprintf(fp, "    <title>网络子图可视化</title>\n");
    // 引入vis-network可视化库（国内CDN）
    fprintf(fp, "    <script src=\"https://cdn.bootcdn.net/ajax/libs/vis-network/9.1.2/standalone/umd/vis-network.min.js\"></script>\n");
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        #network { width: 100%%; height: 700px; border: 1px solid #ccc; border-radius: 8px; }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");

    // 5.2 仅保留可视化容器
    fprintf(fp, "    <div id=\"network\"></div>\n");

    // 5.3 写入JavaScript可视化逻辑
    fprintf(fp, "    <script type=\"text/javascript\">\n");
    
    // 生成节点数据
    fprintf(fp, "        var nodes = [\n");
    for (int i = 0; i < sub_node_count; i++) {
        int node_idx = sub_nodes[i];
        const char *ip = G->nodes[node_idx].ip;
        int is_target = (node_idx == target_idx) ? 1 : 0;

        // 目标节点标红，其他节点蓝色
        if (is_target) {
            fprintf(fp, "            { id: %d, label: \"%s\", color: { background: \"#ff4444\", border: \"#cc0000\" }, size: 30, font: { color: \"white\", size: 14 } }\n", 
                    node_idx, ip);
        } else {
            fprintf(fp, "            { id: %d, label: \"%s\", color: { background: \"#4285f4\", border: \"#3367d6\" }, size: 20, font: { color: \"white\", size: 12 } }\n", 
                    node_idx, ip);
        }
        
        if (i < sub_node_count - 1) {
            fprintf(fp, "            ,");
        }
    }
    fprintf(fp, "        ];\n");

    // 生成边数据
    fprintf(fp, "        var edges = [\n");
    for (int i = 0; i < sub_edge_count; i++) {
        int from = sub_edges[i].from;
        int to = sub_edges[i].to;
        int data_size = sub_edges[i].data_size;
        
        // 根据流量调整边宽度
        float width = data_size > 1000000 ? 3.0f : 1.0f;

        fprintf(fp, "            { from: %d, to: %d, arrows: \"to\", width: %.1f, \n", from, to, width);
        fprintf(fp, "              color: \"#666666\", title: \"流量：%d 字节\" }\n", data_size);
        
        if (i < sub_edge_count - 1) {
            fprintf(fp, "            ,");
        }
    }
    fprintf(fp, "        ];\n");

    // 初始化可视化网络
    fprintf(fp, "        var container = document.getElementById('network');\n");
    fprintf(fp, "        var data = { nodes: nodes, edges: edges };\n");
    fprintf(fp, "        var options = {\n");
    fprintf(fp, "            physics: {\n");
    fprintf(fp, "                enabled: true,\n");
    fprintf(fp, "                stabilization: { \n");
    fprintf(fp, "                    enabled: true,\n");
    fprintf(fp, "                    iterations: 200,  // 大幅减少迭代次数（原1500→200）\n");
    fprintf(fp, "                    onlyDynamicEdges: true,\n");
    fprintf(fp, "                    fit: true\n");
    fprintf(fp, "                },\n");
    fprintf(fp, "                barnesHut: {\n");
    fprintf(fp, "                    gravitationalConstant: -800,  \n");
    fprintf(fp, "                    springLength: 80,             \n");
    fprintf(fp, "                    springConstant: 0.1,          \n");
    fprintf(fp, "                    damping: 0.95,                \n");
    fprintf(fp, "                    avoidOverlap: 0.1\n");
    fprintf(fp, "                }\n");
    fprintf(fp, "            },\n");
    fprintf(fp, "            interaction: {\n");
    fprintf(fp, "                hover: true,\n");
    fprintf(fp, "                zoomView: true,\n");
    fprintf(fp, "                dragNodes: true,\n");
    fprintf(fp, "                hideEdgesOnDrag: true  \n");
    fprintf(fp, "            },\n");
    fprintf(fp, "            layout: {\n");
    fprintf(fp, "                improvedLayout: true,  \n");
    fprintf(fp, "                randomSeed: 42         \n");
    fprintf(fp, "            }\n");
    fprintf(fp, "        };\n");
    
    // 预加载完成后立即停止物理动画（核心提速）
    fprintf(fp, "        var network = new vis.Network(container, data, options);\n");
    fprintf(fp, "        network.on('stabilizationIterationsDone', function() {\n");
    fprintf(fp, "            network.setOptions({ physics: false }); // 稳定后关闭物理引擎\n");
    fprintf(fp, "        });\n");
    
    // 双击节点居中
    fprintf(fp, "        network.on('doubleClick', function(params) {\n");
    fprintf(fp, "            if (params.nodes.length > 0) {\n");
    fprintf(fp, "                network.focus(params.nodes[0], { scale: 1.5, animation: { duration: 300 } });\n");
    fprintf(fp, "            }\n");
    fprintf(fp, "        });\n");
    fprintf(fp, "    </script>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    // 关闭文件
    fclose(fp);

    // 6. 输出成功提示
    char success_msg[MAX_PATH_LEN];
    sprintf(success_msg, 
            "? 子图可视化导出成功！\r\n"
            "目标IP：%s\r\n"
            "子图节点数：%d\r\n"
            "子图边数：%d\r\n"
            "生成文件：%s\\subgraph_view.html\r\n\r\n",
            target_ip, sub_node_count, sub_edge_count, g_csv_path);
    
    SetWindowText(hResult, success_msg);
}

// ===================== GUI界面 =====================
void CreateControl(HWND hParent, const char *className, const char *text, 
                   int x, int y, int w, int h, int id, DWORD style) {
    HWND hCtrl = CreateWindow(
        className, text, WS_CHILD | WS_VISIBLE | style,
        x, y, w, h, hParent, (HMENU)(UINT_PTR)id, GetModuleHandle(NULL), NULL
    );
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(TRUE, 0));
}

void InitUI(HWND hWnd) {
    // 文件路径输入区域
    int btnW = 80, btnH = 30, editW = 400, editH = 25;
    CreateControl(hWnd, "STATIC", "CSV文件路径：", 15, 15, 80, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 100, 15, editW, editH, ID_EDIT_FILE_PATH, ES_AUTOHSCROLL | WS_BORDER);
    CreateControl(hWnd, "BUTTON", "加载文件", 510, 15, btnW, btnH, ID_BTN_LOAD_FILE, BS_PUSHBUTTON);

    // 功能按钮
    int funcBtnX = 15, funcBtnY = 55;
    CreateControl(hWnd, "BUTTON", "节点流量排序", funcBtnX, funcBtnY, 95, btnH, ID_BTN_NODE_FLOW, BS_PUSHBUTTON);
    CreateControl(hWnd, "BUTTON", "HTTPS筛选排序", funcBtnX += 100, funcBtnY, 95, btnH, ID_BTN_HTTPS_FILTER, BS_PUSHBUTTON);
    CreateControl(hWnd, "BUTTON", "单向流量筛选", funcBtnX += 100, funcBtnY, 95, btnH, ID_BTN_UNI_FILTER, BS_PUSHBUTTON);
    CreateControl(hWnd, "BUTTON", "路径查找", funcBtnX += 100, funcBtnY, 95, btnH, ID_BTN_PATH_FIND, BS_PUSHBUTTON);
    CreateControl(hWnd, "BUTTON", "星型结构检测", funcBtnX += 100, funcBtnY, 95, btnH, ID_BTN_DETECT_STAR, BS_PUSHBUTTON);
    CreateControl(hWnd, "BUTTON", "IP安全规则检测", funcBtnX += 100, funcBtnY, 95, btnH, ID_BTN_CHECK_SECURITY, BS_PUSHBUTTON);

    // 路径查找输入
    int labW = 60;
    CreateControl(hWnd, "STATIC", "起点IP：", 15, 95, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 80, 95, 120, editH, ID_EDIT_SRC_IP, ES_AUTOHSCROLL | WS_BORDER);
    CreateControl(hWnd, "STATIC", "终点IP：", 210, 95, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 275, 95, 120, editH, ID_EDIT_DST_IP, ES_AUTOHSCROLL | WS_BORDER);

    // IP安全规则输入
    CreateControl(hWnd, "STATIC", "地址1：", 15, 130, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 80, 130, 120, editH, ID_EDIT_ADDR1, ES_AUTOHSCROLL | WS_BORDER);
    CreateControl(hWnd, "STATIC", "地址2：", 210, 130, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 275, 130, 120, editH, ID_EDIT_ADDR2, ES_AUTOHSCROLL | WS_BORDER);
    CreateControl(hWnd, "STATIC", "地址3：", 390, 130, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 455, 130, 120, editH, ID_EDIT_ADDR3, ES_AUTOHSCROLL | WS_BORDER);
    
    // 子图导出输入
    CreateControl(hWnd, "STATIC", "目标IP：", 15, 165, labW, editH, 0, SS_LEFT);
    CreateControl(hWnd, "EDIT", "", 80, 165, 120, editH, ID_EDIT_TARGET_IP, ES_AUTOHSCROLL | WS_BORDER);
    CreateControl(hWnd, "BUTTON", "导出子图", 210, 165, 80, btnH, ID_BTN_EXPORT_SUB, BS_PUSHBUTTON);

    // 结果显示区
    CreateControl(hWnd, "EDIT", "请在上方输入CSV文件完整路径，点击「加载文件」后使用功能按钮分析...", 
                  15, 190, 750, 280, ID_TXT_RESULT, 
                  ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER);
    g_hWndResult = GetDlgItem(hWnd, ID_TXT_RESULT);
}

// ===================== 消息处理 =====================
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            InitGraph(&g_graph);
            InitUI(hWnd);
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                // 加载文件
                case ID_BTN_LOAD_FILE: {
                    char file_path[MAX_PATH] = {0};
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_FILE_PATH), file_path, MAX_PATH);
                    
                    if (strlen(file_path) == 0) {
                        MessageBox(NULL, "请输入有效的CSV文件路径！", "提示", MB_ICONINFORMATION);
                        break;
                    }
                    
                    strcpy(g_csv_path, file_path);
                    if (LoadCSV(g_csv_path, &g_graph)) {
                        char buf[256];
                        sprintf(buf, "√ 数据加载成功！\r\n节点数：%d | 通信边数：%d\r\n\r\n点击上方按钮执行分析", 
                                g_graph.node_count, g_graph.edge_count);
                        SetWindowText(g_hWndResult, buf);
                    } else {
                        SetWindowText(g_hWndResult, "× CSV加载失败！\r\n请检查：\r\n1. 文件路径是否正确\r\n2. 文件格式是否为：源IP,目的IP,协议,源端口,目的端口,流量,时长");
                    }
                    break;
                }
                // 节点流量排序
                case ID_BTN_NODE_FLOW:
                    DoNodeFlowSort(&g_graph, g_hWndResult);
                    break;
                // HTTPS筛选排序
                case ID_BTN_HTTPS_FILTER:
                    DoHTTPSFilterSort(&g_graph, g_hWndResult);
                    break;
                // 单向流量筛选
                case ID_BTN_UNI_FILTER:
                    DoUniFilterSort(&g_graph, g_hWndResult);
                    break;
                // 路径查找
                case ID_BTN_PATH_FIND: {
                    char src_ip[MAX_IP_LEN], dst_ip[MAX_IP_LEN];
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_SRC_IP), src_ip, MAX_IP_LEN);
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_DST_IP), dst_ip, MAX_IP_LEN);
                    DoPathFind(&g_graph, g_hWndResult, src_ip, dst_ip);
                    break;
                }
                // 星型结构检测
                case ID_BTN_DETECT_STAR:
                    DetectStarStructure(&g_graph, g_hWndResult);
                    break;
                // IP安全规则检测
                case ID_BTN_CHECK_SECURITY: {
                    char addr1[MAX_IP_LEN], addr2[MAX_IP_LEN], addr3[MAX_IP_LEN];
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_ADDR1), addr1, MAX_IP_LEN);
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_ADDR2), addr2, MAX_IP_LEN);
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_ADDR3), addr3, MAX_IP_LEN);
                    CheckIPSecurityRule(&g_graph, g_hWndResult, addr1, addr2, addr3);
                    break;
                }
                // 导出子图
                case ID_BTN_EXPORT_SUB: {
                    char target_ip[MAX_IP_LEN];
                    GetWindowText(GetDlgItem(hWnd, ID_EDIT_TARGET_IP), target_ip, MAX_IP_LEN);
                    ExportSubgraph(&g_graph, target_ip, g_hWndResult);
                    break;
                }
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ===================== 主函数 =====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "NetGraphAnalysis";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, "窗口注册失败！", "错误", MB_ICONERROR);
        return 1;
    }

    HWND hWnd = CreateWindow(
        "NetGraphAnalysis", "网络流量图分析工具", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 550, 
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) {
        MessageBox(NULL, "窗口创建失败！", "错误", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
